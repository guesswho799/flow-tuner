#include "elf_reader.hpp"
#include "disassembler.hpp"
#include "elf_header.hpp"
#include <algorithm>
#include <cctype>
#include <cstdint>
#include <elf.h>
#include <format>
#include <fstream>
#include <iostream>
#include <ranges>
#include <stdexcept>
#include <string>
#include <utility>

// constructors
ElfReader::ElfReader(std::string file_name)
    : _file(std::ifstream(file_name)), _file_name(file_name),
      _header(header_factory()), _sections(sections_factory()),
      _static_symbols(static_symbols_factory()), _strings(strings_factory()) {}

ElfReader::ElfReader(ElfReader &&other)
    : _file(std::ifstream(other._file_name)), _file_name(other._file_name),
      _header(other.get_header()), _sections(other.get_sections()),
      _static_symbols(other.get_static_symbols()),
      _strings(other.get_strings()) {}

ElfReader &ElfReader::operator=(ElfReader &&other) {
  _file = std::ifstream(other._file_name);
  _file_name = other._file_name;
  _header = other.get_header();
  _sections = other.get_sections();
  _static_symbols = other.get_static_symbols();
  _strings = other.get_strings();
  return *this;
}

ElfReader::~ElfReader() { _file.close(); }

// geters
ElfHeader ElfReader::get_header() const { return _header; }

std::vector<NamedSection> ElfReader::get_sections() const { return _sections; }

std::vector<NamedSymbol> ElfReader::get_static_symbols() const {
  return _static_symbols;
}

std::vector<ElfString> ElfReader::get_strings() const { return _strings; }

// filtered geters
bool ElfReader::is_position_independent() const {
  return _header.file_type == ET_DYN;
}

bool ElfReader::does_section_exist(const std::string_view &section_name) const {
  for (const auto &section : _sections) {
    if (section.name == section_name) {
      return true;
    }
  }
  return false;
}

NamedSection
ElfReader::get_section(const std::string_view &section_name) const {
  for (const auto &section : _sections) {
    if (section.name == section_name) {
      return section;
    }
  }

  throw std::runtime_error(std::format("missing section: {}", section_name));
}

size_t
ElfReader::get_section_index(const std::string_view &section_name) const {
  size_t index = 0;
  for (const auto &section : _sections) {
    if (section.name == section_name) {
      return index;
    }
    index++;
  }

  throw std::runtime_error(std::format("missing section: {}", section_name));
}

NamedSection ElfReader::get_section(std::size_t section_index) const {
  if (_sections.size() < section_index) {
    throw std::runtime_error("section search out of bounds: " + section_index);
  }

  return _sections[section_index];
}

std::vector<NamedSymbol> ElfReader::get_non_file_symbols() const {
  const auto symbol_filter = [&](const NamedSymbol &symbol) {
    return (symbol.type & SymbolType::file) == 0;
  };

  std::vector<NamedSymbol> symbols{};
  for (const auto &symbol :
       _static_symbols | std::views::filter(symbol_filter)) {
    symbols.push_back(symbol);
  }

  return symbols;
}

NamedSymbol ElfReader::get_symbol(std::string name) const {
  const auto function_filter = [&](const NamedSymbol &symbol) {
    return symbol.type & SymbolType::function && symbol.name == name;
  };
  const auto iterator = std::find_if(_static_symbols.begin(),
                                     _static_symbols.end(), function_filter);
  if (iterator == _static_symbols.end())
    throw std::runtime_error("missing function: " + name);

  return *iterator;
}

Function ElfReader::get_function(std::string name) const {
  const auto function = get_symbol(name);
  const uint64_t offset =
      function.value + _sections[function.section_index].unloaded_offset -
      _sections[function.section_index].loaded_virtual_address;
  _file.seekg(static_cast<long>(offset));
  std::vector<unsigned char> buffer(function.size);
  _file.read(reinterpret_cast<char *>(buffer.data()), buffer.size());

  return {.name = function.name,
          .address = function.value,
          .size = function.size,
          .opcodes = buffer};
}

std::vector<Function> ElfReader::get_functions() const {
  const auto text_section = get_section(code_section_name);
  const uint64_t section_start = text_section.loaded_virtual_address;
  const uint64_t section_end = section_start + text_section.size;
  std::vector<unsigned char> buffer(text_section.size);
  _file.seekg(static_cast<long>(text_section.unloaded_offset));
  _file.read(reinterpret_cast<char *>(buffer.data()), buffer.size());

  const auto function_filter = [&](const NamedSymbol &symbol) {
    return symbol.value >= section_start and
           symbol.value + symbol.size <= section_end;
  };

  std::vector<Function> functions{};
  for (const auto &symbol :
       _static_symbols | std::views::filter(function_filter)) {
    const auto function_start = buffer.begin() + symbol.value - section_start;
    const auto function_end =
        buffer.begin() + symbol.value + symbol.size - section_start;
    functions.push_back({symbol.name,
                         symbol.value,
                         symbol.size,
                         {function_start, function_end}});
  }

  return functions;
}

DependencyMap ElfReader::get_all_dependencies() {
  DependencyMap result;
  Disassembler disassembler;
  const std::vector<Function> functions = get_functions();
  const std::vector<Function> rela_functions = get_rela_functions();
  for (const auto &function : functions) {
    disassembler.append_dependencies(result, function, functions);
    if (function.name == "__libc_start_main_impl") {
      for (const auto &ifunc : rela_functions) {
        result.add_function_dependency(function, ifunc);
      }
    }
  }
  return result;
}

void ElfReader::correct_addresses(
    const DependencyMap &dependency_map,
    std::vector<Function> &dependency_chain) const {

  Disassembler disassembler;
  const std::vector<Function> functions = get_functions();
  uint64_t current_function_address =
      get_section(code_section_name).loaded_virtual_address;

  // apply new function address
  for (Function &function : dependency_chain) {
    function.address = current_function_address;
    current_function_address += function.size;
  }

  // apply new dependency addresses
  for (Function &function : dependency_chain) {
    disassembler.correct_relative_address(function, dependency_map,
                                          dependency_chain);
  }
}
std::vector<ElfRelocation>
ElfReader::correct_plt(const std::vector<Function> &dependency_chain) const {
  ElfRelocation relocation_info{};
  std::vector<ElfRelocation> result;
  const auto relocation_info_section =
      get_section(relocation_plt_symbol_info_section_name);
  const std::vector<Function> functions = get_functions();

  _file.seekg(static_cast<long>(relocation_info_section.unloaded_offset));

  while (static_cast<uint64_t>(_file.tellg()) <
         relocation_info_section.unloaded_offset +
             relocation_info_section.size) {
    _file.read(reinterpret_cast<char *>(&relocation_info),
               sizeof relocation_info);
    const auto old_function =
        std::find_if(functions.begin(), functions.end(),
                     [relocation_info](const Function &f) {
                       return f.address == relocation_info.function_address;
                     });
    if (old_function == functions.end())
      throw std::runtime_error("missing original rela function");

    const auto new_function =
        std::find_if(dependency_chain.begin(), dependency_chain.end(),
                     [old_function](const Function &f) {
                       return f.name == old_function->name;
                     });
    if (new_function == dependency_chain.end())
      throw std::runtime_error("missing new rela function");

    relocation_info.function_address = new_function->address;
    result.push_back(relocation_info);
  }

  return result;
}

std::vector<ElfSymbol>
ElfReader::correct_symtab(const std::vector<Function> &dependency_chain) const {
  const NamedSection symbol_table = get_section(static_symbol_section_name);

  _file.seekg(symbol_table.unloaded_offset);

  std::vector<ElfSymbol> symbols{};
  while (static_cast<uint64_t>(_file.tellg()) <
         symbol_table.unloaded_offset + symbol_table.size) {
    ElfSymbol symbol{};
    _file.read(reinterpret_cast<char *>(&symbol), sizeof symbol);
    symbols.push_back(symbol);
  }

  const NamedSection str_table = get_section(static_symbol_name_section_name);
  std::vector<NamedSymbol> named_symbols{};
  for (const auto &symbol : symbols) {
    _file.seekg(str_table.unloaded_offset + symbol.name);
    std::string name;
    std::getline(_file, name, '\0');
    named_symbols.emplace_back(name, static_cast<SymbolType>(symbol.type),
                               symbol.section_index, symbol.value, symbol.size);
  }

  int counter = 0;
  for (auto &symbol : named_symbols) {
    const auto it =
        std::find_if(dependency_chain.begin(), dependency_chain.end(),
                     [&](const Function &s) { return s.name == symbol.name; });

    if (it != dependency_chain.end())
      symbols.at(counter).value = it->address;

    counter++;
  }

  return symbols;
}

std::vector<Disassembler::Line>
ElfReader::get_function_code(const NamedSymbol &function,
                             bool try_resolve) const {
  if (!_file.is_open())
    throw std::runtime_error("binary open failed");

  const uint64_t offset =
      function.value + _sections[function.section_index].unloaded_offset -
      _sections[function.section_index].loaded_virtual_address;
  return get_code(offset, function.size, try_resolve);
}

std::vector<Disassembler::Line>
ElfReader::get_code(uint64_t address, uint64_t size, bool try_resolve) const {
  std::vector<unsigned char> buffer(size);
  _file.seekg(static_cast<long>(address));
  _file.read(reinterpret_cast<char *>(buffer.data()), buffer.size());

  Disassembler disassembler{};
  if (try_resolve)
    return disassembler.disassemble(buffer, address, get_static_symbols(),
                                    get_strings());
  else
    return disassembler.disassemble(buffer, address);
}

std::vector<Disassembler::Line>
ElfReader::get_function_code_by_name(std::string name) const {
  return get_function_code(get_symbol(name), true);
}

// factories
ElfHeader ElfReader::header_factory() {
  if (!_file.is_open())
    throw std::runtime_error("binary open failed");

  ElfHeader elf_header{};
  _file.read(reinterpret_cast<char *>(&elf_header), sizeof elf_header);

  return elf_header;
}

std::vector<NamedSection> ElfReader::sections_factory() {
  if (!_file.is_open())
    throw std::runtime_error("binary open failed");

  _file.seekg(static_cast<long>(_header.section_table_address));

  std::vector<SectionHeader> sections{};
  for (int i = 0; i < _header.section_table_entry_count; i++) {
    SectionHeader section{};
    _file.read(reinterpret_cast<char *>(&section), sizeof section);

    sections.push_back(section);
  }

  std::vector<NamedSection> named_sections{};
  for (const auto &section : sections) {
    _file.seekg(sections[_header.section_table_name_index].unloaded_offset +
                section.name_offset);
    std::string name;
    std::getline(_file, name, '\0');
    named_sections.emplace_back(
        name, section.type, section.attributes, section.loaded_virtual_address,
        section.unloaded_offset, section.size, section.associated_section_index,
        section.extra_information, section.required_alinment,
        section.entry_size);
  }

  return named_sections;
}

std::vector<NamedSymbol>
ElfReader::symbols_factory(const std::string_view &section_name,
                           const std::string_view &string_table_name) {
  if (!_file.is_open())
    throw std::runtime_error("binary open failed");

  const NamedSection symbol_table = get_section(section_name);

  _file.seekg(symbol_table.unloaded_offset);

  std::vector<ElfSymbol> symbols{};
  while (static_cast<uint64_t>(_file.tellg()) <
         symbol_table.unloaded_offset + symbol_table.size) {
    ElfSymbol symbol{};
    _file.read(reinterpret_cast<char *>(&symbol), sizeof symbol);
    symbols.push_back(symbol);
  }

  const NamedSection str_table = get_section(string_table_name);
  std::vector<NamedSymbol> named_symbols{};
  for (const auto &symbol : symbols) {
    _file.seekg(str_table.unloaded_offset + symbol.name);
    std::string name;
    std::getline(_file, name, '\0');
    named_symbols.emplace_back(name, static_cast<SymbolType>(symbol.type),
                               symbol.section_index, symbol.value, symbol.size);
  }

  return named_symbols;
}

std::vector<NamedSymbol> ElfReader::fake_static_symbols_factory() {
  if (!_file.is_open())
    throw std::runtime_error("binary open failed");

  const NamedSection code_section = get_section(code_section_name);
  _file.seekg(static_cast<long>(code_section.unloaded_offset));

  std::vector<unsigned char> buffer(code_section.size);
  _file.read(reinterpret_cast<char *>(buffer.data()), buffer.size());

  Disassembler disassembler{};
  const std::vector<Disassembler::Line> lines =
      disassembler.disassemble(buffer, code_section.unloaded_offset);

  const size_t section_index = get_section_index(code_section_name);
  const uint64_t section_address = code_section.loaded_virtual_address;
  const uint64_t entry_point = _header.entry_point_address;
  constexpr SymbolType symbol_type = SymbolType::function;
  std::vector<NamedSymbol> symbols{};
  size_t section_offset = 0;
  auto line = lines.begin();

  while (line != lines.end()) {
    const auto [amount_of_instructions, function_size] =
        find_next_start_of_function(line, lines.end());
    const uint64_t address = section_address + section_offset;
    const std::string function_name =
        address == entry_point ? "_start"
                               : std::format("function_{:x}", address);

    symbols.emplace_back(function_name, symbol_type, section_index, address,
                         function_size);

    section_offset += function_size;
    line += amount_of_instructions;
  }

  return symbols;
}

template <typename It>
std::pair<int, size_t> ElfReader::find_next_start_of_function(It begin,
                                                              It end) {
  int amount_of_instructions = 0;
  size_t function_size = 0;
  int amount_of_function_begin_passed = 0;
  for (; begin != end; ++begin) {
    if (begin->instruction == start_of_function_instruction)
      if (++amount_of_function_begin_passed == 2)
        break;

    amount_of_instructions++;
    function_size += begin->opcodes.end() - begin->opcodes.begin();
  }
  return std::make_pair(amount_of_instructions, function_size);
}

std::vector<NamedSymbol> ElfReader::static_symbols_factory() {
  if (does_section_exist(static_symbol_section_name))
    return symbols_factory(static_symbol_section_name,
                           static_symbol_name_section_name);
  return fake_static_symbols_factory();
}

std::vector<Function> ElfReader::get_rela_functions() {
  const auto functions = get_functions();
  const auto relocation_info_section =
      get_section(relocation_plt_symbol_info_section_name);
  ElfRelocation relocation_info{};
  std::vector<Function> rela_functions;

  _file.seekg(static_cast<long>(relocation_info_section.unloaded_offset));
  while (static_cast<uint64_t>(_file.tellg()) <
         relocation_info_section.unloaded_offset +
             relocation_info_section.size) {
    _file.read(reinterpret_cast<char *>(&relocation_info),
               sizeof relocation_info);
    for (const auto &function : functions) {
      if (function.address == relocation_info.function_address) {
        rela_functions.emplace_back(function);
        break;
      }
    }
  }

  return rela_functions;
}

void ElfReader::create_output_file(const std::string &output_file_name,
                                   const std::vector<Function> &functions,
                                   std::vector<ElfRelocation> &&plt,
                                   std::vector<ElfSymbol> &&symtab) {
  auto writer =
      std::ofstream(output_file_name, std::ios::out | std::ios::binary);
  if (!_file.is_open())
    throw std::runtime_error("binary open failed");
  if (!writer.is_open())
    throw std::runtime_error("output open failed");

  // overwrite entry address
  ElfHeader elf_header = get_header();
  elf_header.entry_point_address = functions[0].address;
  writer.write(reinterpret_cast<char *>(&elf_header), sizeof elf_header);

  // copy until .rela.plt section
  const auto plt_section = get_section(relocation_plt_symbol_info_section_name);
  const uint64_t plt_section_offset =
      plt_section.unloaded_offset - sizeof elf_header;
  std::vector<unsigned char> buffer(plt_section_offset);
  _file.seekg(static_cast<long>(sizeof elf_header));
  _file.read(reinterpret_cast<char *>(buffer.data()), buffer.size());
  writer.write(reinterpret_cast<char *>(buffer.data()), buffer.size());
  buffer.clear();
  buffer.shrink_to_fit();

  // write new rela plt section
  writer.write(reinterpret_cast<char *>(plt.data()), plt_section.size);

  // copy until text section
  const auto text = get_section(code_section_name);
  const auto until_text_section =
      plt_section.unloaded_offset + plt_section.size;
  const uint64_t text_section_offset =
      text.unloaded_offset - until_text_section;
  buffer.reserve(text_section_offset);
  _file.seekg(static_cast<long>(until_text_section));
  _file.read(reinterpret_cast<char *>(buffer.data()), text_section_offset);
  writer.write(reinterpret_cast<char *>(buffer.data()), text_section_offset);
  buffer.clear();
  buffer.shrink_to_fit();

  // write new text section
  uint64_t new_text_section_size = 0;
  for (const auto &function : functions) {
    writer.write(reinterpret_cast<const char *>(function.opcodes.data()),
                 function.opcodes.size());
    new_text_section_size += function.opcodes.size();
  }
  const uint64_t missing_size = text.size - new_text_section_size;
  std::vector<unsigned char> zeros(missing_size);
  writer.write(reinterpret_cast<const char *>(zeros.data()), zeros.size());
  zeros.clear();
  zeros.shrink_to_fit();

  // copy until symbol table
  const auto symbol_section = get_section(static_symbol_section_name);
  const auto already_wrote = text.unloaded_offset + text.size;
  const uint64_t symtab_offset = symbol_section.unloaded_offset - already_wrote;
  buffer.reserve(symtab_offset);
  _file.seekg(static_cast<long>(symtab_offset));
  _file.read(reinterpret_cast<char *>(buffer.data()), symtab_offset);
  writer.write(reinterpret_cast<char *>(buffer.data()), symtab_offset);
  buffer.clear();
  buffer.shrink_to_fit();

  // write new symbol table
  writer.write(reinterpret_cast<char *>(symtab.data()), symbol_section.size);

  // copy after text section
  _file.seekg(0, std::ios::end);
  const auto file_size = _file.tellg();
  const auto after_last_section = symbol_section.unloaded_offset + symbol_section.size;
  buffer.resize(static_cast<uint64_t>(file_size) - after_last_section);
  _file.seekg(static_cast<long>(after_last_section));
  _file.read(reinterpret_cast<char *>(buffer.data()), buffer.size());
  writer.write(reinterpret_cast<char *>(buffer.data()), buffer.size());
}

std::vector<ElfString> ElfReader::strings_factory() {
  if (!_file.is_open())
    throw std::runtime_error("binary open failed");

  const NamedSection string_section = get_section(".rodata");
  _file.seekg(static_cast<long>(string_section.unloaded_offset));
  std::vector<ElfString> strings;
  while (static_cast<uint64_t>(_file.tellg()) <
         string_section.unloaded_offset + string_section.size) {
    const auto address = static_cast<uint64_t>(_file.tellg());
    const auto value = get_next_string(string_section);
    if (_is_valid_string(value)) {
      strings.emplace_back(std::string{value.begin(), value.end()}, address);
    }
  }

  return strings;
}

std::vector<char>
ElfReader::get_next_string(const NamedSection &string_section) {
  char byte_read;
  std::vector<char> result;
  while (static_cast<uint64_t>(_file.tellg()) <
         string_section.unloaded_offset + string_section.size) {
    _file.read(reinterpret_cast<char *>(&byte_read), sizeof byte_read);

    if (byte_read == 0)
      break;

    result.push_back(byte_read);
  }
  return result;
}

bool ElfReader::_is_valid_string(const std::vector<char> &s) {
  if (s.size() == 0)
    return false;

  bool is_all_whitespace = true;
  for (const auto &character : s) {
    if (!std::isprint(character) and character != '\n')
      return false;

    if (is_all_whitespace) {
      is_all_whitespace = isspace(character);
    }
  }

  if (is_all_whitespace)
    return false;

  return true;
}
