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

std::vector<unsigned char>
ElfReader::get_section_data(const std::string_view &section_name) const {
  const NamedSection section_info = get_section(section_name);
  std::vector<unsigned char> section_data(section_info.size);
  _file.seekg(static_cast<long>(section_info.unloaded_offset));
  _file.read(reinterpret_cast<char *>(section_data.data()),
             section_data.size());

  return section_data;
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

NamedSymbol ElfReader::get_symbol(const std::string& name) const {
  const auto function_filter = [&](const NamedSymbol &symbol) {
    return symbol.name == name;
  };
  const auto iterator = std::find_if(_static_symbols.begin(),
                                     _static_symbols.end(), function_filter);
  if (iterator == _static_symbols.end())
    throw std::runtime_error("missing function: " + name);

  return *iterator;
}

Function ElfReader::get_function(const std::string& name) const {
  const auto function = get_symbol(name);
  const uint64_t offset =
      function.value + _sections[function.section_index].unloaded_offset -
      _sections[function.section_index].loaded_virtual_address;

  // because bug in gcc? sybols missing size, must set by hand
  uint64_t actual_size = function.size;
  if (name == "__do_global_dtors_aux" or name == "frame_dummy" or
      name == "register_tm_clones" or name == "deregister_tm_clones") {
    actual_size = 0x40;
  } else if (name == "_fini") {
    actual_size = 0xd;
  } else if (name == "_init") {
    actual_size = 0x1b;
  } else if (name == "__restore_rt") {
    actual_size = 0x9;
  }
  _file.seekg(static_cast<long>(offset));
  std::vector<unsigned char> buffer(actual_size);
  _file.read(reinterpret_cast<char *>(buffer.data()), buffer.size());

  return {.name = function.name,
          .address = function.value,
          .size = actual_size,
          .opcodes = buffer};
}

std::vector<Function> ElfReader::get_functions() const {
  const auto text_section = get_section(code_section_name);
  const auto init_section = get_section(init_section_name);
  const auto fini_section = get_section(fini_section_name);

  const auto is_in_section = [](const NamedSection &section,
                                const NamedSymbol &symbol) {
    return symbol.value >= section.loaded_virtual_address and
           symbol.value + symbol.size <=
               section.loaded_virtual_address + section.size;
  };
  const auto function_filter = [&](const NamedSymbol &symbol) {
    return is_in_section(text_section, symbol) or
           is_in_section(init_section, symbol) or
           is_in_section(fini_section, symbol);
  };

  std::vector<Function> functions{};
  for (const auto &symbol :
       _static_symbols | std::views::filter(function_filter)) {
    functions.push_back(get_function(symbol.name));
  }

  return functions;
}

DependencyMap ElfReader::get_all_dependencies() {
  DependencyMap result;
  Disassembler disassembler;
  const std::vector<Function> functions = get_functions();
  const std::vector<Function> rela_functions = get_rela_functions();
  const std::vector<Function> init_functions =
      get_functions_from_array_section(init_array_section_name);
  const std::vector<Function> fini_functions =
      get_functions_from_array_section(fini_array_section_name);
  const auto plt_section = get_section(plt_section_name);
  const auto init_array_section = get_section(init_array_section_name);
  const auto fini_array_section = get_section(fini_array_section_name);
  for (const auto &function : functions) {
    disassembler.append_dependencies(result, function, functions, plt_section,
                                     init_array_section, fini_array_section);
    if (function.name == "__libc_start_main_impl") {
      for (const auto &ifunc : rela_functions) {
        result.add_function_dependency(function, ifunc);
      }
      for (const auto &init_function : init_functions) {
        result.add_function_dependency(function, init_function);
      }
      for (const auto &fini_function : fini_functions) {
        result.add_function_dependency(function, fini_function);
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
      throw std::runtime_error("missing new rela function " +
                               old_function->name);

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
  const auto functions = get_functions();
  for (auto &symbol : named_symbols) {
    const auto used =
        std::find_if(dependency_chain.begin(), dependency_chain.end(),
                     [&](const Function &s) { return s.name == symbol.name; });
    const auto is_function = std::find_if(functions.begin(), functions.end(),
                                          [&](const Function &s) {
                                            return s.name == symbol.name;
                                          }) != functions.end();

    if (used != dependency_chain.end())
      symbols.at(counter).value = used->address;
    else if (is_function) {
      symbols.at(counter).value = 0;
    }

    counter++;
  }

  return symbols;
}

std::vector<Address> ElfReader::correct_init_array(
    const std::vector<Function> &dependency_chain) const {
  return _correct_array_section(dependency_chain, init_array_section_name);
}

std::vector<Address> ElfReader::correct_fini_array(
    const std::vector<Function> &dependency_chain) const {
  return _correct_array_section(dependency_chain, fini_array_section_name);
}

std::vector<Address>
ElfReader::_correct_array_section(const std::vector<Function> &dependency_chain,
                                  const std::string_view &section_name) const {
  std::vector<Address> addresses{};
  const NamedSection section = get_section(section_name);
  _file.seekg(section.unloaded_offset);

  while (static_cast<uint64_t>(_file.tellg()) <
         section.unloaded_offset + section.size) {
    Address address;
    _file.read(reinterpret_cast<char *>(&address), sizeof address);
    addresses.push_back(address);
  }

  const auto functions = get_functions();
  for (auto &address : addresses) {
    const auto function =
        std::find_if(functions.begin(), functions.end(),
                     [&](const Function &f) { return f.address == address; });

    if (function == functions.end())
      throw std::runtime_error(
          "missing function from init_array in static symbols: " +
          std::to_string(address));

    const auto new_function = std::find_if(
        dependency_chain.begin(), dependency_chain.end(),
        [&](const Function &s) { return s.name == function->name; });

    if (new_function == dependency_chain.end())
      throw std::runtime_error(
          "missing function from init_array in new dependency chain: " +
          std::to_string(address));

    address = new_function->address;
  }

  return addresses;
}

std::vector<unsigned char>
ElfReader::correct_rodata(const std::vector<Function> &dependency_chain) const {
  Disassembler disassembler;
  const auto functions = get_functions();
  const auto rodata_info = get_section(rodata_section_name);
  auto rodata_bytes = get_section_data(rodata_section_name);
  std::vector<SwitchStatement> switch_statements =
      disassembler.get_switch_statements(functions);

  for (std::size_t switch_counter = 0;
       switch_counter < switch_statements.size(); switch_counter++) {
    const SwitchStatement &switch_statement = switch_statements[switch_counter];
    std::optional<std::size_t> start_of_next_table;
    if (switch_counter != switch_statements.size() - 1) {
      start_of_next_table = switch_statements[switch_counter + 1].jump_table;
    }
    const auto is_func = [&](const auto &new_function) {
      return new_function.name == switch_statement.function.name;
    };
    const auto new_func =
        std::find_if(dependency_chain.begin(), dependency_chain.end(), is_func);
    if (new_func == dependency_chain.end()) {
      continue;
    }
    const auto old_jump_offset =
        switch_statement.jump_from - switch_statement.function.address;

    bool should_stay = true;
    int jump_table_index = 0;
    for (; should_stay; jump_table_index++) {

      uint32_t value = 0;
      const uint32_t element_offset = switch_statement.jump_table -
                                      rodata_info.loaded_virtual_address +
                                      jump_table_index * sizeof(uint32_t);

      if (element_offset + sizeof(uint32_t) > rodata_bytes.size() or
          (start_of_next_table.has_value() and
           start_of_next_table.value() == element_offset)) {
        should_stay = false;
        continue;
      }
      for (std::size_t counter = 0; counter < sizeof(uint32_t); counter++) {
        value |= static_cast<uint32_t>(rodata_bytes[element_offset + counter])
                 << (counter * 8);
      }
      const uint32_t old_destination_address =
          value + switch_statement.jump_table;
      if (old_destination_address > switch_statement.function.address +
                                        switch_statement.function.size or
          old_destination_address < switch_statement.function.address) {
        continue;
      }
      const int offset = old_destination_address - switch_statement.jump_from;

      const auto new_jump_address =
          new_func->address + old_jump_offset + offset;
      const uint32_t new_destination_address =
          new_jump_address - switch_statement.jump_table;
      for (std::size_t counter = 0; counter < sizeof(uint32_t); counter++) {
        uint16_t end = (new_destination_address >> (counter * 8)) & 0xFF;
        rodata_bytes[element_offset + counter] = end;
      }
    }
  }

  return rodata_bytes;
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
  return symbols_factory(static_symbol_section_name,
                         static_symbol_name_section_name);
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

std::vector<Function> ElfReader::get_functions_from_array_section(
    const std::string_view &section_name) {
  const auto section = get_section(section_name);
  const auto functions = get_functions();
  std::vector<Function> result;
  uint64_t address;

  _file.seekg(static_cast<long>(section.unloaded_offset));
  while (static_cast<uint64_t>(_file.tellg()) <
         section.unloaded_offset + section.size) {
    _file.read(reinterpret_cast<char *>(&address), sizeof(uint64_t));
    for (const auto &function : functions) {
      if (function.address == address) {
        result.emplace_back(function);
        break;
      }
    }
  }

  return result;
}

void ElfReader::create_output_file(
    const std::string &output_file_name, const std::vector<Function> &functions,
    std::vector<ElfRelocation> &&plt, std::vector<ElfSymbol> &&symtab,
    std::vector<Address> &&new_init_array_section,
    std::vector<Address> &&new_fini_array_section,
    std::vector<unsigned char> &&new_rodata_section) {
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

  // copy until rodata section
  const auto rodata_section = get_section(rodata_section_name);
  auto already_wrote = text.unloaded_offset + text.size;
  const uint64_t rodata_offset = rodata_section.unloaded_offset - already_wrote;
  buffer.reserve(rodata_offset);
  _file.seekg(static_cast<long>(already_wrote));
  _file.read(reinterpret_cast<char *>(buffer.data()), rodata_offset);
  writer.write(reinterpret_cast<char *>(buffer.data()), rodata_offset);
  buffer.clear();
  buffer.shrink_to_fit();

  // write new rodata section
  writer.write(reinterpret_cast<char *>(new_rodata_section.data()),
               new_rodata_section.size());

  // copy until init array section
  const auto init_array_section = get_section(init_array_section_name);
  const auto fini_array_section = get_section(fini_array_section_name);
  already_wrote = rodata_section.unloaded_offset + rodata_section.size;
  const uint64_t array_offset =
      init_array_section.unloaded_offset - already_wrote;
  buffer.reserve(array_offset);
  _file.seekg(static_cast<long>(already_wrote));
  _file.read(reinterpret_cast<char *>(buffer.data()), array_offset);
  writer.write(reinterpret_cast<char *>(buffer.data()), array_offset);
  buffer.clear();
  buffer.shrink_to_fit();

  // write new init array section
  writer.write(reinterpret_cast<char *>(new_init_array_section.data()),
               init_array_section.size);
  writer.write(reinterpret_cast<char *>(new_fini_array_section.data()),
               fini_array_section.size);

  // copy until symbol table
  const auto symbol_section = get_section(static_symbol_section_name);
  already_wrote = fini_array_section.unloaded_offset + fini_array_section.size;
  const uint64_t symtab_offset = symbol_section.unloaded_offset - already_wrote;
  buffer.reserve(symtab_offset);
  _file.seekg(static_cast<long>(already_wrote));
  _file.read(reinterpret_cast<char *>(buffer.data()), symtab_offset);
  writer.write(reinterpret_cast<char *>(buffer.data()), symtab_offset);
  buffer.clear();
  buffer.shrink_to_fit();

  // write new symbol table
  writer.write(reinterpret_cast<char *>(symtab.data()), symbol_section.size);

  // copy after text section
  _file.seekg(0, std::ios::end);
  const auto file_size = _file.tellg();
  const auto after_last_section =
      symbol_section.unloaded_offset + symbol_section.size;
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
