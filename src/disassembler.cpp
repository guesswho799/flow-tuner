#include "disassembler.hpp"
#include "elf_header.hpp"
#include "x86_64_instructions.hpp"

#include <algorithm>
#include <cstdint>
#include <elf.h>
#include <iostream>
#include <regex>
#include <sstream>
#include <stdexcept>
#include <string.h>
#include <string>
#include <variant>

Disassembler::Disassembler() : _handle(_get_handler()) {
  cs_option(_handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL);
}

Disassembler::~Disassembler() { cs_close(&_handle); }

csh Disassembler::_get_handler() {
  csh handle;
  if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
    throw std::runtime_error("Disassmebler open failed");
  return handle;
}

std::optional<int32_t> Disassembler::_is_absolute_instruction(
    const std::string &operation, const std::string &argument,
    const std::vector<Function> &static_symbols,
    const NamedSection &plt_section) {
  using namespace X86_64Instructions;
  if (!is_call(operation) and !is_jump(operation) and !is_mov(operation))
    return {};
  if (!_is_hex_number(argument))
    return {};

  const auto dependency_address = _hex_to_decimal(argument);
  if (dependency_address >= plt_section.loaded_virtual_address and
      dependency_address <
          plt_section.loaded_virtual_address + plt_section.size) {
    return dependency_address - plt_section.loaded_virtual_address;
  }
  for (const auto &function : static_symbols) {
    if (dependency_address == function.address) {
      return 0;
    }
  }
  for (const auto &function : static_symbols) {
    if (dependency_address >= function.address and
        dependency_address < function.address + function.size) {
      return dependency_address - function.address;
    }
  }
  return {};
}

std::string
Disassembler::_resolve_address(const std::vector<NamedSymbol> &static_symbols,
                               const std::vector<ElfString> &strings,
                               uint64_t address) {
  const std::string symbol = _resolve_symbol(static_symbols, address);
  if (!symbol.empty())
    return symbol;

  const std::string s = _resolve_string(strings, address);
  if (!s.empty())
    return s;

  return " " + std::to_string(address);
}

std::string
Disassembler::_resolve_symbol(const std::vector<NamedSymbol> &static_symbols,
                              uint64_t address) {
  // TODO: optimize, unordered map instead of vector
  for (const auto &symbol : static_symbols) {
    if (symbol.value == address)
      return " <" + symbol.name + ">";
  }

  return "";
}

std::string Disassembler::_resolve_string(const std::vector<ElfString> &strings,
                                          uint64_t address) {
  constexpr size_t max_string_size = 15;
  for (const auto &s : strings) {
    if (s.address == address) {
      std::string result = s.value;
      if (result.size() > max_string_size) {
        result.resize(max_string_size - 3);
        result += "...";
      }
      return " \"" + result + "\"";
    }
  }
  return "";
}

int64_t Disassembler::get_address(const std::string &instruction_argument) {
  const std::regex pattern(".*\\[rip ([\\+-]) (0x[0-9a-f]+)\\].*");
  std::smatch match;
  if (std::regex_match(instruction_argument, match, pattern)) {
    int64_t address = _hex_to_decimal(match[2].str());
    if (0 == strncmp(match[1].str().c_str(), "-", 1)) {
      address *= -1;
    }
    return address;
  }
  return 0;
}

uint64_t Disassembler::_hex_to_decimal(const std::string &number) {
  const size_t index = number.find("0x");
  uint64_t result = 0;
  std::stringstream ss;
  ss << std::hex << number.substr(index);
  ss >> result;
  return result;
}

bool Disassembler::_is_hex_number(const std::string &s) {
  const size_t index = s.find("0x");
  if (index == std::string::npos)
    return false;

  const size_t skip_prefix = 2 + index;
  std::string::const_iterator it = s.begin() + skip_prefix;
  while (it != s.end() and std::isxdigit(*it))
    ++it;
  return !s.empty() && it == s.end();
}

bool Disassembler::_is_relative_instruction(const std::string &argument) {
  return argument.find("rip") != std::string::npos;
}

void Disassembler::append_dependencies(
    DependencyMap &dependency_map, const Function &function,
    const std::vector<Function> &static_symbols,
    const NamedSection &plt_section, const NamedSection &init_array_section,
    const NamedSection &fini_array_section) {
  cs_insn *insn;
  const ssize_t count =
      cs_disasm(_handle, function.opcodes.data(), function.opcodes.size(),
                function.address, 0, &insn);
  if (count < 0)
    throw std::runtime_error("Disassmebler parse failed");

  for (uint16_t i = 0; i < count; i++) {

    const uint16_t size = insn[i].size;
    const uint64_t address = insn[i].address;
    const std::string argument = insn[i].op_str;
    const std::string operation = insn[i].mnemonic;
    const bool is_relative = _is_relative_instruction(argument);
    const auto is_absolute = _is_absolute_instruction(
        operation, argument, static_symbols, plt_section);
    Address target_address = 0;

    if (is_relative) {
      target_address = address + size + get_address(argument);
    } else if (is_absolute.has_value()) {
      target_address = _hex_to_decimal(argument);
    } else {
      continue;
    }

    const std::variant<Address, Function> dependency = _resolve_dependency(
        static_symbols, target_address, init_array_section, fini_array_section);
    const bool is_function = std::holds_alternative<Function>(dependency);
    const bool is_address = std::holds_alternative<Address>(dependency);

    const bool is_inside_dependency =
        target_address > function.address and
        target_address < function.address + function.size;
    if (is_inside_dependency)
      continue;

    bool correct_as_absolute = is_absolute.has_value();
    using namespace X86_64Instructions;
    if (is_call(operation) or is_jump(operation))
      correct_as_absolute = false;

    if (is_function) {
      const Function dep = std::get<Function>(dependency);
      dependency_map.add_function_dependency(
          function, dep, i, correct_as_absolute, is_absolute.value_or(0));
    } else if (is_address) {
      dependency_map.add_non_function_dependency(
          function, std::get<Address>(dependency), i, correct_as_absolute);
    } else {
      throw std::runtime_error("unable to parse function: " + function.name +
                               ", address: " + std::to_string(address));
    }
  }

  cs_free(insn, count);
}

std::variant<Address, Function>
Disassembler::_resolve_dependency(const std::vector<Function> &static_symbols,
                                  Address address,
                                  const NamedSection &init_array_section,
                                  const NamedSection &fini_array_section) {
  if (address >= init_array_section.loaded_virtual_address and
      address <
          init_array_section.loaded_virtual_address + init_array_section.size) {
    return init_array_section.loaded_virtual_address;
  }
  if (address >= fini_array_section.loaded_virtual_address and
      address <
          fini_array_section.loaded_virtual_address + fini_array_section.size) {
    return fini_array_section.loaded_virtual_address;
  }
  for (const auto &function : static_symbols) {
    if (address == function.address) {
      return function;
    }
  }
  for (const auto &function : static_symbols) {
    if (address >= function.address and
        address < function.address + function.size)
      return function;
  }

  return address;
}

bool Disassembler::_is_indirect_function(
    Address address, const NamedSection &init_array_section,
    const NamedSection &fini_array_section) {
  return (address >= init_array_section.loaded_virtual_address and
          address < init_array_section.loaded_virtual_address +
                        init_array_section.size) or
         (address >= fini_array_section.loaded_virtual_address and
          address < fini_array_section.loaded_virtual_address +
                        fini_array_section.size);
}

void Disassembler::correct_relative_address(
    Function &function, const DependencyMap &dependency_map,
    const std::vector<Function> &static_symbols) {
  cs_insn *insn;
  const ssize_t count =
      cs_disasm(_handle, function.opcodes.data(), function.opcodes.size(),
                function.address, 0, &insn);
  if (count < 0)
    throw std::runtime_error("Disassmebler parse failed");

  auto buffer_iterator = function.opcodes.begin();

  for (uint16_t i = 0; i < count; i++) {
    const auto address_dependency =
        dependency_map.get_non_function_dependency(function, i);
    const auto function_dependency =
        dependency_map.get_function_dependency(function, i);
    const uint16_t size = insn[i].size;
    const uint64_t address = insn[i].address;
    const std::string operation = _remove_prefix(insn[i].mnemonic);
    const std::string argument = insn[i].op_str;
    int64_t relative_address = 0;

    if (address_dependency.has_value()) {
      const auto [target_address, is_absolute] = address_dependency.value();
      if (is_absolute)
        relative_address = target_address;
      else
        relative_address = target_address - (address + size);

    } else if (function_dependency.has_value()) {
      const auto [target_function, is_absolute, offset] =
          function_dependency.value();
      for (const auto &it : static_symbols) {
        if (it.name == target_function.name) {
          if (is_absolute)
            relative_address = it.address + offset;
          else
            relative_address = it.address - (address + size) + offset;
          break;
        }
      }

    } else {
      buffer_iterator += size;
      continue;
    }

    X86_64Instructions::overwrite_instruction(operation, buffer_iterator,
                                              argument, relative_address, size);
  }

  cs_free(insn, count);
}

std::vector<SwitchStatement>
Disassembler::get_switch_statements(const std::vector<Function> &functions) {
  std::vector<SwitchStatement> switch_statements;
  for (const Function &function : functions) {
    cs_insn *insn;
    const ssize_t count =
        cs_disasm(_handle, function.opcodes.data(), function.opcodes.size(),
                  function.address, 0, &insn);
    if (count < 0)
      throw std::runtime_error("Disassmebler parse failed");

    for (uint16_t i = 0; i < count; i++) {
      bool found_jump_table = false;
      const uint16_t size = insn[i].size;
      const uint64_t address = insn[i].address;
      const std::string operation = insn[i].mnemonic;
      const std::string argument = insn[i].op_str;
      if (!operation.starts_with("notrack")) {
        continue;
      }

      for (int backward_counter = i - 1;
           backward_counter >= 0 and found_jump_table == false;
           backward_counter--) {
        const uint16_t previous_size = insn[backward_counter].size;
        const std::string previous_operation = insn[backward_counter].mnemonic;
        const std::string previous_argument = insn[backward_counter].op_str;
        const uint64_t previous_address = insn[backward_counter].address;
        if (previous_operation.starts_with("lea") and
            previous_argument.find("rip") != std::string::npos) {
          const auto jump_to =
              previous_address + previous_size + get_address(previous_argument);
          const auto jump_from = address + size;
          switch_statements.emplace_back(jump_from, jump_to, function);
          found_jump_table = true;
        }
      }
      if (found_jump_table == false) {
        std::stringstream ss;
        ss << std::hex << address;
        throw std::runtime_error("switch statement jump missing base jump "
                                 "table address load instruction: " +
                                 function.name + ", at address: 0x" + ss.str());
      }
    }
    cs_free(insn, count);
  }

  return switch_statements;
}

std::string Disassembler::_remove_prefix(const std::string &s) {
  const std::string_view prefix = "lock ";
  if (s.starts_with(prefix))
    return s.substr(prefix.size());
  return s;
}
