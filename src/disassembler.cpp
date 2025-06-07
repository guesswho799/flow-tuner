#include "disassembler.hpp"
#include "elf_header.hpp"

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
    const NamedSection &plt_section, const NamedSection &init_section) {
  if (!_is_call(operation) and !_is_jump(operation) and !_is_mov(operation))
    return {};
  if (!_is_hex_number(argument))
    return {};

  const auto dependency_address = _hex_to_decimal(argument);
  if (dependency_address == init_section.loaded_virtual_address) {
    return 0;
  }
  if (dependency_address >= plt_section.loaded_virtual_address and
      dependency_address <
          plt_section.loaded_virtual_address + plt_section.size) {
    return dependency_address - plt_section.loaded_virtual_address;
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

bool Disassembler::_is_notrack(const std::string &s) {
  return 0 == strncmp(s.c_str(), "notrack", 7);
}

bool Disassembler::_is_call(const std::string &s) {
  return 0 == strncmp(s.c_str(), "call", 4);
}

bool Disassembler::_is_mov(const std::string &s) {
  return 0 == strncmp(s.c_str(), "mov", 3);
}

bool Disassembler::_is_movups(const std::string &s) {
  return 0 == strncmp(s.c_str(), "movups", 6);
}

bool Disassembler::_is_movaps(const std::string &s) {
  return 0 == strncmp(s.c_str(), "movaps", 6);
}

bool Disassembler::_is_movq(const std::string &s) {
  return 0 == strncmp(s.c_str(), "movq", 4);
}

bool Disassembler::_is_movzx(const std::string &s) {
  return 0 == strncmp(s.c_str(), "movzx", 5);
}

bool Disassembler::_is_movdqa(const std::string &s) {
  return 0 == strncmp(s.c_str(), "movdqa", 6);
}

bool Disassembler::_is_vmovdqa(const std::string &s) {
  return 0 == strncmp(s.c_str(), "vmovdqa", 7);
}

bool Disassembler::_is_cmov(const std::string &s) {
  return 0 == strncmp(s.c_str(), "cmov", 4);
}

bool Disassembler::_is_load(const std::string &s) {
  return 0 == strncmp(s.c_str(), "lea", 3);
}

bool Disassembler::_is_inc(const std::string &s) {
  return 0 == strncmp(s.c_str(), "inc", 3);
}

bool Disassembler::_is_dec(const std::string &s) {
  return 0 == strncmp(s.c_str(), "dec", 3);
}

bool Disassembler::_is_add(const std::string &s) {
  return 0 == strncmp(s.c_str(), "add", 3);
}

bool Disassembler::_is_imul(const std::string &s) {
  return 0 == strncmp(s.c_str(), "imul", 4);
}

bool Disassembler::_is_xadd(const std::string &s) {
  return 0 == strncmp(s.c_str(), "xadd", 4);
}

bool Disassembler::_is_sub(const std::string &s) {
  return 0 == strncmp(s.c_str(), "sub", 3);
}

bool Disassembler::_is_divss(const std::string &s) {
  return 0 == strncmp(s.c_str(), "divss", 5);
}

bool Disassembler::_is_cmp(const std::string &s) {
  return 0 == strncmp(s.c_str(), "cmp", 3);
}

bool Disassembler::_is_xchg(const std::string &s) {
  return 0 == strncmp(s.c_str(), "xchg", 4);
}

bool Disassembler::_is_cmpxchg(const std::string &s) {
  return 0 == strncmp(s.c_str(), "cmpxchg", 7);
}

bool Disassembler::_is_ucomisd(const std::string &s) {
  return 0 == strncmp(s.c_str(), "ucomisd", 7);
}

bool Disassembler::_is_and(const std::string &s) {
  return 0 == strncmp(s.c_str(), "and", 3);
}

bool Disassembler::_is_andpd(const std::string &s) {
  return 0 == strncmp(s.c_str(), "andpd", 5);
}

bool Disassembler::_is_pand(const std::string &s) {
  return 0 == strncmp(s.c_str(), "pand", 4);
}

bool Disassembler::_is_fld(const std::string &s) {
  return 0 == strncmp(s.c_str(), "fld", 3);
}

bool Disassembler::_is_or(const std::string &s) {
  return 0 == strncmp(s.c_str(), "or", 2);
}

bool Disassembler::_is_test(const std::string &s) {
  return 0 == strncmp(s.c_str(), "test", 4);
}

bool Disassembler::_is_push(const std::string &s) {
  return 0 == strncmp(s.c_str(), "push", 4);
}

bool Disassembler::_is_relative_instruction(const std::string &argument) {
  return argument.find("rip") != std::string::npos;
}

void Disassembler::append_dependencies(
    DependencyMap &dependency_map, const Function &function,
    const std::vector<Function> &static_symbols,
    const NamedSection &plt_section, const NamedSection &init_section,
    const NamedSection &init_array_section,
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
        operation, argument, static_symbols, plt_section, init_section);
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
    if (_is_call(operation) or _is_jump(operation))
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

void Disassembler::breakpoint() {}

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

bool Disassembler::_is_jump(const std::string &instruction) {
  std::vector<std::string_view> jump_values{"jmp", "jb", "je",  "jne",
                                            "jg",  "jl", "jge", "jle"};
  return std::find(jump_values.begin(), jump_values.end(), instruction) !=
         jump_values.end();
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
            relative_address = it.address - address + size + offset;
          break;
        }
      }

    } else {
      buffer_iterator += size;
      continue;
    }

    if (_is_call(operation) or _is_cmov(operation) or _is_load(operation) or
        _is_inc(operation) or _is_dec(operation) or _is_ucomisd(operation) or
        _is_andpd(operation) or _is_pand(operation) or _is_fld(operation) or
        _is_imul(operation) or _is_xadd(operation) or _is_sub(operation) or
        _is_divss(operation) or _is_push(operation) or _is_movq(operation) or
        _is_movups(operation) or _is_movaps(operation) or
        _is_vmovdqa(operation) or _is_movdqa(operation) or
        _is_movzx(operation) or _is_cmpxchg(operation)) {
      _overwrite_end(buffer_iterator, relative_address, size);
    } else if (_is_test(operation) or _is_and(operation)) {
      _overwrite_skip_two(buffer_iterator, relative_address, size);
    } else if (_is_jump(operation)) {
      _overwrite_jmp(buffer_iterator, relative_address, size);
    } else if (_is_cmp(operation) or _is_xchg(operation) or
               _is_add(operation)) {
      _overwrite_cmp(buffer_iterator, argument, relative_address, size);
    } else if (_is_mov(operation) or _is_or(operation)) {
      _overwrite_mov(buffer_iterator, relative_address, size);
    } else {
      throw std::runtime_error(
          "unsupported instruction in function " + function.name + ": " +
          operation + " " + argument + ", address? " +
          std::to_string(address_dependency.has_value()) + ", function? " +
          std::to_string(function_dependency.has_value()));
    }
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

template <typename T>
void Disassembler::_overwrite_nop(T &buffer_iterator, uint16_t size) {
  for (int i = 0; i < size; i++) {
    *buffer_iterator = 0x90;
    buffer_iterator++;
  }
}

template <typename T>
void Disassembler::_overwrite_end(T &buffer_iterator, int64_t relative_address,
                                  uint16_t size) {
  const int amount_to_skip = size - 4;
  buffer_iterator += amount_to_skip;
  for (const auto &opcode : _number_to_opcodes(relative_address)) {
    *buffer_iterator = opcode;
    buffer_iterator++;
  }
}

template <typename T>
void Disassembler::_overwrite_jmp(T &buffer_iterator, int64_t relative_address,
                                  uint16_t size) {
  const int amount_to_skip = *buffer_iterator == 0x0f ? 2 : 1;
  buffer_iterator += amount_to_skip;
  for (const auto &opcode : _number_to_opcodes(relative_address)) {
    *buffer_iterator = opcode;
    buffer_iterator++;
  }
  const auto bytes_left = size - (amount_to_skip + 4);
  buffer_iterator += bytes_left;
}

template <typename T>
void Disassembler::_overwrite_cmp(T &buffer_iterator,
                                  const std::string &argument,
                                  int64_t relative_address, uint16_t size) {
  const int amount_to_skip =
      argument.find("qword") != std::string::npos ? 3 : 2;
  buffer_iterator += amount_to_skip;
  for (const auto &opcode : _number_to_opcodes(relative_address)) {
    *buffer_iterator = opcode;
    buffer_iterator++;
  }
  const auto bytes_left = size - (amount_to_skip + 4);
  buffer_iterator += bytes_left;
}

template <typename T>
void Disassembler::_overwrite_mov(T &buffer_iterator, int64_t relative_address,
                                  uint16_t size) {
  int amount_to_skip = 0;
  switch (*buffer_iterator) {
  case 0x48:
  case 0x66:
  case 0x44:
  case 0x4c:
    amount_to_skip = 3;
    break;
  case 0xb8:
    amount_to_skip = 1;
    break;
  default:
    amount_to_skip = 2;
    break;
  }
  buffer_iterator += amount_to_skip;
  for (const auto &opcode : _number_to_opcodes(relative_address)) {
    *buffer_iterator = opcode;
    buffer_iterator++;
  }
  const auto bytes_left = size - (amount_to_skip + 4);
  buffer_iterator += bytes_left;
}

template <typename T>
void Disassembler::_overwrite_skip_two(T &buffer_iterator,
                                       int64_t relative_address,
                                       uint16_t size) {
  buffer_iterator += 2;
  for (const auto &opcode : _number_to_opcodes(relative_address)) {
    *buffer_iterator = opcode;
    buffer_iterator++;
  }
  const auto bytes_left = size - 6;
  buffer_iterator += bytes_left;
}

std::vector<unsigned char> Disassembler::_number_to_opcodes(int64_t number) {
  const uint64_t mask = 0xFF;
  const uint64_t jump_interval_in_bits = 8;
  const uint64_t size_of_instruction_address = 4;
  std::vector<uint8_t> result;
  for (uint64_t i = 0; i < size_of_instruction_address; i++) {
    const uint64_t current_mask = mask << (jump_interval_in_bits * i);
    const unsigned char current_number = static_cast<unsigned char>(
        (number & current_mask) >> (jump_interval_in_bits * i));
    result.push_back(current_number);
  }
  result.shrink_to_fit();
  return result;
}
