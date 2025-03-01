#include "disassembler.hpp"
#include "elf_header.hpp"

#include <algorithm>
#include <cstdint>
#include <elf.h>
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

std::vector<Disassembler::Line>
Disassembler::disassemble(const std::vector<uint8_t> &input_buffer,
                          uint64_t base_address,
                          const std::vector<NamedSymbol> &static_symbols,
                          const std::vector<ElfString> &strings) {
  cs_insn *insn;
  const ssize_t count = cs_disasm(_handle, input_buffer.data(),
                                  input_buffer.size(), base_address, 0, &insn);
  if (count < 0)
    throw std::runtime_error("Disassmebler parse failed");

  std::vector<Disassembler::Line> result;
  auto buffer_iterator = input_buffer.begin();

  for (int i = 0; i < count; i++) {

    const uint16_t size = insn[i].size;
    const uint64_t address = insn[i].address;
    const std::string argument = insn[i].op_str;
    const std::string operation = insn[i].mnemonic;

    const uint64_t post_address = address + size;
    const std::vector<unsigned char> opcodes(buffer_iterator,
                                             buffer_iterator + size);
    const std::string comment = _generate_comment(
        operation, argument, post_address, static_symbols, strings);
    const std::string full_argument = argument + comment;

    result.emplace_back(opcodes, operation, full_argument, address);
    buffer_iterator += size;
  }
  cs_free(insn, count);
  return result;
}

std::string
Disassembler::_generate_comment(const std::string &operation,
                                const std::string &argument, uint64_t address,
                                const std::vector<NamedSymbol> &static_symbols,
                                const std::vector<ElfString> &strings) {
  if (_is_absolute_instruction(operation, argument))
    return _resolve_symbol(static_symbols, _hex_to_decimal(argument));
  else if (_is_load(operation))
    return _resolve_address(static_symbols, strings,
                            address + get_address(argument));
  return "";
}

bool Disassembler::_is_absolute_instruction(const std::string &operation,
                                            const std::string &argument) {
  if (_is_call(operation) or _is_jump(operation) or _is_mov(operation))
    return _is_hex_number(argument);
  return false;
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

bool Disassembler::_is_movq(const std::string &s) {
  return 0 == strncmp(s.c_str(), "movq", 4);
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
  const std::regex pattern(".*\\[rip [\\+-] 0x[0-9a-f]+\\].*");
  return std::regex_match(argument, pattern);
}

void Disassembler::append_dependencies(
    DependencyMap &dependency_map, const Function &function,
    const std::vector<Function> &static_symbols) {
  cs_insn *insn;
  const ssize_t count =
      cs_disasm(_handle, function.opcodes.data(), function.opcodes.size(),
                function.address, 0, &insn);
  if (count < 0)
    throw std::runtime_error("Disassmebler parse failed");

  auto buffer_iterator = function.opcodes.begin();

  for (uint16_t i = 0; i < count; i++) {

    const uint16_t size = insn[i].size;
    const uint64_t address = insn[i].address;
    const std::string argument = insn[i].op_str;
    const std::string operation = insn[i].mnemonic;
    const bool is_relative = _is_relative_instruction(argument);
    const bool is_absolute = _is_absolute_instruction(operation, argument);
    Address target_address = 0;

    if (is_relative) {
      target_address = address + size + get_address(argument);

    } else if (is_absolute) {
      target_address = _hex_to_decimal(argument);
    }

    if (target_address) {
      const std::variant<Address, Function> dependency =
          _resolve_dependency(static_symbols, target_address);
      const bool is_function = std::holds_alternative<Function>(dependency);
      const bool is_address = std::holds_alternative<Address>(dependency);

      if (is_function) {
        bool correct_as_absolute = is_absolute;
        if (_is_call(operation))
          correct_as_absolute = false;

        dependency_map.add_function_dependency(
            function, std::get<Function>(dependency), i, correct_as_absolute);
      } else if (is_address and is_relative) {
        const Address dependency_address = std::get<Address>(dependency);
        const bool is_outside_dependency =
            dependency_address < function.address or
            dependency_address > function.address + function.size;
        if (is_outside_dependency) {
          dependency_map.add_non_function_dependency(
              function, dependency_address, i, is_absolute);
        }
      }
    }

    buffer_iterator += size;
  }

  cs_free(insn, count);
}

void Disassembler::breakpoint() {}

std::variant<Address, Function>
Disassembler::_resolve_dependency(const std::vector<Function> &static_symbols,
                                  Address address) {
  for (const auto &function : static_symbols) {
    if (function.address == address)
      return function;
  }

  return address;
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
      const auto [target_function, is_absolute] = function_dependency.value();
      for (const auto &it : static_symbols) {
        if (it.name == target_function.name) {
          if (is_absolute)
            relative_address = it.address;
          else
            relative_address = it.address - (address + size);
          break;
        }
      }

    } else {
      // security jumps, getting next line to jump to from rodata section
      // overwriting text section addresses in rodata would cause false
      // positives
      if (_is_notrack(operation)) {
        _overwrite_nop(buffer_iterator, size);
      } else {
        buffer_iterator += size;
      }
      continue;
    }

    if (_is_call(operation) or _is_cmov(operation) or _is_load(operation) or
        _is_inc(operation) or _is_dec(operation) or _is_ucomisd(operation) or
        _is_andpd(operation) or _is_pand(operation) or _is_fld(operation) or
        _is_add(operation) or _is_imul(operation) or _is_xadd(operation) or
        _is_sub(operation) or _is_divss(operation) or _is_push(operation) or
        _is_movq(operation) or _is_movups(operation) or
        _is_vmovdqa(operation)) {
      _overwrite_end(buffer_iterator, relative_address, size);
    } else if (_is_test(operation) or _is_and(operation)) {
      _overwrite_skip_two(buffer_iterator, relative_address, size);
    } else if (_is_jump(operation)) {
      _overwrite_jmp(buffer_iterator, relative_address, size);
    } else if (_is_cmp(operation) or _is_xchg(operation)) {
      _overwrite_cmp(buffer_iterator, argument, relative_address, size);
    } else if (_is_mov(operation) or _is_or(operation)) {
      _overwrite_mov(buffer_iterator, relative_address, size);
    } else {
      throw std::runtime_error("unsupported instruction in function " +
                               function.name + ": " + operation + " " +
                               argument);
    }
  }

  cs_free(insn, count);
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
  const int amount_to_skip = *buffer_iterator == 0x48 or * buffer_iterator ==
                                     0x66 or * buffer_iterator ==
                                     0x44 or * buffer_iterator == 0x4c
                                 ? 3
                                 : 2;
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
