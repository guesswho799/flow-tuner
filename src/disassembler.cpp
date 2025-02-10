#include "disassembler.hpp"
#include "elf_header.hpp"
#include "status.hpp"

#include <algorithm>
#include <cstdint>
#include <elf.h>
#include <regex>
#include <sstream>
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
    throw Status::disassembler__open_failed;
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
    throw Status::disassembler__parse_failed;

  std::vector<Disassembler::Line> result;
  auto buffer_iterator = input_buffer.begin();

  for (int i = 0; i < count; i++) {

    const uint16_t size = insn[i].size;
    const uint64_t address = insn[i].address;
    const std::string argument = insn[i].op_str;
    const std::string operation = insn[i].mnemonic;

    const uint64_t post_address = address + size;
    const std::vector<uint16_t> opcodes(buffer_iterator,
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
  else if (_is_load_instruction(operation))
    return _resolve_address(static_symbols, strings,
                            address + get_address(argument));
  return "";
}

bool Disassembler::_is_absolute_instruction(
    const std::string &instruction_operation,
    const std::string &instruction_argument) {
  if (_is_call_instruction(instruction_operation) or
      _is_jump(instruction_operation))
    return _is_hex_number(instruction_argument);
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
  const std::regex pattern(".*\\[rip *([\\+-]) *0x([0-9a-f]+)\\].*");
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
  uint64_t result = 0;
  std::stringstream ss;
  ss << std::hex << number;
  ss >> result;
  return result;
}

bool Disassembler::_is_hex_number(const std::string &s) {
  if (!s.starts_with("0x"))
    return false;

  constexpr int skip_prefix = 2;
  std::string::const_iterator it = s.begin() + skip_prefix;
  while (it != s.end() and std::isxdigit(*it))
    ++it;
  return !s.empty() && it == s.end();
}

bool Disassembler::_is_call_instruction(const std::string &s) {
  return 0 == strncmp(s.c_str(), "call", 4);
}

bool Disassembler::_is_load_instruction(const std::string &s) {
  return 0 == strncmp(s.c_str(), "lea", 3);
}

bool Disassembler::_is_relative_instruction(const std::string &s) {
  const std::regex pattern(".*\\[rip [\\+-] 0x[0-9a-f]+\\].*");
  return std::regex_match(s, pattern);
}

Dependencies
Disassembler::get_dependencies(const Function &function,
                               const std::vector<Function> &static_symbols) {
  cs_insn *insn;
  const ssize_t count =
      cs_disasm(_handle, function.opcodes.data(), function.opcodes.size(),
                function.address, 0, &insn);
  if (count < 0)
    throw Status::disassembler__parse_failed;

  Dependencies result;
  auto buffer_iterator = function.opcodes.begin();

  for (int i = 0; i < count; i++) {

    const uint16_t size = insn[i].size;
    const uint64_t address = insn[i].address;
    const std::string argument = insn[i].op_str;
    const std::string operation = insn[i].mnemonic;
    Address target_address = 0;

    if (address == 4202484)
      breakpoint();

    if (_is_relative_instruction(argument)) {
      target_address = address + size + get_address(argument);
    } else if (_is_absolute_instruction(operation, argument)) {
      target_address = _hex_to_decimal(argument);
    }

    if (target_address) {
      const std::variant<Address, Function> dependency =
          _resolve_dependency(static_symbols, target_address);

      if (std::holds_alternative<Function>(dependency))
        result.first.push_back(std::get<Function>(dependency));
      if (std::holds_alternative<Address>(dependency)) {
        const Address dependency_address = std::get<Address>(dependency);
        if (dependency_address < function.address or
            dependency_address > function.address + function.size)
          result.second.push_back(dependency_address);
      }
    }

    buffer_iterator += size;
  }

  cs_free(insn, count);
  return result;
}

void Disassembler::breakpoint() {}

std::variant<Address, Function>
Disassembler::_resolve_dependency(const std::vector<Function> &static_symbols,
                                  uint64_t address) {
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
