#pragma once

#include "dependency.hpp"
#include "elf_header.hpp"
#include <capstone/capstone.h>
#include <cstdint>
#include <string>
#include <variant>
#include <vector>

class Disassembler {
public:
  struct Line {
    std::vector<uint16_t> opcodes;
    std::string instruction;
    std::string arguments;
    uint64_t address;
  };

public:
  Disassembler();
  ~Disassembler();

  std::vector<Line>
  disassemble(const std::vector<uint8_t> &input_buffer, uint64_t base_address,
              const std::vector<NamedSymbol> &static_symbols = {},
              const std::vector<ElfString> &strings = {});
  static int64_t get_address(const std::string &instruction_argument);
  void append_dependencies(DependencyMap& dependency_map, const Function &function,
                                const std::vector<Function> &static_symbols);

private:
  static void breakpoint();
  static std::string
  _generate_comment(const std::string &operation, const std::string &argument,
                    uint64_t address,
                    const std::vector<NamedSymbol> &static_symbols,
                    const std::vector<ElfString> &strings);

  static bool _is_absolute_instruction(const std::string &instruction_operation,
                                       const std::string &instruction_argument);
  static std::string
  _resolve_address(const std::vector<NamedSymbol> &static_symbols,
                   const std::vector<ElfString> &strings, uint64_t address);
  static std::string
  _resolve_symbol(const std::vector<NamedSymbol> &static_symbols,
                  uint64_t address);
  static std::string _resolve_string(const std::vector<ElfString> &strings,
                                     uint64_t address);
  static uint64_t _hex_to_decimal(const std::string &number);
  static bool _is_hex_number(const std::string &number);
  static bool _is_call(const std::string &s);
  static bool _is_mov(const std::string &s);
  static bool _is_load_instruction(const std::string &s);
  static bool _is_relative_instruction(const std::string &s);

  static std::variant<Address, Function>
  _resolve_dependency(const std::vector<Function> &static_symbols,
                      Address address);
  static bool _is_jump(const std::string &instruction);

private:
  csh _get_handler();

private:
  csh _handle;
};
