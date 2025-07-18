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
    std::vector<unsigned char> opcodes;
    std::string instruction;
    std::string arguments;
    uint64_t address;
  };

public:
  Disassembler();
  ~Disassembler();

  static int64_t get_address(const std::string &instruction_argument);
  void append_dependencies(DependencyMap &dependency_map,
                           const Function &function,
                           const std::vector<Function> &static_symbols,
                           const NamedSection &plt_section,
                           const NamedSection &init_array_section,
                           const NamedSection &fini_array_section);
  void correct_relative_address(Function &function,
                                const DependencyMap &dependency_map,
                                const std::vector<Function> &static_symbols);
  std::vector<SwitchStatement>
  get_switch_statements(const std::vector<Function> &functions);

private:
  static std::optional<int32_t>
  _is_absolute_instruction(const std::string &instruction_operation,
                           const std::string &instruction_argument,
                           const std::vector<Function> &static_symbols,
                           const NamedSection &plt_section);
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
  static std::string _remove_prefix(const std::string &s);
  static bool _is_relative_instruction(const std::string &argument);
  template <typename T>
  static void _overwrite_nop(T &buffer_iterator, uint16_t size);
  template <typename T>
  static void _overwrite_end(T &buffer_iterator, int64_t relative_address,
                             uint16_t size);
  template <typename T>
  static void _overwrite_jmp(T &buffer_iterator, int64_t relative_address,
                             uint16_t size);
  template <typename T>
  static void _overwrite_cmp(T &buffer_iterator, const std::string &argument,
                             int64_t relative_address, uint16_t size);
  template <typename T>
  static void _overwrite_mov(T &buffer_iterator, int64_t relative_address,
                             uint16_t size);
  template <typename T>
  static void _overwrite_skip_two(T &buffer_iterator, int64_t relative_address,
                                  uint16_t size);
  static std::vector<unsigned char> _number_to_opcodes(int64_t number);

  static std::variant<Address, Function>
  _resolve_dependency(const std::vector<Function> &static_symbols,
                      Address address, const NamedSection &init_array_section,
                      const NamedSection &fini_array_section);
  static bool _is_indirect_function(Address address,
                                    const NamedSection &init_array_section,
                                    const NamedSection &fini_array_section);

private:
  csh _get_handler();

private:
  csh _handle;
};
