#pragma once

#include <cstdint>
#include <fstream>
#include <string>
#include <sys/types.h>
#include <vector>

#include "disassembler.hpp"
#include "elf_header.hpp"

class ElfReader {
  // constructors
public:
  explicit ElfReader(std::string file_name);
  ElfReader(const ElfReader &other) = delete;
  ElfReader &operator=(const ElfReader &other) = delete;
  ElfReader(ElfReader &&other);
  ElfReader &operator=(ElfReader &&other);
  ~ElfReader();

  // geters
public:
  ElfHeader get_header() const;
  std::vector<NamedSection> get_sections() const;
  std::vector<NamedSymbol> get_static_symbols() const;
  std::vector<ElfString> get_strings() const;

  // filtered geters
public:
  bool is_position_independent() const;
  bool does_section_exist(const std::string_view &section_name) const;
  NamedSection get_section(const std::string_view &section_name) const;
  NamedSection get_section(std::size_t section_index) const;
  size_t get_section_index(const std::string_view &section_name) const;
  std::vector<NamedSymbol> get_non_file_symbols() const;
  NamedSymbol get_symbol(std::string name) const;
  Function get_function(std::string name) const;
  std::vector<Function> get_functions() const;
  std::vector<NamedSymbol>
  get_symbol_dependencies(const Function &function) const;
  std::vector<Disassembler::Line> get_function_code(const NamedSymbol &function,
                                                    bool try_resolve) const;
  std::vector<Disassembler::Line>
  get_function_code_by_name(std::string name) const;
  DependencyMap get_all_dependencies() const;
  void correct_addresses(const DependencyMap &dependency_map,
                         std::vector<Function> &dependency_chain) const;

  // factories
private:
  ElfHeader header_factory();
  std::vector<NamedSection> sections_factory();
  std::vector<NamedSymbol>
  symbols_factory(const std::string_view &section_name,
                  const std::string_view &string_table_name);
  template <typename It>
  std::pair<int, size_t> find_next_start_of_function(It begin, It end);
  std::vector<NamedSymbol> fake_static_symbols_factory();
  std::vector<NamedSymbol> static_symbols_factory();
  std::vector<ElfString> strings_factory();
  std::vector<char> get_next_string(const NamedSection &string_section);
  bool _is_valid_string(const std::vector<char> &s);

private:
  mutable std::ifstream _file;
  std::string _file_name;
  ElfHeader _header;
  std::vector<NamedSection> _sections;
  std::vector<NamedSymbol> _static_symbols;
  std::vector<ElfString> _strings;

private:
  static constexpr std::string_view start_of_function_instruction = "endbr64";
  static constexpr std::string_view code_section_name = ".text";
  static constexpr std::string_view static_symbol_section_name = ".symtab";
  static constexpr std::string_view static_symbol_name_section_name = ".strtab";
  static constexpr std::string_view relocation_plt_symbol_info_section_name =
      ".rela.plt";
  static constexpr std::string_view relocation_plt_section_name = ".plt.sec";
};
