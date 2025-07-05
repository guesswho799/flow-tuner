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
  std::vector<unsigned char>
  get_section_data(const std::string_view &section_name) const;
  NamedSection get_section(std::size_t section_index) const;
  size_t get_section_index(const std::string_view &section_name) const;
  std::vector<NamedSymbol> get_non_file_symbols() const;
  NamedSymbol get_symbol(std::string name) const;
  Function get_function(std::string name) const;
  std::vector<Function> get_functions() const;
  std::vector<NamedSymbol>
  get_symbol_dependencies(const Function &function) const;
  DependencyMap get_all_dependencies();
  void correct_addresses(const DependencyMap &dependency_map,
                         std::vector<Function> &dependency_chain) const;
  std::vector<ElfRelocation>
  correct_plt(const std::vector<Function> &dependency_chain) const;
  std::vector<ElfSymbol>
  correct_symtab(const std::vector<Function> &dependency_chain) const;
  std::vector<Address>
  correct_init_array(const std::vector<Function> &dependency_chain) const;
  std::vector<Address>
  correct_fini_array(const std::vector<Function> &dependency_chain) const;
  std::vector<unsigned char>
  correct_rodata(const std::vector<Function> &dependency_chain) const;
  std::vector<Function> get_rela_functions();
  std::vector<Function>
  get_functions_from_array_section(const std::string_view &section_name);

private:
  std::vector<Address>
  _correct_array_section(const std::vector<Function> &dependency_chain,
                         const std::string_view &section_name) const;

public:
  void create_output_file(const std::string &output_file_name,
                          const std::vector<Function> &functions,
                          std::vector<ElfRelocation> &&plt,
                          std::vector<ElfSymbol> &&symtab,
                          std::vector<Address> &&new_init_array_section,
                          std::vector<Address> &&new_fini_array_section,
                          std::vector<unsigned char> &&new_rodata_section);

  // factories
private:
  ElfHeader header_factory();
  std::vector<NamedSection> sections_factory();
  std::vector<NamedSymbol>
  symbols_factory(const std::string_view &section_name,
                  const std::string_view &string_table_name);
  template <typename It>
  std::pair<int, size_t> find_next_start_of_function(It begin, It end);
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
  static constexpr std::string_view plt_section_name = ".plt";
  static constexpr std::string_view init_section_name = ".init";
  static constexpr std::string_view fini_section_name = ".fini";
  static constexpr std::string_view init_array_section_name = ".init_array";
  static constexpr std::string_view fini_array_section_name = ".fini_array";
  static constexpr std::string_view rodata_section_name = ".rodata";
};
