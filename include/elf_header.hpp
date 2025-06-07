#pragma once
#include <bitset>
#include <cstddef>
#include <cstdint>
#include <unordered_map>
#include <vector>

struct ElfHeader {
  std::byte magic[4];
  std::byte bit_format;
  std::byte endianness;
  std::byte version;
  std::byte ABI[2];
  std::byte padding[7];
  uint16_t file_type;
  uint16_t instruction_set_architecture;
  uint32_t version2;
  uint64_t entry_point_address;
  uint64_t header_table_address;
  uint64_t section_table_address;
  std::byte flags[4];
  std::byte header_size[2];
  std::byte header_table_entry_size[2];
  std::byte header_table_entry_count[2];
  uint16_t section_table_entry_size;
  uint16_t section_table_entry_count;
  uint16_t section_table_name_index;
};

enum class SectionType : uint32_t {
  unused = 0,
  program_data,
  symbol_table,
  string_table,
  relocation_entried,
  symbol_hash_table,
  notes,
  bss,
  relocation_entries,
  reserved,
  dynamic_linker_symbol_table
  // ...
};

struct SectionHeader {
  uint32_t name_offset;
  SectionType type;
  uint64_t attributes;
  uint64_t loaded_virtual_address;
  uint64_t unloaded_offset;
  uint64_t size;
  uint32_t associated_section_index;
  uint32_t extra_information;
  uint64_t required_alinment;
  uint64_t entry_size;
};

struct NamedSection {
  std::string name;
  SectionType type;
  uint64_t attributes;
  uint64_t loaded_virtual_address;
  uint64_t unloaded_offset;
  uint64_t size;
  uint32_t associated_section_index;
  uint32_t extra_information;
  uint64_t required_alinment;
  uint64_t entry_size;
};

struct ElfSymbol {
  uint32_t name;
  uint8_t type;
  uint8_t visibility;
  uint16_t section_index;
  uint64_t value;
  uint64_t size;
};

enum class SymbolType : uint8_t {
  no_type = 0,
  data_object,
  function,
  section,
  file,
  reserved,
  local,
  global,
  weak
};

inline constexpr bool operator&(SymbolType x, SymbolType y) {
  return static_cast<int>(x) & static_cast<int>(y);
}

using Address = uint64_t;
struct NamedSymbol {
  std::string name;
  SymbolType type;
  uint16_t section_index;
  uint64_t value;
  uint64_t size;
};

struct Function {
  std::string name;
  uint64_t address;
  uint64_t size;
  std::vector<unsigned char> opcodes;
};

struct FunctionHasher {
  size_t operator()(const Function &f) const {
    return std::hash<std::string>{}(f.name);
  }
};
struct FunctionEquals {
  bool operator()(const Function &f1, const Function &f2) const {
    return f1.name == f2.name;
  }
};

struct ElfString {
  std::string value;
  uint64_t address;
};

struct ElfRelocation {
  uint64_t file_offset;
  uint32_t dont_know;
  uint32_t symbol_index;
  uint64_t function_address;
};

// key: jump from
// value: jump to
using IndirectCall = std::unordered_map<Address, Address>;

struct SwitchStatement {
  Address jump_from;
  Address jump_table;
  Function function;
};
