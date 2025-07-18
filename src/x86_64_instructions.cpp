#include "x86_64_instructions.hpp"
#include <vector>
#include <cstdint>


namespace X86_64Instructions {

std::vector<unsigned char> number_to_opcodes(int64_t number) {
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

bool is_jump(const std::string &instruction) {
  std::vector<std::string_view> jump_values{"jmp", "jb", "je",  "jne",
                                            "jg",  "jl", "jge", "jle"};
  return std::find(jump_values.begin(), jump_values.end(), instruction) !=
         jump_values.end();
}
}; // namespace SupportedX86_64Instructions
