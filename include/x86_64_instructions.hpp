#pragma once

#include "fixed_string.hpp"
#include <algorithm>
#include <cstdint>
#include <stdexcept>
#include <vector>

namespace X86_64Instructions {

std::vector<unsigned char> number_to_opcodes(int64_t number);
bool is_jump(const std::string &instruction);

template <typename T>
void overwrite_end(T &buffer_iterator, int64_t relative_address,
                   uint16_t size) {
  const int amount_to_skip = size - 4;
  buffer_iterator += amount_to_skip;
  for (const auto &opcode : number_to_opcodes(relative_address)) {
    *buffer_iterator = opcode;
    buffer_iterator++;
  }
}

template <typename T>
void overwrite_jmp(T &buffer_iterator, int64_t relative_address,
                   uint16_t size) {
  const int amount_to_skip = *buffer_iterator == 0x0f ? 2 : 1;
  buffer_iterator += amount_to_skip;
  for (const auto &opcode : number_to_opcodes(relative_address)) {
    *buffer_iterator = opcode;
    buffer_iterator++;
  }
  const auto bytes_left = size - (amount_to_skip + 4);
  buffer_iterator += bytes_left;
}

template <typename T>
void overwrite_cmp(T &buffer_iterator, const std::string &argument,
                   int64_t relative_address, uint16_t size) {
  const int amount_to_skip =
      argument.find("qword") != std::string::npos ? 3 : 2;
  buffer_iterator += amount_to_skip;
  for (const auto &opcode : number_to_opcodes(relative_address)) {
    *buffer_iterator = opcode;
    buffer_iterator++;
  }
  const auto bytes_left = size - (amount_to_skip + 4);
  buffer_iterator += bytes_left;
}

template <typename T>
void overwrite_mov(T &buffer_iterator, int64_t relative_address,
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
  for (const auto &opcode : number_to_opcodes(relative_address)) {
    *buffer_iterator = opcode;
    buffer_iterator++;
  }
  const auto bytes_left = size - (amount_to_skip + 4);
  buffer_iterator += bytes_left;
}

template <typename T>
void overwrite_skip_two(T &buffer_iterator, int64_t relative_address,
                        uint16_t size) {
  buffer_iterator += 2;
  for (const auto &opcode : number_to_opcodes(relative_address)) {
    *buffer_iterator = opcode;
    buffer_iterator++;
  }
  const auto bytes_left = size - 6;
  buffer_iterator += bytes_left;
}

template <FixedString instruction> constexpr auto support_instruction() {
  return [&](const std::string &full_instruction) {
    return full_instruction.starts_with(instruction.view());
  };
}

constexpr auto is_call = support_instruction<"call">();
constexpr auto is_cmov = support_instruction<"cmov">();
constexpr auto is_load = support_instruction<"lea">();
constexpr auto is_inc = support_instruction<"inc">();
constexpr auto is_dec = support_instruction<"dec">();
constexpr auto is_ucomisd = support_instruction<"ucomisd">();
constexpr auto is_andpd = support_instruction<"andpd">();
constexpr auto is_pand = support_instruction<"pand">();
constexpr auto is_fld = support_instruction<"fld">();
constexpr auto is_imul = support_instruction<"imul">();
constexpr auto is_xadd = support_instruction<"xadd">();
constexpr auto is_sub = support_instruction<"sub">();
constexpr auto is_divss = support_instruction<"divss">();
constexpr auto is_push = support_instruction<"push">();
constexpr auto is_movq = support_instruction<"movq">();
constexpr auto is_movups = support_instruction<"movups">();
constexpr auto is_movaps = support_instruction<"movaps">();
constexpr auto is_vmovdqa = support_instruction<"vmovdqa">();
constexpr auto is_movdqa = support_instruction<"movdqa">();
constexpr auto is_movzx = support_instruction<"movzx">();
constexpr auto is_cmpxchg = support_instruction<"cmpxchg">();
constexpr auto is_test = support_instruction<"test">();
constexpr auto is_and = support_instruction<"and">();
constexpr auto is_cmp = support_instruction<"cmp">();
constexpr auto is_xchg = support_instruction<"xchg">();
constexpr auto is_add = support_instruction<"add">();
constexpr auto is_mov = support_instruction<"mov">();
constexpr auto is_or = support_instruction<"or">();

template <typename T>
static void overwrite_instruction(const std::string &operation,
                                  T &buffer_iterator,
                                  const std::string &argument,
                                  int64_t relative_address, uint16_t size) {

  if (is_call(operation) or is_cmov(operation) or is_load(operation) or
      is_inc(operation) or is_dec(operation) or is_ucomisd(operation) or
      is_andpd(operation) or is_pand(operation) or is_fld(operation) or
      is_imul(operation) or is_xadd(operation) or is_sub(operation) or
      is_divss(operation) or is_push(operation) or is_movq(operation) or
      is_movups(operation) or is_movaps(operation) or is_vmovdqa(operation) or
      is_movdqa(operation) or is_movzx(operation) or is_cmpxchg(operation)) {
    overwrite_end(buffer_iterator, relative_address, size);

  } else if (is_test(operation) or is_and(operation)) {
    overwrite_skip_two(buffer_iterator, relative_address, size);
  } else if (is_jump(operation)) {
    overwrite_jmp(buffer_iterator, relative_address, size);
  } else if (is_cmp(operation) or is_xchg(operation) or is_add(operation)) {
    overwrite_cmp(buffer_iterator, argument, relative_address, size);
  } else if (is_mov(operation) or is_or(operation)) {
    overwrite_mov(buffer_iterator, relative_address, size);
  } else {
    throw std::runtime_error("unsupported instruction: " + operation + " " +
                             argument);
  }
}
}; // namespace X86_64Instructions
