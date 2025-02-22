#include "dependency.hpp"
#include "elf_header.hpp"
#include "elf_reader.hpp"
#include <cstdint>
#include <cstdlib>
#include <cxxopts.hpp>
#include <format>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <stdlib.h>
#include <string>
#include <utility>
#include <vector>

std::pair<std::string, std::string> parse_args(int argc, char *argv[]) {
  cxxopts::Options options("Cinker", "Cross links elf files");
  options.add_options()("i,input", "Input file name",
                        cxxopts::value<std::string>());
  options.add_options()("o,output", "Output file name",
                        cxxopts::value<std::string>()->default_value("a.out"));
  options.add_options()("h,help", "Print usage");

  cxxopts::ParseResult result;
  try {
    result = options.parse(argc, argv);
  } catch (...) {
    std::cout << options.help() << std::endl;
    std::exit(1);
  }
  if (result.count("help") or result.count("input") == 0) {
    std::cout << options.help() << std::endl;
    std::exit(1);
  }

  return std::make_pair(result["input"].as<std::string>(),
                        result["output"].as<std::string>());
}

void recursive_function_chain(const DependencyMap &dependency_map,
                              const Function &function,
                              std::vector<Function> &out) {
  if (!dependency_map.has_function_dependency(function))
    return;

  const auto dependencies = dependency_map.get_function_dependency(function);

  for (const auto &[_, dependency, __] : dependencies) {
    bool should_skip = false;
    for (const auto &already_popped : out) {
      if (already_popped.address == dependency.address)
        should_skip = true;
    }
    if (should_skip)
      continue;

    out.push_back(dependency);
    recursive_function_chain(dependency_map, dependency, out);
  }
}

std::vector<Function> get_function_chain(const DependencyMap &dependency_map,
                                         const Function &first_function) {
  std::vector<Function> dependencies;
  dependencies.push_back(first_function);

  recursive_function_chain(dependency_map, first_function, dependencies);
  return dependencies;
}

void create_output_file(const ElfReader &elf_reader, const std::string &input,
                        const std::string &output,
                        const std::vector<Function> &functions) {
  auto reader = std::ifstream(input);
  auto writer = std::ofstream(output, std::ios::out | std::ios::binary);
  if (!reader.is_open())
    throw std::runtime_error("binary open failed");
  if (!writer.is_open())
    throw std::runtime_error("output open failed");

  // overwrite entry address
  ElfHeader elf_header = elf_reader.get_header();
  elf_header.entry_point_address = functions[0].address;
  writer.write(reinterpret_cast<char *>(&elf_header), sizeof elf_header);

  // copy until text section
  const auto text = elf_reader.get_section(".text");
  const uint64_t text_section_offset = text.unloaded_offset - sizeof elf_header;
  std::vector<unsigned char> buffer(text_section_offset);
  reader.seekg(static_cast<long>(sizeof elf_header));
  reader.read(reinterpret_cast<char *>(buffer.data()), buffer.size());
  writer.write(reinterpret_cast<char *>(buffer.data()), buffer.size());
  buffer.clear();
  buffer.shrink_to_fit();

  // write new text section
  uint64_t new_text_section_size = 0;
  for (const auto &function : functions) {
    writer.write(reinterpret_cast<const char *>(function.opcodes.data()),
                 function.opcodes.size());
    new_text_section_size += function.opcodes.size();
  }
  const uint64_t missing_size = text.size - new_text_section_size;
  std::vector<unsigned char> zeros(missing_size);
  writer.write(reinterpret_cast<const char *>(zeros.data()), zeros.size());
  zeros.clear();
  zeros.shrink_to_fit();

  // copy after text section
  reader.seekg(0, std::ios::end);
  const auto file_size = reader.tellg();
  const auto after_text_section = text.unloaded_offset + text.size;
  buffer.resize(static_cast<uint64_t>(file_size) - after_text_section);
  reader.seekg(static_cast<long>(after_text_section));
  reader.read(reinterpret_cast<char *>(buffer.data()), buffer.size());
  writer.write(reinterpret_cast<char *>(buffer.data()), buffer.size());
}

void print_dependencies(const auto &dependency_chain,
                        const auto &dependency_map) {
  for (const auto &function : dependency_chain) {
    std::cout << function.name << ": ";
    if (dependency_map.has_function_dependency(function)) {
      const auto dependencies =
          dependency_map.get_function_dependency(function);
      for (const auto &[_, dependency, __] : dependencies) {
        std::cout << dependency.name << ", ";
      }
    }
    std::cout << std::endl;
  }
}

void print_text_section(const auto &dependency_chain, const auto &reader) {
  Disassembler disassembler;
  for (const auto &function : dependency_chain) {
    std::cout << "========================\n";
    std::cout << function.name << " " << std::hex << function.address
              << std::endl;
    std::cout << "========================\n";
    for (const auto &line : disassembler.disassemble(
             function.opcodes, function.address, reader.get_static_symbols(),
             reader.get_strings())) {
      std::cout << "0x" << std::hex << line.address << ": " << line.instruction
                << " " << line.arguments << std::endl;
    }
  }
}

int main(int argc, char *argv[]) {

  const auto [input_file, output_file] = parse_args(argc, argv);
  std::cout << input_file << " " << output_file << std::endl;

  try {
    ElfReader reader{input_file};
    const auto start = reader.get_function("_start");
    const auto dependency_map = reader.get_all_dependencies();
    auto dependency_chain = get_function_chain(dependency_map, start);
    reader.correct_addresses(dependency_map, dependency_chain);
    create_output_file(reader, input_file, output_file, dependency_chain);

    // print_dependencies(dependency_chain, dependency_map);
    // print_text_section(dependency_chain, reader);

  } catch (const std::exception &exception) {
    std::cout << "exception -> " << exception.what() << std::endl;
  }

  return 0;
}
