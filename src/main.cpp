#include "dependency.hpp"
#include "elf_reader.hpp"
#include <cstdlib>
#include <cxxopts.hpp>
#include <iostream>
#include <stdlib.h>
#include <string>
#include <utility>

std::pair<std::string, std::string> parse_args(int argc, char *argv[]) {
  cxxopts::ParseResult result;
  cxxopts::Options options("FlowTuner", "Tunes elf binaries");
  options.add_options()("i,input", "Input file name",
                        cxxopts::value<std::string>());
  options.add_options()("o,output", "Output file name",
                        cxxopts::value<std::string>()->default_value("a.out"));
  options.add_options()("h,help", "Print usage");

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
    auto dependency_chain = dependency_map.get_function_chain(start);
    reader.correct_addresses(dependency_map, dependency_chain);
    reader.create_output_file(output_file, dependency_chain,
                              reader.correct_plt(dependency_chain));

    // print_dependencies(dependency_chain, dependency_map);
    // print_text_section(dependency_chain, reader);

  } catch (const std::exception &exception) {
    std::cout << "exception -> " << exception.what() << std::endl;
  }

  return 0;
}
