#include "elf_header.hpp"
#include "elf_reader.hpp"
#include "status.hpp"
#include <cstdlib>
#include <cxxopts.hpp>
#include <iostream>
#include <utility>

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

void print_dependencies(const Dependent &dependent,
                        const Dependencies &dependencies) {
  std::cout << dependent.name << ": ";
  for (const auto &dependency : dependencies.first) {
    std::cout << dependency.name << ", ";
  }
  for (const auto &dependency : dependencies.second) {
    std::cout << std::hex << dependency << ", ";
  }
  std::cout << std::endl;
}

int main(int argc, char *argv[]) {

  const auto [input_file, output_file] = parse_args(argc, argv);
  std::cout << input_file << " " << output_file << std::endl;

  try {
    ElfReader reader{input_file};
    for (const auto &[dependent, dependencies] :
         reader.get_all_dependencies()) {
      print_dependencies(dependent, dependencies);
    }
  } catch (const CriticalException &exception) {
    std::cout << exception.get() << std::endl;
  }

  return 0;
}
