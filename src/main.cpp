#include "dependency.hpp"
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

void recursive_function_chain(const DependencyMap &dependency_map,
                              const Function &function,
                              std::vector<Function> &out) {
  if (!dependency_map.has_function_dependency(function))
    return;

  const auto dependencies = dependency_map.get_function_dependency(function);

  for (const auto &dependency : dependencies) {
    bool should_skip = false;
    for (const auto& already_popped : out) {
      if (already_popped.address == dependency.address) should_skip = true;
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

int main(int argc, char *argv[]) {

  const auto [input_file, output_file] = parse_args(argc, argv);
  std::cout << input_file << " " << output_file << std::endl;

  try {
    ElfReader reader{input_file};
    const auto dependency_map = reader.get_all_dependencies();
    const auto start = reader.get_function("_start");
    const auto dependency_chain = get_function_chain(dependency_map, start);
    for (const auto &dependency : dependency_chain) {
      std::cout << dependency.name << std::endl;
    }
  } catch (const CriticalException &exception) {
    std::cout << exception.get() << std::endl;
  }

  return 0;
}
