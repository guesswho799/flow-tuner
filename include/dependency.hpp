#pragma once

#include "elf_header.hpp"
#include <cstdint>
#include <optional>
#include <unordered_map>

class DependencyMap {
public:
  using IsAbsolute = bool;
  using LineNumber = uint16_t;
  using Dependent = Function;
  using NonFunctionDependencies =
      std::vector<std::tuple<LineNumber, Address, IsAbsolute>>;
  using FunctionDependencies =
      std::vector<std::tuple<LineNumber, Function, IsAbsolute>>;

public:
  void add_function_dependency(const Function &dependent,
                               const Function &dependency,
                               LineNumber in_function_index, bool is_absolute);
  void add_function_dependency(const Function &dependent,
                               const Function &dependency);
  void add_non_function_dependency(const Function &dependent,
                                   Address dependency,
                                   LineNumber in_function_index,
                                   bool is_absolute);

public:
  auto begin() const;
  auto end() const;
  FunctionDependencies
  get_function_dependency(const Dependent &dependent) const;
  NonFunctionDependencies
  get_non_function_dependency(const Dependent &dependent) const;
  std::optional<std::pair<Function, IsAbsolute>>
  get_function_dependency(const Dependent &dependent,
                          LineNumber in_function_index) const;
  std::optional<std::pair<Address, IsAbsolute>>
  get_non_function_dependency(const Dependent &dependent,
                              LineNumber in_function_index) const;
  bool has_function_dependency(const Dependent &dependent) const;
  bool has_non_function_dependency(const Dependent &dependent) const;

private:
  std::unordered_map<Dependent, FunctionDependencies, FunctionHasher,
                     FunctionEquals>
      _function_dependency_map;
  std::unordered_map<Dependent, NonFunctionDependencies, FunctionHasher,
                     FunctionEquals>
      _non_function_dependency_map;
};
