#pragma once

#include "elf_header.hpp"
#include <unordered_map>

class DependencyMap {
public:
  using Dependent = Function;
  using NonFunctionDependencies = std::vector<Address>;
  using FunctionDependencies = std::vector<Function>;

public:
  void add_function_dependency(const Function &dependent,
                               const Function &dependency);
  void add_relative_dependency(const Function &dependent, Address dependency);

public:
  auto begin() const;
  auto end() const;
  FunctionDependencies
  get_function_dependency(const Dependent &dependent) const;
  NonFunctionDependencies
  get_non_function_dependency(const Dependent &dependent) const;
  bool
  has_function_dependency(const Dependent &dependent) const;
  bool
  has_non_function_dependency(const Dependent &dependent) const;

private:
  std::unordered_map<Dependent, FunctionDependencies, FunctionHasher, FunctionEquals>
      _function_dependency_map;
  std::unordered_map<Dependent, NonFunctionDependencies, FunctionHasher, FunctionEquals>
      _non_function_dependency_map;
};
