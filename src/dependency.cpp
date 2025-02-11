#include "dependency.hpp"

void DependencyMap::add_function_dependency(const Function &dependent,
                                            const Function &dependency) {
  _function_dependency_map[dependent].push_back(dependency);
}

void DependencyMap::add_relative_dependency(const Function &dependent,
                                            Address dependency) {
  _non_function_dependency_map[dependent].push_back(dependency);
}

auto DependencyMap::begin() const { return _function_dependency_map.begin(); }
auto DependencyMap::end() const { return _function_dependency_map.end(); }
DependencyMap::FunctionDependencies DependencyMap::get_function_dependency(const Dependent &dependent) const {
  return _function_dependency_map.at(dependent);
}
DependencyMap::NonFunctionDependencies DependencyMap::get_non_function_dependency(const Dependent &dependent) const {
  return _non_function_dependency_map.at(dependent);
}
bool DependencyMap::has_function_dependency(const Dependent &dependent) const {
  return _function_dependency_map.contains(dependent);
}
bool DependencyMap::has_non_function_dependency(const Dependent &dependent) const {
  return _non_function_dependency_map.contains(dependent);
}
