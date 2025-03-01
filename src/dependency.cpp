#include "dependency.hpp"
#include <utility>

void DependencyMap::add_function_dependency(const Function &dependent,
                                            const Function &dependency,
                                            LineNumber in_function_index,
                                            bool is_absolute) {
  _function_dependency_map[dependent].emplace_back(in_function_index,
                                                   dependency, is_absolute);
}

void DependencyMap::add_function_dependency(const Function &dependent,
                                            const Function &dependency) {
  constexpr int dont_correct_callsite = 9999;
  _function_dependency_map[dependent].emplace_back(dont_correct_callsite,
                                                   dependency, false);
}

void DependencyMap::add_non_function_dependency(const Function &dependent,
                                                Address dependency,
                                                LineNumber in_function_index,
                                                bool is_absolute) {
  _non_function_dependency_map[dependent].emplace_back(in_function_index,
                                                       dependency, is_absolute);
}

auto DependencyMap::begin() const { return _function_dependency_map.begin(); }
auto DependencyMap::end() const { return _function_dependency_map.end(); }

DependencyMap::FunctionDependencies
DependencyMap::get_function_dependency(const Dependent &dependent) const {
  return _function_dependency_map.at(dependent);
}

DependencyMap::NonFunctionDependencies
DependencyMap::get_non_function_dependency(const Dependent &dependent) const {
  return _non_function_dependency_map.at(dependent);
}

std::optional<std::pair<Function, DependencyMap::IsAbsolute>>
DependencyMap::get_function_dependency(
    const DependencyMap::Dependent &dependent,
    DependencyMap::LineNumber in_function_index) const {
  if (!has_function_dependency(dependent))
    return {};
  const auto dependencies = _function_dependency_map.at(dependent);

  for (const auto &[index, dependency, is_absolute] : dependencies) {
    if (index == in_function_index)
      return std::make_pair(dependency, is_absolute);
  }

  return {};
}

std::optional<std::pair<Address, DependencyMap::IsAbsolute>>
DependencyMap::get_non_function_dependency(
    const Dependent &dependent,
    DependencyMap::LineNumber in_function_index) const {
  if (!has_non_function_dependency(dependent))
    return {};
  const auto dependencies = _non_function_dependency_map.at(dependent);

  for (const auto &[index, dependency, is_absolute] : dependencies) {
    if (index == in_function_index)
      return std::make_pair(dependency, is_absolute);
  }

  return {};
}

bool DependencyMap::has_function_dependency(const Dependent &dependent) const {
  return _function_dependency_map.contains(dependent);
}

bool DependencyMap::has_non_function_dependency(
    const Dependent &dependent) const {
  return _non_function_dependency_map.contains(dependent);
}

void DependencyMap::_recursive_function_chain(const Function &function,
                                              std::vector<Function> &out) const{
  if (!has_function_dependency(function))
    return;

  const auto dependencies = get_function_dependency(function);

  for (const auto &[_, dependency, __] : dependencies) {
    bool should_skip = false;
    for (const auto &already_popped : out) {
      if (already_popped.address == dependency.address)
        should_skip = true;
    }
    if (should_skip)
      continue;

    out.push_back(dependency);
    _recursive_function_chain(dependency, out);
  }
}

std::vector<Function>
DependencyMap::get_function_chain(const Function &first_function) const{
  std::vector<Function> dependencies;
  dependencies.push_back(first_function);

  _recursive_function_chain(first_function, dependencies);
  return dependencies;
}
