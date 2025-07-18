#pragma once
#include <cstring>
#include <string_view>


template <std::size_t n> struct FixedString {
  constexpr FixedString(const char (&str)[n + 1]) noexcept {
    std::size_t i = 0;
    for (char const c : str) {
      _data[i++] = c;
    }
    _data[n] = 0;
  }

  constexpr std::string_view view() const { return std::string_view{_data, n}; }

  char _data[n + 1];
};

template <std::size_t n> FixedString(char const (&)[n]) -> FixedString<n - 1>;
