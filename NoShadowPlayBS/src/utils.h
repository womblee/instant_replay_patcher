#pragma once

#include <string>
#include <cstdint>

std::wstring to_lower(const std::wstring& str);
std::string bytes_to_hex_string(const uint8_t* bytes, size_t size);
std::string int_to_hex(uintptr_t value);