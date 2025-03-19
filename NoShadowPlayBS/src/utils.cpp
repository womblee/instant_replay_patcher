#include "utils.h"

#include <algorithm>
#include <sstream>
#include <iomanip>
#include <conio.h>

std::wstring to_lower(const std::wstring& str)
{
    std::wstring result = str;
    std::transform(result.begin(), result.end(), result.begin(), ::towlower);
    return result;
}

std::string bytes_to_hex_string(const uint8_t* bytes, size_t size)
{
    std::ostringstream oss;
    for (size_t i = 0; i < size; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)bytes[i] << " ";
    }
    return oss.str();
}

std::string int_to_hex(uintptr_t value)
{
    std::stringstream stream;
    stream << std::hex << value;
    return stream.str();
}