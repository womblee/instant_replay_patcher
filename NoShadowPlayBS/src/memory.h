#pragma once

#include <vector>
#include <string>
#include <cstdint>
#include <windows.h>

std::vector<DWORD> get_processes_by_name(const std::wstring& process_name);
bool is_module_loaded(DWORD process_id, const std::wstring& module_name);
uintptr_t get_remote_module_base_address(HANDLE h_process, const wchar_t* module_name);
uintptr_t get_exported_function_address(HANDLE h_process, uintptr_t module_base, const wchar_t* module_name, const char* function_name);
uintptr_t allocate_memory_near_address(HANDLE process, uintptr_t desired_address, SIZE_T size,
DWORD protection = PAGE_EXECUTE_READWRITE, SIZE_T range = 0x20000000 - 0x2000);
bool assemble_jump_near_instruction(uint8_t* buffer, uintptr_t source_address, uintptr_t target_address);
bool write_memory(HANDLE h_process, uintptr_t address, const void* buffer, SIZE_T size);
bool write_memory_with_protection(HANDLE h_process, uintptr_t address, const void* buffer, SIZE_T size);
bool write_memory_with_protection_dynamic(HANDLE h_process, uintptr_t address, const std::vector<uint8_t>& buffer);