#include "memory.h"
#include "utils.h"
#include <tlhelp32.h>

std::vector<DWORD> get_processes_by_name(const std::wstring& process_name)
{
    std::vector<DWORD> process_ids;
    HANDLE h_process_snap;
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    h_process_snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (h_process_snap == INVALID_HANDLE_VALUE)
        return process_ids;

    if (!Process32First(h_process_snap, &pe32))
    {
        CloseHandle(h_process_snap);
        return process_ids;
    }

    std::wstring target_name = to_lower(process_name);
    do
    {
        if (to_lower(pe32.szExeFile) == target_name)
            process_ids.push_back(pe32.th32ProcessID);
    } while (Process32Next(h_process_snap, &pe32));

    CloseHandle(h_process_snap);
    return process_ids;
}

bool is_module_loaded(DWORD process_id, const std::wstring& module_name)
{
    HANDLE h_module_snap = INVALID_HANDLE_VALUE;
    MODULEENTRY32 me32;
    me32.dwSize = sizeof(MODULEENTRY32);

    h_module_snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, process_id);
    if (h_module_snap == INVALID_HANDLE_VALUE)
        return false;

    if (!Module32First(h_module_snap, &me32))
    {
        CloseHandle(h_module_snap);
        return false;
    }

    std::wstring target_module_name = to_lower(module_name);

    do
    {
        if (to_lower(me32.szModule) == target_module_name || to_lower(me32.szExePath) == target_module_name)
        {
            CloseHandle(h_module_snap);
            return true;
        }
    } while (Module32Next(h_module_snap, &me32));

    CloseHandle(h_module_snap);
    return false;
}

uintptr_t get_remote_module_base_address(HANDLE h_process, const wchar_t* module_name)
{
    HANDLE h_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetProcessId(h_process));
    if (h_snapshot == INVALID_HANDLE_VALUE) return 0;

    MODULEENTRY32 me;
    me.dwSize = sizeof(MODULEENTRY32);
    uintptr_t module_base = 0;
    if (Module32First(h_snapshot, &me))
    {
        do
        {
            if (_wcsicmp(me.szModule, module_name) == 0) {
                module_base = (uintptr_t)me.modBaseAddr;
                break;
            }
        } while (Module32Next(h_snapshot, &me));
    }
    CloseHandle(h_snapshot);
    return module_base;
}

uintptr_t get_exported_function_address(HANDLE h_process, uintptr_t module_base, const wchar_t* module_name, const char* function_name) {
    // Load the specified module locally (will just increase reference count if already loaded) 
    // Only used to get a handle to the module
    HMODULE h_local_module = LoadLibrary(module_name);
    if (!h_local_module) return 0;

    // Get the address of the function in the local module
    FARPROC local_proc_address = GetProcAddress(h_local_module, function_name);
    if (!local_proc_address)
    {
        FreeLibrary(h_local_module);
        return 0;
    }

    // Calculate the offset of the function within the local module
    uintptr_t offset = (uintptr_t)local_proc_address - (uintptr_t)h_local_module;

    // Free the local module (decrease reference count)
    FreeLibrary(h_local_module);

    // TODO: Maybe refactor to only return the offset
    // Address of the function in the remote module
    return module_base + offset;
}

uintptr_t allocate_memory_near_address(HANDLE process, uintptr_t desired_address, SIZE_T size, DWORD protection, SIZE_T range) {
    /* Default/optional args:
    // DWORD protection     = PAGE_EXECUTE_READWRITE
    // SIZE_T range         = 0x20000000 - 0x2000
    */

    const SIZE_T step = 0x1000; // One page (4KB)
    uintptr_t base_address = desired_address - range;
    uintptr_t end_address = desired_address + range;

    for (uintptr_t address = base_address; address < end_address; address += step)
    {
        void* allocated_memory = VirtualAllocEx(
            process,
            reinterpret_cast<void*>(address),
            size,
            MEM_RESERVE | MEM_COMMIT,
            protection
        );

        if (allocated_memory != NULL)
            return reinterpret_cast<uintptr_t>(allocated_memory);
    }

    return NULL;
}

bool assemble_jump_near_instruction(uint8_t* buffer, uintptr_t source_address, uintptr_t target_address) {
    // TODO: Use dynamic byte array or force length of 5 bytes

    // Calculate the relative offset for the jump
    intptr_t jump_offset = target_address - (source_address + 5); // 5 is the size of the JMP instruction

    if (std::abs(jump_offset) > 0x7FFFFFFF) // Check if the offset is within 32-bit range
        return false;

    // Assemble the JMP instruction (E9 offset)
    buffer[0] = 0xE9; // JMP opcode
    *reinterpret_cast<int32_t*>(buffer + 1) = static_cast<int32_t>(jump_offset);

    return true;
}

bool write_memory(HANDLE h_process, uintptr_t address, const void* buffer, SIZE_T size) {
    SIZE_T written;
    return WriteProcessMemory(h_process, reinterpret_cast<void*>(address), buffer, size, &written) && written == size;
}

bool write_memory_with_protection(HANDLE h_process, uintptr_t address, const void* buffer, SIZE_T size) {
    DWORD old_protect;

    // Change memory protection to allow writing
    if (!VirtualProtectEx(h_process, reinterpret_cast<void*>(address), size, PAGE_EXECUTE_READWRITE, &old_protect))
        return false;

    bool success = write_memory(h_process, address, buffer, size);

    // Restore the original memory protection
    if (!VirtualProtectEx(h_process, reinterpret_cast<void*>(address), size, old_protect, &old_protect))
        return false;

    return success;
}

bool write_memory_with_protection_dynamic(HANDLE h_process, uintptr_t address, const std::vector<uint8_t>& buffer) {
    // TODO: Make overload for write_memory_with_protection
    DWORD old_protect;

    // Change memory protection to allow writing
    if (!VirtualProtectEx(h_process, reinterpret_cast<void*>(address), buffer.size(), PAGE_EXECUTE_READWRITE, &old_protect))
        return false;

    // Write the memory
    bool success = write_memory(h_process, address, buffer.data(), buffer.size());

    // Restore the original memory protection
    if (!VirtualProtectEx(h_process, reinterpret_cast<void*>(address), buffer.size(), old_protect, &old_protect))
        return false;

    return success;
}