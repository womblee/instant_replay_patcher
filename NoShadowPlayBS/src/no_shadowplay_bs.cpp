#include "utils.h"
#include "memory.h"
#include "config.h"
#include "font.h"
#include <ImGui/imgui.h>
#include <ImGui/imgui_impl_dx11.h>
#include <ImGui/imgui_impl_win32.h>
#include <d3d11.h>
#include <tchar.h>
#include <iostream>
#include <array>
#include <string>
#include <thread>
#include <chrono>
#include <Windows.h>
#include <ctime>

#pragma comment(lib, "d3d11.lib")

// Copyright information
#define COPYRIGHT_INFO "by nloginov, credit furyzenblade"
#define VERSION "1.1.0"

// Forward declarations
extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);
bool create_device_d3d(HWND hwnd, ID3D11Device** device, ID3D11DeviceContext** device_context, IDXGISwapChain** swap_chain);
void cleanup_device_d3d(ID3D11Device* device, ID3D11DeviceContext* device_context, IDXGISwapChain* swap_chain);
LRESULT WINAPI wnd_proc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam);

// Global variables
static ID3D11Device* g_device = NULL;
static ID3D11DeviceContext* g_device_context = NULL;
static IDXGISwapChain* g_swap_chain = NULL;
static ID3D11RenderTargetView* g_main_render_target_view = NULL;

// Original bytes storage for patch restoration
struct original_bytes {
    std::vector<uint8_t> window_display_affinity_bytes;
    std::vector<uint8_t> module32_first_w_bytes;
    uintptr_t wda_address = 0;
    uintptr_t m32fw_address = 0;
};

// Patch status tracking with improved logging
struct patch_status {
    bool wait_for_process = true;
    bool is_running = true;
    bool is_patched = false;
    bool startup_enabled = false;
    bool auto_close = false;
    bool undo_available = false;
    DWORD target_process_id = 0;
    std::string status_message = "Waiting for nvcontainer.exe...";
    std::string detailed_log;
    original_bytes orig_bytes;

    // Log levels
    enum LogLevel {
        INFO,
        WARNING,
        ERR,
        SUCCESS
    };
};

// Function to set startup registry
bool set_startup(bool enable) {
    HKEY h_key;
    const char* key_path = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";

    if (RegOpenKeyExA(HKEY_CURRENT_USER, key_path, 0, KEY_SET_VALUE, &h_key) != ERROR_SUCCESS)
        return false;

    char exe_path[MAX_PATH];
    GetModuleFileNameA(NULL, exe_path, MAX_PATH);

    if (enable) {
        std::string command = std::string(exe_path);
        RegSetValueExA(h_key, "NvPatcher", 0, REG_SZ, (BYTE*)command.c_str(), command.length() + 1);
    }
    else
        RegDeleteValueA(h_key, "NvPatcher");

    RegCloseKey(h_key);
    return true;
}

// Check if startup is enabled
bool is_startup_enabled() {
    HKEY h_key;
    const char* key_path = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";

    if (RegOpenKeyExA(HKEY_CURRENT_USER, key_path, 0, KEY_READ, &h_key) != ERROR_SUCCESS)
        return false;

    char value[MAX_PATH] = { 0 };
    DWORD value_size = sizeof(value);
    DWORD value_type;

    bool exists = RegQueryValueExA(h_key, "NvPatcher", 0, &value_type, (BYTE*)value, &value_size) == ERROR_SUCCESS;
    RegCloseKey(h_key);

    return exists;
}

// Get current timestamp for logs
std::string get_timestamp() {
    auto now = std::chrono::system_clock::now();
    std::time_t time = std::chrono::system_clock::to_time_t(now);

    char buffer[80];
    struct tm timeinfo;
    localtime_s(&timeinfo, &time);
    strftime(buffer, sizeof(buffer), "%H:%M:%S", &timeinfo);

    return std::string(buffer);
}

// Improved add_log function with log levels
void add_log(patch_status& status, const std::string& message, patch_status::LogLevel level = patch_status::LogLevel::INFO) {
    std::string prefix;

    switch (level) {
    case patch_status::LogLevel::INFO:
        prefix = "[INFO]";
        break;
    case patch_status::LogLevel::WARNING:
        prefix = "[WARNING]";
        break;
    case patch_status::LogLevel::ERR:
        prefix = "[ERROR]";
        break;
    case patch_status::LogLevel::SUCCESS:
        prefix = "[SUCCESS]";
        break;
    }

    std::string timestamp = get_timestamp();
    std::string formatted_message = "[" + timestamp + "] " + prefix + " " + message;
    status.detailed_log += formatted_message + "\n";
    status.status_message = message;
}

// Function to check if a process has already been patched
bool is_process_patched(HANDLE h_process, uintptr_t target_address, patch_status& status) {
    std::vector<uint8_t> current_bytes(7, 0);
    SIZE_T bytes_read;

    if (!ReadProcessMemory(h_process, (LPCVOID)target_address, current_bytes.data(), current_bytes.size(), &bytes_read)) {
        add_log(status, "Failed to read memory for patch check", patch_status::LogLevel::ERR);
        return false;
    }

    // Check if the first byte is a JMP instruction (0xE9)
    return current_bytes[0] == 0xE9;
}

// Function to back up original bytes before patching
bool backup_original_bytes(HANDLE h_process, uintptr_t target_address, std::vector<uint8_t>& backup, size_t size) {
    backup.resize(size, 0);
    SIZE_T bytes_read;

    return ReadProcessMemory(h_process, (LPCVOID)target_address, backup.data(), size, &bytes_read) && bytes_read == size;
}

// Function to restore original bytes (undo patch)
bool restore_original_bytes(HANDLE h_process, uintptr_t target_address, const std::vector<uint8_t>& original_bytes) {
    if (original_bytes.empty() || target_address == 0) {
        return false;
    }

    return write_memory_with_protection(h_process, target_address, original_bytes.data(), original_bytes.size());
}

int patch_get_window_display_affinity(HANDLE h_process, patch_status& status) {
    // Get USER32.dll base address
    uintptr_t remote_user32_base = get_remote_module_base_address(h_process, L"USER32.dll");
    if (!remote_user32_base) {
        add_log(status, "Could not get USER32.dll base address", patch_status::LogLevel::ERR);
        return 1;
    }

    add_log(status, "Found USER32.dll base address: 0x" + int_to_hex(remote_user32_base), patch_status::LogLevel::INFO);

    // Get the address of the target function
    uintptr_t remote_target_address = get_exported_function_address(h_process, remote_user32_base, L"USER32.dll", "GetWindowDisplayAffinity");
    if (!remote_target_address) {
        add_log(status, "Could not get remote address of GetWindowDisplayAffinity", patch_status::LogLevel::ERR);
        return 1;
    }

    add_log(status, "Found address of GetWindowDisplayAffinity: 0x" + int_to_hex(remote_target_address), patch_status::LogLevel::INFO);

    // Store the address for later undo
    status.orig_bytes.wda_address = remote_target_address;

    // Check if already patched
    if (is_process_patched(h_process, remote_target_address, status)) {
        add_log(status, "GetWindowDisplayAffinity already appears to be patched", patch_status::LogLevel::WARNING);
        return 0; // Consider this a success, it's already patched
    }

    // Backup original bytes before patching
    if (!backup_original_bytes(h_process, remote_target_address, status.orig_bytes.window_display_affinity_bytes, 6)) {
        add_log(status, "Failed to backup original bytes before patching", patch_status::LogLevel::ERR);
        return 1;
    }

    // Allocate memory in the target process
    uintptr_t allocated_memory = allocate_memory_near_address(h_process, remote_target_address, 0x1000);
    if (!allocated_memory) {
        add_log(status, "Could not allocate memory near target address", patch_status::LogLevel::ERR);
        return 1;
    }

    add_log(status, "Allocated 1kb of memory at: 0x" + int_to_hex(allocated_memory), patch_status::LogLevel::INFO);

    // Place payload at new memory location
    if (!write_memory_with_protection_dynamic(h_process, allocated_memory,
        {
            0x48, 0x31, 0xC0,   // xor rax, rax
            0xC3                // ret
        })
        ) {
        add_log(status, "Could not write payload to allocated memory region", patch_status::LogLevel::ERR);
        return 1;
    }

    add_log(status, "Payload written successfully to allocated memory region", patch_status::LogLevel::INFO);

    // Assemble the JMP instruction
    std::array<uint8_t, 5> jmp_instruction_bytes;
    if (!assemble_jump_near_instruction(jmp_instruction_bytes.data(), remote_target_address, allocated_memory)) {
        add_log(status, "Allocated memory address is too far to assemble a jump near to", patch_status::LogLevel::ERR);
        return 1;
    }

    add_log(status, "Assembled jump instruction: " + bytes_to_hex_string(jmp_instruction_bytes.data(), jmp_instruction_bytes.size()), patch_status::LogLevel::INFO);

    // Write the JMP instruction (plus 1 nop for the left over byte)
    std::array<uint8_t, 6> buffer;
    std::copy(jmp_instruction_bytes.begin(), jmp_instruction_bytes.end(), buffer.begin());
    buffer[5] = 0x90; // NOP instruction

    if (!write_memory_with_protection(h_process, remote_target_address, buffer.data(), buffer.size())) {
        add_log(status, "Could not write jump instruction and NOP to target address", patch_status::LogLevel::ERR);
        return 1;
    }
    add_log(status, "Placed hook at USER32.GetWindowDisplayAffinity", patch_status::LogLevel::SUCCESS);

    return 0;
}

int patch_kernel32_module32_first_w(HANDLE h_process, patch_status& status) {
    // Get KERNEL32.DLL base address
    uintptr_t module_base_address = get_remote_module_base_address(h_process, L"KERNEL32.DLL");
    if (!module_base_address) {
        add_log(status, "Could not get KERNEL32.DLL base address", patch_status::LogLevel::ERR);
        return 1;
    }

    add_log(status, "Found KERNEL32.DLL base address: 0x" + int_to_hex(module_base_address), patch_status::LogLevel::INFO);

    // Get the address of the target function
    uintptr_t function_address = get_exported_function_address(h_process, module_base_address, L"KERNEL32.DLL", "Module32FirstW");
    if (!function_address) {
        add_log(status, "Could not get remote address of Module32FirstW", patch_status::LogLevel::ERR);
        return 1;
    }

    add_log(status, "Found address of Module32FirstW: 0x" + int_to_hex(function_address), patch_status::LogLevel::INFO);

    // Store the address for later undo
    status.orig_bytes.m32fw_address = function_address;

    // Check if already patched
    if (is_process_patched(h_process, function_address, status)) {
        add_log(status, "Module32FirstW already appears to be patched", patch_status::LogLevel::WARNING);
        return 0; // Consider this a success, it's already patched
    }

    // Backup original bytes before patching
    if (!backup_original_bytes(h_process, function_address, status.orig_bytes.module32_first_w_bytes, 7)) {
        add_log(status, "Failed to backup original bytes before patching", patch_status::LogLevel::ERR);
        return 1;
    }

    // Allocate memory in the target process
    uintptr_t allocated_memory = allocate_memory_near_address(h_process, function_address, 0x1000);
    if (!allocated_memory) {
        add_log(status, "Could not allocate memory near target address", patch_status::LogLevel::ERR);
        return 1;
    }

    add_log(status, "Allocated 1kb of memory at: 0x" + int_to_hex(allocated_memory), patch_status::LogLevel::INFO);

    // Place payload at new memory location
    if (!write_memory_with_protection_dynamic(h_process, allocated_memory,
        {
            0x48, 0x31, 0xC0,   // xor rax, rax
            0xC3                // ret
        })
        ) {
        add_log(status, "Could not write payload to allocated memory region", patch_status::LogLevel::ERR);
        return 1;
    }

    add_log(status, "Payload written successfully to allocated memory region", patch_status::LogLevel::INFO);

    // Assemble the JMP instruction
    std::array<uint8_t, 5> jmp_instruction_bytes;
    if (!assemble_jump_near_instruction(jmp_instruction_bytes.data(), function_address, allocated_memory)) {
        add_log(status, "Allocated memory address is too far to assemble a jump near to", patch_status::LogLevel::ERR);
        return 1;
    }

    add_log(status, "Assembled jump instruction: " + bytes_to_hex_string(jmp_instruction_bytes.data(), jmp_instruction_bytes.size()), patch_status::LogLevel::INFO);

    // Write the JMP instruction (plus 2 nop's for the left over bytes)
    std::array<uint8_t, 7> buffer;
    std::copy(jmp_instruction_bytes.begin(), jmp_instruction_bytes.end(), buffer.begin());
    buffer[5] = 0x90; // NOP instruction
    buffer[6] = 0x90; // NOP instruction

    if (!write_memory_with_protection(h_process, function_address, buffer.data(), buffer.size())) {
        add_log(status, "Could not write jump instruction and NOP to target address", patch_status::LogLevel::ERR);
        return 1;
    }

    add_log(status, "Placed hook at KERNEL32.Module32FirstW", patch_status::LogLevel::SUCCESS);

    return 0;
}

// Function to undo patches
bool undo_patches(patch_status& status) {
    if (!status.undo_available || status.target_process_id == 0) {
        add_log(status, "No patches available to undo", patch_status::LogLevel::WARNING);
        return false;
    }

    HANDLE h_process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, status.target_process_id);
    if (!h_process) {
        add_log(status, "Could not open process for undo operation", patch_status::LogLevel::ERR);
        return false;
    }

    bool success = true;

    // Restore GetWindowDisplayAffinity
    if (status.orig_bytes.wda_address != 0 && !status.orig_bytes.window_display_affinity_bytes.empty()) {
        if (!restore_original_bytes(h_process, status.orig_bytes.wda_address, status.orig_bytes.window_display_affinity_bytes)) {
            add_log(status, "Failed to restore original bytes for GetWindowDisplayAffinity", patch_status::LogLevel::ERR);
            success = false;
        }
        else {
            add_log(status, "Successfully restored original bytes for GetWindowDisplayAffinity", patch_status::LogLevel::SUCCESS);
        }
    }

    // Restore Module32FirstW
    if (status.orig_bytes.m32fw_address != 0 && !status.orig_bytes.module32_first_w_bytes.empty()) {
        if (!restore_original_bytes(h_process, status.orig_bytes.m32fw_address, status.orig_bytes.module32_first_w_bytes)) {
            add_log(status, "Failed to restore original bytes for Module32FirstW", patch_status::LogLevel::ERR);
            success = false;
        }
        else {
            add_log(status, "Successfully restored original bytes for Module32FirstW", patch_status::LogLevel::SUCCESS);
        }
    }

    CloseHandle(h_process);

    if (success) {
        status.undo_available = false;
        status.is_patched = false;
        add_log(status, "All patches successfully reverted", patch_status::LogLevel::SUCCESS);
    }

    return success;
}

// Worker thread function to apply patches
void patching_thread(patch_status* status) {
    while (status->wait_for_process && status->is_running) {
        // Check for nvcontainer.exe process
        std::vector<DWORD> process_ids = get_processes_by_name(L"nvcontainer.exe");

        if (process_ids.empty()) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
            continue;
        }

        // Filter processes with nvd3dumx.dll loaded
        std::vector<DWORD> filtered_process_ids;
        for (DWORD process_id : process_ids) {
            if (is_module_loaded(process_id, L"nvd3dumx.dll"))
                filtered_process_ids.push_back(process_id);
        }

        if (filtered_process_ids.empty()) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
            continue;
        }

        // Found the process, no need to wait anymore
        status->wait_for_process = false;
        DWORD nvcontainer_process_id = filtered_process_ids[0];
        status->target_process_id = nvcontainer_process_id;
        add_log(*status, "Correct process found. PID: " + std::to_string(nvcontainer_process_id), patch_status::LogLevel::SUCCESS);

        // Open the process
        HANDLE h_process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, nvcontainer_process_id);
        if (!h_process) {
            add_log(*status, "Could not open process", patch_status::LogLevel::ERR);
            status->is_patched = false;
            break;
        }

        // Apply patches
        add_log(*status, "Starting to apply patches...", patch_status::LogLevel::INFO);
        int error_code = patch_get_window_display_affinity(h_process, *status);
        if (error_code) {
            add_log(*status, "Something went wrong while applying the first patch", patch_status::LogLevel::ERR);
            CloseHandle(h_process);
            status->is_patched = false;
            break;
        }

        error_code = patch_kernel32_module32_first_w(h_process, *status);
        if (error_code) {
            add_log(*status, "Something went wrong while applying the second patch", patch_status::LogLevel::ERR);
            CloseHandle(h_process);
            status->is_patched = false;
            break;
        }

        CloseHandle(h_process);
        add_log(*status, "Patches finished!", patch_status::LogLevel::SUCCESS);
        status->is_patched = true;
        status->undo_available = true;

        // Auto close if requested
        if (status->auto_close)
            status->is_running = false;
    }
}

void apply_style() {
    auto& style = ImGui::GetStyle();
    style.WindowPadding = { 10.f, 10.f };
    style.PopupRounding = 0.f;
    style.FramePadding = { 8.f, 4.f };
    style.ItemSpacing = { 10.f, 8.f };
    style.ItemInnerSpacing = { 6.f, 6.f };
    style.TouchExtraPadding = { 0.f, 0.f };
    style.IndentSpacing = 21.f;
    style.ScrollbarSize = 15.f;
    style.GrabMinSize = 8.f;
    style.WindowBorderSize = 1.f;
    style.ChildBorderSize = 0.f;
    style.PopupBorderSize = 1.f;
    style.FrameBorderSize = 0.f;
    style.TabBorderSize = 0.f;
    style.WindowRounding = 0.f;
    style.ChildRounding = 0.f;
    style.FrameRounding = 0.f;
    style.ScrollbarRounding = 0.f;
    style.GrabRounding = 0.f;
    style.TabRounding = 0.f;
    style.WindowTitleAlign = { 0.5f, 0.5f };
    style.ButtonTextAlign = { 0.5f, 0.5f };
    style.DisplaySafeAreaPadding = { 3.f, 3.f };

    auto& colors = style.Colors;
    colors[ImGuiCol_Text] = ImVec4(1.00f, 1.00f, 1.00f, 1.00f);
    colors[ImGuiCol_TextDisabled] = ImVec4(1.00f, 0.90f, 0.19f, 1.00f);
    colors[ImGuiCol_WindowBg] = ImVec4(0.06f, 0.06f, 0.06f, 1.00f);
    colors[ImGuiCol_ChildBg] = ImVec4(0.00f, 0.00f, 0.00f, 0.00f);
    colors[ImGuiCol_PopupBg] = ImVec4(0.08f, 0.08f, 0.08f, 0.94f);
    colors[ImGuiCol_Border] = ImVec4(0.30f, 0.30f, 0.30f, 0.50f);
    colors[ImGuiCol_BorderShadow] = ImVec4(0.00f, 0.00f, 0.00f, 0.00f);
    colors[ImGuiCol_FrameBg] = ImVec4(0.21f, 0.21f, 0.21f, 0.54f);
    colors[ImGuiCol_FrameBgHovered] = ImVec4(0.21f, 0.21f, 0.21f, 0.78f);
    colors[ImGuiCol_FrameBgActive] = ImVec4(0.28f, 0.27f, 0.27f, 0.54f);
    colors[ImGuiCol_TitleBg] = ImVec4(0.17f, 0.17f, 0.17f, 1.00f);
    colors[ImGuiCol_TitleBgActive] = ImVec4(0.19f, 0.19f, 0.19f, 1.00f);
    colors[ImGuiCol_TitleBgCollapsed] = ImVec4(0.00f, 0.00f, 0.00f, 0.51f);
    colors[ImGuiCol_MenuBarBg] = ImVec4(0.14f, 0.14f, 0.14f, 1.00f);
    colors[ImGuiCol_ScrollbarBg] = ImVec4(0.02f, 0.02f, 0.02f, 0.53f);
    colors[ImGuiCol_ScrollbarGrab] = ImVec4(0.31f, 0.31f, 0.31f, 1.00f);
    colors[ImGuiCol_ScrollbarGrabHovered] = ImVec4(0.41f, 0.41f, 0.41f, 1.00f);
    colors[ImGuiCol_ScrollbarGrabActive] = ImVec4(0.51f, 0.51f, 0.51f, 1.00f);
    colors[ImGuiCol_CheckMark] = ImVec4(1.00f, 1.00f, 1.00f, 1.00f);
    colors[ImGuiCol_SliderGrab] = ImVec4(0.34f, 0.34f, 0.34f, 1.00f);
    colors[ImGuiCol_SliderGrabActive] = ImVec4(0.39f, 0.38f, 0.38f, 1.00f);
    colors[ImGuiCol_Button] = ImVec4(0.41f, 0.41f, 0.41f, 0.74f);
    colors[ImGuiCol_ButtonHovered] = ImVec4(0.41f, 0.41f, 0.41f, 0.78f);
    colors[ImGuiCol_ButtonActive] = ImVec4(0.41f, 0.41f, 0.41f, 0.87f);
    colors[ImGuiCol_Header] = ImVec4(0.37f, 0.37f, 0.37f, 0.31f);
    colors[ImGuiCol_HeaderHovered] = ImVec4(0.38f, 0.38f, 0.38f, 0.37f);
    colors[ImGuiCol_HeaderActive] = ImVec4(0.37f, 0.37f, 0.37f, 0.51f);
    colors[ImGuiCol_Separator] = ImVec4(0.38f, 0.38f, 0.38f, 0.50f);
    colors[ImGuiCol_SeparatorHovered] = ImVec4(0.46f, 0.46f, 0.46f, 0.50f);
    colors[ImGuiCol_SeparatorActive] = ImVec4(0.46f, 0.46f, 0.46f, 0.64f);
    colors[ImGuiCol_ResizeGrip] = ImVec4(0.26f, 0.26f, 0.26f, 1.00f);
    colors[ImGuiCol_ResizeGripHovered] = ImVec4(0.31f, 0.31f, 0.31f, 1.00f);
    colors[ImGuiCol_ResizeGripActive] = ImVec4(0.35f, 0.35f, 0.35f, 1.00f);
    colors[ImGuiCol_Tab] = ImVec4(0.21f, 0.21f, 0.21f, 0.86f);
    colors[ImGuiCol_TabHovered] = ImVec4(0.27f, 0.27f, 0.27f, 0.86f);
    colors[ImGuiCol_TabActive] = ImVec4(0.34f, 0.34f, 0.34f, 0.86f);
    colors[ImGuiCol_TabUnfocused] = ImVec4(0.10f, 0.10f, 0.10f, 0.97f);
    colors[ImGuiCol_TabUnfocusedActive] = ImVec4(0.15f, 0.15f, 0.15f, 1.00f);
    colors[ImGuiCol_PlotLines] = ImVec4(0.61f, 0.61f, 0.61f, 1.00f);
    colors[ImGuiCol_PlotLinesHovered] = ImVec4(1.00f, 0.43f, 0.35f, 1.00f);
    colors[ImGuiCol_PlotHistogram] = ImVec4(0.90f, 0.70f, 0.00f, 1.00f);
    colors[ImGuiCol_PlotHistogramHovered] = ImVec4(1.00f, 0.60f, 0.00f, 1.00f);
    colors[ImGuiCol_TextSelectedBg] = ImVec4(0.26f, 0.59f, 0.98f, 0.35f);
    colors[ImGuiCol_DragDropTarget] = ImVec4(1.00f, 1.00f, 0.00f, 0.90f);
    colors[ImGuiCol_NavHighlight] = ImVec4(0.26f, 0.59f, 0.98f, 1.00f);
    colors[ImGuiCol_NavWindowingHighlight] = ImVec4(1.00f, 1.00f, 1.00f, 0.70f);
    colors[ImGuiCol_NavWindowingDimBg] = ImVec4(0.80f, 0.80f, 0.80f, 0.20f);
    colors[ImGuiCol_ModalWindowDimBg] = ImVec4(0.80f, 0.80f, 0.80f, 0.35f);
}

std::string get_config_path() {
    char path[MAX_PATH];
    GetModuleFileNameA(NULL, path, MAX_PATH);

    // Remove the executable name to get the directory
    std::string dir(path);
    size_t pos = dir.find_last_of("\\/");
    std::string exe_dir = (pos != std::string::npos) ? dir.substr(0, pos + 1) : "";

    return exe_dir + "config.ini";
}

// WinMain - the Windows entry point
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
    // Load configuration
    Config config;
    config.Load(get_config_path().c_str());

    patch_status status;
    status.startup_enabled = config.startup_enabled;
    status.auto_close = config.auto_close;

    if (config.no_gui)
    {
        // Non-GUI mode (if still needed for debugging)
        patching_thread(&status);
        return 0;
    }

    // Initialize window
    WNDCLASSEX wc = { sizeof(WNDCLASSEX), CS_CLASSDC, wnd_proc, 0L, 0L, hInstance, NULL, NULL, NULL, NULL, _T("NVIDIA Patcher"), NULL };
    RegisterClassEx(&wc);
    HWND hwnd = CreateWindow(wc.lpszClassName, _T("NVIDIA Patcher"),
        WS_POPUP | WS_VISIBLE, // WS_POPUP for borderless
        100, 100, 700, 500, NULL, NULL, wc.hInstance, NULL);

    // Initialize Direct3D
    if (!create_device_d3d(hwnd, &g_device, &g_device_context, &g_swap_chain))
    {
        cleanup_device_d3d(g_device, g_device_context, g_swap_chain);
        UnregisterClass(wc.lpszClassName, wc.hInstance);
        return 1;
    }

    // Show the window
    ShowWindow(hwnd, SW_SHOWDEFAULT);
    UpdateWindow(hwnd);

    // Setup ImGui context
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO(); (void)io;

    // Setup style
    apply_style();

    // Setup Platform/Renderer backends
    ImGui_ImplWin32_Init(hwnd);
    ImGui_ImplDX11_Init(g_device, g_device_context);

    ImFontConfig font_cfg{};
    font_cfg.FontDataOwnedByAtlas = false;

    ImFont* main_font = ImGui::GetIO().Fonts->AddFontFromMemoryTTF(
        const_cast<std::uint8_t*>(font_main),
        sizeof(font_main),
        MAIN_FONT_SIZE, // See font.h to edit
        &font_cfg);

    io.FontDefault = main_font;

    // Start patching thread
    std::thread worker_thread(patching_thread, &status);

    // Main loop
    MSG msg;
    ZeroMemory(&msg, sizeof(msg));
    while (msg.message != WM_QUIT && status.is_running)
    {
        if (PeekMessage(&msg, NULL, 0U, 0U, PM_REMOVE))
        {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
            continue;
        }

        // Start the Dear ImGui frame
        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();

        // UI Layout
        ImGui::SetNextWindowPos(ImVec2(0, 0));
        ImGui::SetNextWindowSize(ImVec2(700, 500));
        ImGui::Begin("NVIDIA Patcher", &status.is_running,
            ImGuiWindowFlags_NoResize |
            ImGuiWindowFlags_NoMove |
            ImGuiWindowFlags_NoCollapse |
            ImGuiWindowFlags_NoBringToFrontOnFocus);

        // Header with version and status
        ImGui::Text("NVIDIA Patcher v%s", VERSION);
        ImGui::SameLine(ImGui::GetWindowWidth() - 235);
        ImGui::Text(COPYRIGHT_INFO);
        ImGui::Separator();

        // Status panel
        ImGui::BeginChild("StatusPanel", ImVec2(0, 60), true);

        // Display current status with colored indicators
        ImGui::Text("Status: ");
        ImGui::SameLine();

        if (status.wait_for_process) {
            ImGui::TextColored(ImVec4(1.0f, 0.8f, 0.0f, 1.0f), "Waiting for nvcontainer.exe...");
        }
        else if (status.is_patched) {
            ImGui::TextColored(ImVec4(0.0f, 1.0f, 0.0f, 1.0f), "Patches Applied Successfully");
        }
        else {
            ImGui::TextColored(ImVec4(1.0f, 0.0f, 0.0f, 1.0f), status.status_message.c_str());
        }

        // Process ID information if available
        if (status.target_process_id != 0) {
            ImGui::Text("Target Process ID: %u", status.target_process_id);
        }

        ImGui::EndChild();

        // Controls panel
        ImGui::BeginChild("ControlsPanel", ImVec2(0, 60), true);

        // Main action buttons
        if (status.wait_for_process) {
            if (ImGui::Button("Cancel", ImVec2(100, 30))) {
                status.is_running = false;
            }
        }
        else {
            if (ImGui::Button("Close", ImVec2(100, 30))) {
                status.is_running = false;
            }
        }

        ImGui::SameLine();

        // Undo patches button - only enabled when patches are applied
        if (ImGui::Button("Undo Patches", ImVec2(120, 30)) && status.undo_available) {
            undo_patches(status);
        }

        ImGui::SameLine();

        // Settings checkboxes
        if (ImGui::Checkbox("Run at Windows startup", &status.startup_enabled))
        {
            config.startup_enabled = status.startup_enabled;
            config.Save(get_config_path().c_str());
            set_startup(status.startup_enabled);
        }

        ImGui::SameLine();

        if (ImGui::Checkbox("Auto-close after patching", &status.auto_close))
        {
            config.auto_close = status.auto_close;
            config.Save(get_config_path().c_str());
        }

        ImGui::EndChild();

        // Log display with title
        ImGui::Text("Detailed Log:");
        ImGui::BeginChild("LogRegion", ImVec2(0, 0), true, ImGuiWindowFlags_HorizontalScrollbar);
        ImGui::TextUnformatted(status.detailed_log.c_str());

        // Auto-scroll to keep up with new log entries
        if (ImGui::GetScrollY() >= ImGui::GetScrollMaxY() - 20)
        {
            ImGui::SetScrollHereY(1.0f);
        }
        ImGui::EndChild();

        ImGui::End();

        // Rendering
        ImGui::Render();
        g_device_context->OMSetRenderTargets(1, &g_main_render_target_view, NULL);
        const float clear_color[4] = { 0.45f, 0.55f, 0.60f, 1.00f };
        g_device_context->ClearRenderTargetView(g_main_render_target_view, clear_color);
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
        g_swap_chain->Present(1, 0);
    }

    // Wait for worker thread to finish
    status.is_running = false;
    if (worker_thread.joinable())
        worker_thread.join();

    // Cleanup
    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();

    cleanup_device_d3d(g_device, g_device_context, g_swap_chain);
    DestroyWindow(hwnd);
    UnregisterClass(wc.lpszClassName, wc.hInstance);

    return 0;
}

bool create_device_d3d(HWND hwnd, ID3D11Device** device, ID3D11DeviceContext** device_context, IDXGISwapChain** swap_chain)
{
    // Setup swap chain
    DXGI_SWAP_CHAIN_DESC sd;
    ZeroMemory(&sd, sizeof(sd));
    sd.BufferCount = 2;
    sd.BufferDesc.Width = 0;
    sd.BufferDesc.Height = 0;
    sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferDesc.RefreshRate.Numerator = 60;
    sd.BufferDesc.RefreshRate.Denominator = 1;
    sd.Flags = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
    sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.OutputWindow = hwnd;
    sd.SampleDesc.Count = 1;
    sd.SampleDesc.Quality = 0;
    sd.Windowed = TRUE;
    sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

    UINT create_device_flags = 0;
    D3D_FEATURE_LEVEL feature_level;
    const D3D_FEATURE_LEVEL feature_level_array[2] = { D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0, };
    if (D3D11CreateDeviceAndSwapChain(NULL, D3D_DRIVER_TYPE_HARDWARE, NULL, create_device_flags, feature_level_array, 2, D3D11_SDK_VERSION, &sd, swap_chain, device, &feature_level, device_context) != S_OK)
        return false;

    ID3D11Texture2D* pBackBuffer;
    (*swap_chain)->GetBuffer(0, IID_PPV_ARGS(&pBackBuffer));
    (*device)->CreateRenderTargetView(pBackBuffer, NULL, &g_main_render_target_view);
    pBackBuffer->Release();

    return true;
}

void cleanup_device_d3d(ID3D11Device* device, ID3D11DeviceContext* device_context, IDXGISwapChain* swap_chain)
{
    if (g_main_render_target_view) { g_main_render_target_view->Release(); g_main_render_target_view = NULL; }
    if (swap_chain) { swap_chain->Release(); }
    if (device_context) { device_context->Release(); }
    if (device) { device->Release(); }
}

// Win32 message handler
LRESULT WINAPI wnd_proc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
{
    if (ImGui_ImplWin32_WndProcHandler(hwnd, msg, wparam, lparam))
        return true;

    switch (msg)
    {
    case WM_SIZE:
        if (g_device != NULL && wparam != SIZE_MINIMIZED)
        {
            if (g_main_render_target_view) { g_main_render_target_view->Release(); g_main_render_target_view = NULL; }
            g_swap_chain->ResizeBuffers(0, (UINT)LOWORD(lparam), (UINT)HIWORD(lparam), DXGI_FORMAT_UNKNOWN, 0);
            ID3D11Texture2D* back_buffer;
            g_swap_chain->GetBuffer(0, IID_PPV_ARGS(&back_buffer));
            g_device->CreateRenderTargetView(back_buffer, NULL, &g_main_render_target_view);
            back_buffer->Release();
        }
        return 0;
    case WM_SYSCOMMAND:
        if ((wparam & 0xfff0) == SC_KEYMENU) // Disable ALT application menu
            return 0;
        break;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProc(hwnd, msg, wparam, lparam);
}
