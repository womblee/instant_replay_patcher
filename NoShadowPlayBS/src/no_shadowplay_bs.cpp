#include "utils.h"
#include "memory.h"
#include "config.h"
#include "font.h" // Exported font to C via HxD
#include <ImGui/imgui.h>
#include <ImGui/imgui_impl_dx11.h>
#include <ImGui/imgui_impl_win32.h>
#include <d3d11.h>
#include <tchar.h>
#include <iostream>
#include <array>
#include <string>
#include <thread>
#include <Windows.h> 
#include <ctime>
#include <fstream>
#include <dwmapi.h>
#include <shlobj.h>
#include <filesystem>
#include <shobjidl.h> 
#include <objbase.h>
#include <comdef.h>
#include <tlhelp32.h>

#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "dwmapi.lib")
#define IDI_ICON1 101

// Copyright information
#define COPYRIGHT_INFO \
"Made by: nloginov\n" \
"Concept: furyzenblade\n\n" \
"nlog.us/donate"

#define VERSION "1.4.6"

// Namespaces
namespace fs = std::filesystem;

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
    // Process opening
    std::vector<uint8_t> open_process_bytes;

    // Process enumeration
    std::vector<uint8_t> process32_first_w_bytes;
    std::vector<uint8_t> process32_next_w_bytes;

    // Module enumeration
    std::vector<uint8_t> module32_first_w_bytes;
    std::vector<uint8_t> module32_next_w_bytes;
    std::vector<uint8_t> enum_modules_bytes;

    // Window enumeration
    std::vector<uint8_t> enum_windows_bytes;
    std::vector<uint8_t> get_window_info_bytes;
    std::vector<uint8_t> window_display_affinity_bytes;

    // Module info
    /*std::vector<uint8_t> get_file_version_info_a_bytes;
    std::vector<uint8_t> get_file_version_info_size_a_bytes;*/
    std::vector<uint8_t> get_module_handle_a_bytes;
    std::vector<uint8_t> get_module_handle_w_bytes;
    std::vector<uint8_t> get_module_handle_ex_a_bytes;
    std::vector<uint8_t> get_module_handle_ex_w_bytes;
    std::vector<uint8_t> get_module_filename_a_bytes;
    std::vector<uint8_t> get_module_filename_w_bytes;
    std::vector<uint8_t> k32_get_module_filename_ex_a_bytes;
    std::vector<uint8_t> k32_get_module_base_name_a_bytes;

    // Signature-based patches
    std::vector<uint8_t> nvd3dumx_signature_bytes;

    // Address fields
    uintptr_t open_process_address = 0;
    uintptr_t process32_first_w_address = 0;
    uintptr_t process32_next_w_address = 0;
    uintptr_t module32_first_w_address = 0;
    uintptr_t module32_next_w_address = 0;
    uintptr_t enum_modules_address = 0;
    uintptr_t enum_windows_address = 0;
    uintptr_t get_window_info_address = 0;
    uintptr_t window_display_affinity_address = 0;
    /*uintptr_t get_file_version_info_a_address = 0;
    uintptr_t get_file_version_info_size_a_address = 0;*/
    uintptr_t get_module_handle_a_address = 0;
    uintptr_t get_module_handle_w_address = 0;
    uintptr_t get_module_handle_ex_a_address = 0;
    uintptr_t get_module_handle_ex_w_address = 0;
    uintptr_t get_module_filename_a_address = 0;
    uintptr_t get_module_filename_w_address = 0;
    uintptr_t k32_get_module_filename_ex_a_address = 0;
    uintptr_t k32_get_module_base_name_a_address = 0;

    // Signature-based addresses
    uintptr_t nvd3dumx_signature_address = 0;

    DWORD process_id = 0;
};

enum class patch_type {
    RETURN_FALSE,
    RETURN_TRUE,
    WDA_NONE_,
    CUSTOM_PATCH
};

enum class patch_method {
    EXPORTED_FUNCTION,
    SIGNATURE_SCAN
};

struct signature_info {
    std::vector<uint8_t> pattern;
    std::vector<bool> mask;  // true = match byte, false = wildcard
    std::string ida_style;   // For display purposes

    signature_info() = default;
    signature_info(const std::string& ida_sig) : ida_style(ida_sig) {
        parse_ida_signature(ida_sig);
    }

    void parse_ida_signature(const std::string& ida_sig) {
        pattern.clear();
        mask.clear();

        std::istringstream iss(ida_sig);
        std::string token;

        while (iss >> token) {
            if (token == "??" || token == "?") {
                pattern.push_back(0x00);
                mask.push_back(false);  // wildcard
            }
            else if (token.length() == 2) {
                try {
                    uint8_t byte = static_cast<uint8_t>(std::stoul(token, nullptr, 16));
                    pattern.push_back(byte);
                    mask.push_back(true);  // match this byte
                }
                catch (const std::exception&) {
                    // Invalid hex, treat as wildcard
                    pattern.push_back(0x00);
                    mask.push_back(false);
                }
            }
        }
    }
};

struct patch_config {
    const char* function_name;
    const wchar_t* module_name;
    patch_method method;
    patch_type type;
    std::vector<uint8_t> patch_bytes;
    std::vector<uint8_t>* backup_bytes;
    uintptr_t* address_field;
    size_t patch_size;

    // Signature-specific fields
    signature_info signature;
    std::string display_name;  // For logging

    // Constructor for exported functions (existing)
    patch_config(const char* func_name, const wchar_t* mod_name, patch_type p_type,
        std::vector<uint8_t> p_bytes, std::vector<uint8_t>* backup,
        uintptr_t* addr_field, size_t p_size)
        : function_name(func_name), module_name(mod_name), method(patch_method::EXPORTED_FUNCTION),
        type(p_type), patch_bytes(std::move(p_bytes)), backup_bytes(backup),
        address_field(addr_field), patch_size(p_size), display_name(func_name) {
    }

    // Constructor for signature-based patches
    patch_config(const std::string& name, const wchar_t* mod_name, const std::string& sig,
        patch_type p_type, std::vector<uint8_t> p_bytes, std::vector<uint8_t>* backup,
        uintptr_t* addr_field, size_t p_size)
        : function_name(nullptr), module_name(mod_name), method(patch_method::SIGNATURE_SCAN),
        type(p_type), patch_bytes(std::move(p_bytes)), backup_bytes(backup),
        address_field(addr_field), patch_size(p_size), signature(sig), display_name(name) {
    }
};

// Patch status tracking with improved logging
struct patch_status {
    bool wait_for_process = true;
    bool is_running = true;
    bool is_patched = false;
    bool startup_enabled = false;
    bool start_menu_enabled = false;
    bool hide_log_window = false;
    bool dark_mode = false;
    bool auto_close = false;
    bool auto_patch = true;
    bool undo_available = false;
    bool manual_patch_requested = false;
    DWORD target_process_id = 0;
    std::string status_message = "Ready - waiting for manual patch or auto-patch...";
    std::string detailed_log;
    original_bytes orig_bytes;

    // Log levels
    enum log_level {
        INFO,
        WARNING,
        ERR,
        SUCCESS
    };
};

// Function to return current executable path
std::string get_current_executable_path() {
    char buffer[MAX_PATH];
    GetModuleFileNameA(NULL, buffer, MAX_PATH);

    return std::string(buffer);
}

// Function to return current executable path (WCHAR version)
std::wstring get_current_executable_path_wide() {
    WCHAR buffer[MAX_PATH];
    GetModuleFileNameW(NULL, buffer, MAX_PATH);

    return std::wstring(buffer);
}

// Function to check if the program is running as admin
bool is_running_as_administrator() {
    BOOL is_admin = FALSE;
    PSID admin_group = nullptr;

    // Create a SID for the administrators group
    SID_IDENTIFIER_AUTHORITY nt_authority = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&nt_authority, 2, SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &admin_group)) {
        // Check if the current token is a member of the administrators group
        if (!CheckTokenMembership(NULL, admin_group, &is_admin)) {
            is_admin = FALSE;
        }
        FreeSid(admin_group);
    }

    return is_admin == TRUE;
}

bool is_another_instance_running() {
    std::wstring current_exe = fs::path(get_current_executable_path_wide()).filename().wstring();
    int instance_count = 0;

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return false;
    }

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(snapshot, &pe32)) {
        do {
            if (current_exe == pe32.szExeFile) {
                instance_count++;
                if (instance_count > 1) {
                    CloseHandle(snapshot);
                    return true;
                }
            }
        } while (Process32NextW(snapshot, &pe32));
    }

    CloseHandle(snapshot);
    return false;
}

// Function to set startup registry
bool set_startup(bool enable) {
    HKEY h_key;
    const char* key_path = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";

    if (RegOpenKeyExA(HKEY_CURRENT_USER, key_path, 0, KEY_SET_VALUE, &h_key) != ERROR_SUCCESS)
        return false;

    if (enable) {
        std::string exe_path = get_current_executable_path();
        RegSetValueExA(h_key, "NvPatcher", 0, REG_SZ, (BYTE*)exe_path.c_str(), static_cast<DWORD>(exe_path.length() + 1));
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

// Function to get the Start Menu programs folder path
std::string get_start_menu_programs_folder() {
    char start_menu_path[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_PROGRAMS, NULL, 0, start_menu_path))) {
        return start_menu_path;
    }
    return "";
}

// Function to check if shortcut exists in Start Menu
bool is_start_menu_enabled() {
    auto start_menu = get_start_menu_programs_folder();
    if (start_menu.empty()) return false;

    fs::path shortcut_path = fs::path(start_menu) / "NoShadowPlayBS.lnk";
    return fs::exists(shortcut_path);
}

// Function to add/remove shortcut from Start Menu
bool set_start_menu_shortcut(bool enable) {
    // Initialize COM
    CoInitialize(NULL);
    bool result = false;

    // Get executable path (wide char version)
    std::wstring exe_path = get_current_executable_path_wide();

    // Get Start Menu Programs folder (wide char version)
    WCHAR start_menu_path[MAX_PATH];
    if (FAILED(SHGetFolderPathW(NULL, CSIDL_PROGRAMS, NULL, 0, start_menu_path))) {
        CoUninitialize();
        return false;
    }

    std::wstring shortcut_path = std::wstring(start_menu_path) + L"\\NoShadowPlayBS.lnk";

    if (enable) {
        // Create shortcut
        IShellLinkW* psl = nullptr;
        IPersistFile* ppf = nullptr;

        if (SUCCEEDED(CoCreateInstance(CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER, IID_IShellLinkW, (LPVOID*)&psl))) {
            psl->SetPath(exe_path.c_str());
            psl->SetWorkingDirectory(fs::path(exe_path).parent_path().wstring().c_str());
            psl->SetDescription(L"ShadowPlay Patcher - Remove Recording Restrictions");

            if (SUCCEEDED(psl->QueryInterface(IID_IPersistFile, (void**)&ppf))) {
                result = SUCCEEDED(ppf->Save(shortcut_path.c_str(), TRUE));
                ppf->Release();
            }
            psl->Release();
        }
    }
    else {
        // Remove shortcut
        try {
            if (fs::exists(shortcut_path)) {
                result = fs::remove(shortcut_path);
            }
            else {
                result = true; // Doesn't exist counts as success
            }
        }
        catch (...) {
            result = false;
        }
    }

    CoUninitialize();
    return result;
}

// Function to apply Windows-native titlebar styling
void apply_native_titlebar_style(HWND hwnd, bool dark_mode) {
    if (hwnd == NULL) return;

    // Set dark/light titlebar for Windows 10 version 1809 and later
    BOOL use_dark_mode = dark_mode ? TRUE : FALSE;

    // Try the newer attribute first (Windows 10 version 1903+)
    HRESULT hr = DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE,
        &use_dark_mode, sizeof(use_dark_mode));

    // Fall back to older attribute for Windows 10 version 1809-1903
    if (FAILED(hr)) {
        DwmSetWindowAttribute(hwnd, 19, &use_dark_mode, sizeof(use_dark_mode));
    }

    // Optional: Add subtle blur effect for modern appearance
    if (dark_mode) {
        DWM_BLURBEHIND bb = {};
        bb.dwFlags = DWM_BB_ENABLE;
        bb.fEnable = TRUE;
        bb.hRgnBlur = NULL;
        DwmEnableBlurBehindWindow(hwnd, &bb);
    }
}

// Helper function to convert wide string to narrow string
std::string wstring_to_string(const std::wstring& wstr) {
    if (wstr.empty()) return std::string();

    int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
    std::string str(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &str[0], size_needed, NULL, NULL);

    return str;
}

// Helper function to convert wchar_t* to string
std::string wchar_to_string(const wchar_t* wstr) {
    return wstring_to_string(std::wstring(wstr));
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
void add_log(patch_status& status, const std::string& message, patch_status::log_level level = patch_status::log_level::INFO) {
    std::string prefix;

    switch (level) {
    case patch_status::log_level::INFO:
        prefix = "[INFO]";
        break;
    case patch_status::log_level::WARNING:
        prefix = "[WARNING]";
        break;
    case patch_status::log_level::ERR:
        prefix = "[ERROR]";
        break;
    case patch_status::log_level::SUCCESS:
        prefix = "[SUCCESS]";
        break;
    }

    std::string timestamp = get_timestamp();
    std::string formatted_message = "[" + timestamp + "] " + prefix + " " + message;
    status.detailed_log += formatted_message + "\n";
    status.status_message = message;
}

// Save patch info to file for persistence
void save_patch_info(const original_bytes& orig_bytes, const std::string& config_path) {
    std::string patch_info_path = config_path.substr(0, config_path.find_last_of('.')) + "_patches.dat";
    std::ofstream file(patch_info_path, std::ios::binary);

    if (!file.is_open()) return;

    // Write process ID
    file.write(reinterpret_cast<const char*>(&orig_bytes.process_id), sizeof(orig_bytes.process_id));

    // Write addresses
    file.write(reinterpret_cast<const char*>(&orig_bytes.open_process_address), sizeof(orig_bytes.open_process_address));
    file.write(reinterpret_cast<const char*>(&orig_bytes.window_display_affinity_address), sizeof(orig_bytes.window_display_affinity_address));
    file.write(reinterpret_cast<const char*>(&orig_bytes.process32_first_w_address), sizeof(orig_bytes.process32_first_w_address));
    file.write(reinterpret_cast<const char*>(&orig_bytes.process32_next_w_address), sizeof(orig_bytes.process32_next_w_address));
    file.write(reinterpret_cast<const char*>(&orig_bytes.module32_first_w_address), sizeof(orig_bytes.module32_first_w_address));
    file.write(reinterpret_cast<const char*>(&orig_bytes.module32_next_w_address), sizeof(orig_bytes.module32_next_w_address));
    file.write(reinterpret_cast<const char*>(&orig_bytes.enum_windows_address), sizeof(orig_bytes.enum_windows_address));
    file.write(reinterpret_cast<const char*>(&orig_bytes.get_window_info_address), sizeof(orig_bytes.get_window_info_address));
    file.write(reinterpret_cast<const char*>(&orig_bytes.enum_modules_address), sizeof(orig_bytes.enum_modules_address));
    /*file.write(reinterpret_cast<const char*>(&orig_bytes.get_file_version_info_a_address), sizeof(orig_bytes.get_file_version_info_a_address));
    file.write(reinterpret_cast<const char*>(&orig_bytes.get_file_version_info_size_a_address), sizeof(orig_bytes.get_file_version_info_size_a_address));*/
    file.write(reinterpret_cast<const char*>(&orig_bytes.get_module_handle_a_address), sizeof(orig_bytes.get_module_handle_a_address));
    file.write(reinterpret_cast<const char*>(&orig_bytes.get_module_handle_w_address), sizeof(orig_bytes.get_module_handle_w_address));
    file.write(reinterpret_cast<const char*>(&orig_bytes.get_module_handle_ex_a_address), sizeof(orig_bytes.get_module_handle_ex_a_address));
    file.write(reinterpret_cast<const char*>(&orig_bytes.get_module_handle_ex_w_address), sizeof(orig_bytes.get_module_handle_ex_w_address));
    file.write(reinterpret_cast<const char*>(&orig_bytes.get_module_filename_a_address), sizeof(orig_bytes.get_module_filename_a_address));
    file.write(reinterpret_cast<const char*>(&orig_bytes.get_module_filename_w_address), sizeof(orig_bytes.get_module_filename_w_address));
    file.write(reinterpret_cast<const char*>(&orig_bytes.k32_get_module_filename_ex_a_address), sizeof(orig_bytes.k32_get_module_filename_ex_a_address));
    file.write(reinterpret_cast<const char*>(&orig_bytes.k32_get_module_base_name_a_address), sizeof(orig_bytes.k32_get_module_base_name_a_address));
    file.write(reinterpret_cast<const char*>(&orig_bytes.nvd3dumx_signature_address), sizeof(orig_bytes.nvd3dumx_signature_address));

    // Helper lambda to write byte vectors
    auto write_bytes = [&file](const std::vector<uint8_t>& bytes) {
        size_t size = bytes.size();
        file.write(reinterpret_cast<const char*>(&size), sizeof(size));
        if (size > 0) {
            file.write(reinterpret_cast<const char*>(bytes.data()), size);
        }
        };

    // Write all byte vectors
    write_bytes(orig_bytes.open_process_bytes);
    write_bytes(orig_bytes.window_display_affinity_bytes);
    write_bytes(orig_bytes.process32_first_w_bytes);
    write_bytes(orig_bytes.process32_next_w_bytes);
    write_bytes(orig_bytes.module32_first_w_bytes);
    write_bytes(orig_bytes.module32_next_w_bytes);
    write_bytes(orig_bytes.enum_windows_bytes);
    write_bytes(orig_bytes.get_window_info_bytes);
    write_bytes(orig_bytes.enum_modules_bytes);
    /*write_bytes(orig_bytes.get_file_version_info_a_bytes);
    write_bytes(orig_bytes.get_file_version_info_size_a_bytes);*/
    write_bytes(orig_bytes.get_module_handle_a_bytes);
    write_bytes(orig_bytes.get_module_handle_w_bytes);
    write_bytes(orig_bytes.get_module_handle_ex_a_bytes);
    write_bytes(orig_bytes.get_module_handle_ex_w_bytes);
    write_bytes(orig_bytes.get_module_filename_a_bytes);
    write_bytes(orig_bytes.get_module_filename_w_bytes);
    write_bytes(orig_bytes.k32_get_module_filename_ex_a_bytes);
    write_bytes(orig_bytes.k32_get_module_base_name_a_bytes);
    write_bytes(orig_bytes.nvd3dumx_signature_bytes);

    file.close();
}

// Load patch info from file
bool load_patch_info(original_bytes& orig_bytes, const std::string& config_path) {
    std::string patch_info_path = config_path.substr(0, config_path.find_last_of('.')) + "_patches.dat";
    std::ifstream file(patch_info_path, std::ios::binary);

    if (!file.is_open()) return false;

    try {
        // Read process ID
        file.read(reinterpret_cast<char*>(&orig_bytes.process_id), sizeof(orig_bytes.process_id));

        // Read addresses
        file.read(reinterpret_cast<char*>(&orig_bytes.open_process_address), sizeof(orig_bytes.open_process_address));
        file.read(reinterpret_cast<char*>(&orig_bytes.window_display_affinity_address), sizeof(orig_bytes.window_display_affinity_address));
        file.read(reinterpret_cast<char*>(&orig_bytes.process32_first_w_address), sizeof(orig_bytes.process32_first_w_address));
        file.read(reinterpret_cast<char*>(&orig_bytes.process32_next_w_address), sizeof(orig_bytes.process32_next_w_address));
        file.read(reinterpret_cast<char*>(&orig_bytes.module32_first_w_address), sizeof(orig_bytes.module32_first_w_address));
        file.read(reinterpret_cast<char*>(&orig_bytes.module32_next_w_address), sizeof(orig_bytes.module32_next_w_address));
        file.read(reinterpret_cast<char*>(&orig_bytes.enum_windows_address), sizeof(orig_bytes.enum_windows_address));
        file.read(reinterpret_cast<char*>(&orig_bytes.get_window_info_address), sizeof(orig_bytes.get_window_info_address));
        file.read(reinterpret_cast<char*>(&orig_bytes.enum_modules_address), sizeof(orig_bytes.enum_modules_address));
        /*file.read(reinterpret_cast<char*>(&orig_bytes.get_file_version_info_a_address), sizeof(orig_bytes.get_file_version_info_a_address));
        file.read(reinterpret_cast<char*>(&orig_bytes.get_file_version_info_size_a_address), sizeof(orig_bytes.get_file_version_info_size_a_address));*/
        file.read(reinterpret_cast<char*>(&orig_bytes.get_module_handle_a_address), sizeof(orig_bytes.get_module_handle_a_address));
        file.read(reinterpret_cast<char*>(&orig_bytes.get_module_handle_w_address), sizeof(orig_bytes.get_module_handle_w_address));
        file.read(reinterpret_cast<char*>(&orig_bytes.get_module_handle_ex_a_address), sizeof(orig_bytes.get_module_handle_ex_a_address));
        file.read(reinterpret_cast<char*>(&orig_bytes.get_module_handle_ex_w_address), sizeof(orig_bytes.get_module_handle_ex_w_address));
        file.read(reinterpret_cast<char*>(&orig_bytes.get_module_filename_a_address), sizeof(orig_bytes.get_module_filename_a_address));
        file.read(reinterpret_cast<char*>(&orig_bytes.get_module_filename_w_address), sizeof(orig_bytes.get_module_filename_w_address));
        file.read(reinterpret_cast<char*>(&orig_bytes.k32_get_module_filename_ex_a_address), sizeof(orig_bytes.k32_get_module_filename_ex_a_address));
        file.read(reinterpret_cast<char*>(&orig_bytes.k32_get_module_base_name_a_address), sizeof(orig_bytes.k32_get_module_base_name_a_address));
        file.read(reinterpret_cast<char*>(&orig_bytes.nvd3dumx_signature_address), sizeof(orig_bytes.nvd3dumx_signature_address));

        // Helper lambda to read byte vectors
        auto read_bytes = [&file](std::vector<uint8_t>& bytes) {
            size_t size;
            file.read(reinterpret_cast<char*>(&size), sizeof(size));
            if (size > 0 && size < 1024) { // Sanity check
                bytes.resize(size);
                file.read(reinterpret_cast<char*>(bytes.data()), size);
            }
            };

        // Read all byte vectors
        read_bytes(orig_bytes.open_process_bytes);
        read_bytes(orig_bytes.window_display_affinity_bytes);
        read_bytes(orig_bytes.process32_first_w_bytes);
        read_bytes(orig_bytes.process32_next_w_bytes);
        read_bytes(orig_bytes.module32_first_w_bytes);
        read_bytes(orig_bytes.module32_next_w_bytes);
        read_bytes(orig_bytes.enum_windows_bytes);
        read_bytes(orig_bytes.get_window_info_bytes);
        read_bytes(orig_bytes.enum_modules_bytes);
        /*read_bytes(orig_bytes.get_file_version_info_a_bytes);
        read_bytes(orig_bytes.get_file_version_info_size_a_bytes);*/
        read_bytes(orig_bytes.get_module_handle_a_bytes);
        read_bytes(orig_bytes.get_module_handle_w_bytes);
        read_bytes(orig_bytes.get_module_handle_ex_a_bytes);
        read_bytes(orig_bytes.get_module_handle_ex_w_bytes);
        read_bytes(orig_bytes.get_module_filename_a_bytes);
        read_bytes(orig_bytes.get_module_filename_w_bytes);
        read_bytes(orig_bytes.k32_get_module_filename_ex_a_bytes);
        read_bytes(orig_bytes.k32_get_module_base_name_a_bytes);
        read_bytes(orig_bytes.nvd3dumx_signature_bytes);

        file.close();
        return true;
    }
    catch (...) {
        file.close();
        return false;
    }
}

// Delete patch info file
void delete_patch_info(const std::string& config_path) {
    std::string patch_info_path = config_path.substr(0, config_path.find_last_of('.')) + "_patches.dat";
    DeleteFileA(patch_info_path.c_str());
}

// Signature scanning functions
uintptr_t find_pattern_in_module(HANDLE h_process, uintptr_t module_base, size_t module_size,
    const signature_info& sig, patch_status& status) {
    if (sig.pattern.empty()) {
        add_log(status, "Empty signature pattern", patch_status::log_level::ERR);
        return 0;
    }

    // Read module memory in chunks
    const size_t chunk_size = 64 * 1024;  // 64KB chunks
    std::vector<uint8_t> buffer(chunk_size);

    for (size_t offset = 0; offset < module_size; offset += chunk_size - sig.pattern.size()) {
        size_t read_size = min(chunk_size, module_size - offset);
        SIZE_T bytes_read = 0;

        if (!ReadProcessMemory(h_process, (LPCVOID)(module_base + offset),
            buffer.data(), read_size, &bytes_read) || bytes_read == 0) {
            continue;
        }

        // Search for pattern in this chunk
        for (size_t i = 0; i <= bytes_read - sig.pattern.size(); ++i) {
            bool match = true;
            for (size_t j = 0; j < sig.pattern.size(); ++j) {
                if (sig.mask[j] && buffer[i + j] != sig.pattern[j]) {
                    match = false;
                    break;
                }
            }

            if (match) {
                uintptr_t found_address = module_base + offset + i;
                return found_address;
            }
        }
    }

    return 0;  // Pattern not found
}

uintptr_t get_module_size(HANDLE h_process, uintptr_t module_base) {
    IMAGE_DOS_HEADER dos_header;
    IMAGE_NT_HEADERS nt_headers;
    SIZE_T bytes_read;

    // Read DOS header
    if (!ReadProcessMemory(h_process, (LPCVOID)module_base, &dos_header,
        sizeof(dos_header), &bytes_read)) {
        return 0;
    }

    // Read NT headers
    if (!ReadProcessMemory(h_process, (LPCVOID)(module_base + dos_header.e_lfanew),
        &nt_headers, sizeof(nt_headers), &bytes_read)) {
        return 0;
    }

    return nt_headers.OptionalHeader.SizeOfImage;
}

uintptr_t find_signature_in_module(HANDLE h_process, const wchar_t* module_name,
    const signature_info& sig, patch_status& status) {
    // Get module base address
    uintptr_t module_base = get_remote_module_base_address(h_process, module_name);
    if (!module_base) {
        add_log(status, std::string("Could not find module: ") + wchar_to_string(module_name),
            patch_status::log_level::ERR);
        return 0;
    }

    // Get module size
    size_t module_size = get_module_size(h_process, module_base);
    if (!module_size) {
        add_log(status, "Could not get module size", patch_status::log_level::ERR);
        return 0;
    }

    return find_pattern_in_module(h_process, module_base, module_size, sig, status);
}

// Check if process is still running
bool is_process_running(DWORD process_id) {
    HANDLE h_process = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, process_id);
    if (!h_process) return false;

    DWORD exit_code;
    bool running = GetExitCodeProcess(h_process, &exit_code) && exit_code == STILL_ACTIVE;
    CloseHandle(h_process);
    return running;
}

// Function to check if a process has already been patched
bool is_process_patched(HANDLE h_process, uintptr_t target_address, patch_status& status) {
    std::vector<uint8_t> current_bytes(7, 0);
    SIZE_T bytes_read;

    if (!ReadProcessMemory(h_process, (LPCVOID)target_address, current_bytes.data(), current_bytes.size(), &bytes_read)) {
        add_log(status, "Failed to read memory for patch check", patch_status::log_level::ERR);
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

// Function to force load a DLL in the target process
bool force_load_dll_in_process(HANDLE h_process, const wchar_t* dll_name) {
    // Get LoadLibraryW address from kernel32.dll
    HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
    if (!kernel32) return false;

    FARPROC load_library_w = GetProcAddress(kernel32, "LoadLibraryW");
    if (!load_library_w) return false;

    // Allocate memory for the DLL name in target process
    size_t dll_name_size = (wcslen(dll_name) + 1) * sizeof(wchar_t);
    void* remote_dll_name = VirtualAllocEx(h_process, NULL, dll_name_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote_dll_name) return false;

    // Write DLL name to target process
    if (!WriteProcessMemory(h_process, remote_dll_name, dll_name, dll_name_size, NULL)) {
        VirtualFreeEx(h_process, remote_dll_name, 0, MEM_RELEASE);
        return false;
    }

    // Create remote thread to call LoadLibraryW
    HANDLE thread = CreateRemoteThread(h_process, NULL, 0, (LPTHREAD_START_ROUTINE)load_library_w, remote_dll_name, 0, NULL);
    if (!thread) {
        VirtualFreeEx(h_process, remote_dll_name, 0, MEM_RELEASE);
        return false;
    }

    // Wait for the thread to complete
    WaitForSingleObject(thread, INFINITE);

    // Get the return value (HMODULE)
    DWORD exit_code = 0;
    GetExitCodeThread(thread, &exit_code);

    // Cleanup
    CloseHandle(thread);
    VirtualFreeEx(h_process, remote_dll_name, 0, MEM_RELEASE);

    return exit_code != 0; // LoadLibraryW returns NULL on failure
}

int apply_patch(HANDLE h_process, patch_status& status, const patch_config& config) {
    uintptr_t target_address = 0;

    if (config.method == patch_method::EXPORTED_FUNCTION) {
        // Original exported function logic
        uintptr_t module_base = get_remote_module_base_address(h_process, config.module_name);

        if (!module_base) {
            add_log(status, std::string("DLL not loaded, attempting to force load ") +
                wchar_to_string(config.module_name), patch_status::log_level::INFO);
            if (!force_load_dll_in_process(h_process, config.module_name)) {
                add_log(status, std::string("Could not force load ") +
                    wchar_to_string(config.module_name), patch_status::log_level::ERR);
                return 1;
            }

            Sleep(100);
            module_base = get_remote_module_base_address(h_process, config.module_name);
            if (!module_base) {
                add_log(status, "DLL still not loaded after force load attempt",
                    patch_status::log_level::ERR);
                return 1;
            }
        }

        target_address = get_exported_function_address(h_process, module_base,
            config.module_name, config.function_name);

        if (!target_address) {
            add_log(status, std::string("Could not get address of ") + config.function_name,
                patch_status::log_level::ERR);
            return 1;
        }

    }
    else if (config.method == patch_method::SIGNATURE_SCAN) {
        // Signature scanning logic
        target_address = find_signature_in_module(h_process, config.module_name,
            config.signature, status);

        if (!target_address) {
            add_log(status, "Could not find signature for " + config.display_name,
                patch_status::log_level::ERR);
            return 1;
        }
    }

    // Store address for undo
    *(config.address_field) = target_address;

    // Check if already patched
    if (is_process_patched(h_process, target_address, status)) {
        add_log(status, config.display_name + " already appears to be patched",
            patch_status::log_level::WARNING);
        return 0;
    }

    // Backup original bytes
    config.backup_bytes->resize(config.patch_size);
    if (!backup_original_bytes(h_process, target_address, *config.backup_bytes, config.patch_size)) {
        add_log(status, "Failed to backup " + config.display_name, patch_status::log_level::ERR);
        return 1;
    }

    // For custom patches, write directly
    if (config.type == patch_type::CUSTOM_PATCH) {
        if (config.patch_bytes.size() > config.patch_size) {
            add_log(status, "Patch bytes too large for " + config.display_name,
                patch_status::log_level::ERR);
            return 1;
        }

        std::vector<uint8_t> final_patch = config.patch_bytes;
        final_patch.resize(config.patch_size, 0x90); // Fill with NOPs

        if (!write_memory_with_protection(h_process, target_address,
            final_patch.data(), final_patch.size())) {
            add_log(status, "Could not write custom patch for " + config.display_name,
                patch_status::log_level::ERR);
            return 1;
        }

        add_log(status, "Patched " + config.display_name,
            patch_status::log_level::SUCCESS);

        return 0;
    }

    // Original jump-based patching logic for other patch types
    uintptr_t allocated_memory = allocate_memory_near_address(h_process, target_address, 0x1000);
    if (!allocated_memory) {
        add_log(status, "Could not allocate memory near " + config.display_name,
            patch_status::log_level::ERR);
        return 1;
    }

    if (!write_memory_with_protection_dynamic(h_process, allocated_memory, config.patch_bytes)) {
        add_log(status, "Could not write payload for " + config.display_name,
            patch_status::log_level::ERR);
        return 1;
    }

    std::array<uint8_t, 5> jmp_instruction;
    if (!assemble_jump_near_instruction(jmp_instruction.data(), target_address, allocated_memory)) {
        add_log(status, "Jump too far for " + config.display_name, patch_status::log_level::ERR);
        return 1;
    }

    std::vector<uint8_t> final_patch(jmp_instruction.begin(), jmp_instruction.end());
    final_patch.resize(config.patch_size, 0x90);

    if (!write_memory_with_protection(h_process, target_address,
        final_patch.data(), final_patch.size())) {
        add_log(status, "Could not write final patch for " + config.display_name,
            patch_status::log_level::ERR);
        return 1;
    }

    add_log(status, "Patched " + config.display_name, patch_status::log_level::SUCCESS);
    return 0;
}

std::vector<patch_config> get_patch_configs(patch_status& status) {
    std::vector<patch_config> configs;

    // Original exported function patches
    configs.emplace_back("OpenProcess", L"KERNEL32.dll", patch_type::RETURN_FALSE,
        std::vector<uint8_t>{0x48, 0x31, 0xC0, 0xC3},
        & status.orig_bytes.open_process_bytes,
        & status.orig_bytes.open_process_address, 12);

    configs.emplace_back("Process32FirstW", L"KERNEL32.DLL", patch_type::RETURN_FALSE,
        std::vector<uint8_t>{0x33, 0xC0, 0xC3},
        & status.orig_bytes.process32_first_w_bytes,
        & status.orig_bytes.process32_first_w_address, 7);

    configs.emplace_back("Process32NextW", L"KERNEL32.DLL", patch_type::RETURN_FALSE,
        std::vector<uint8_t>{0x33, 0xC0, 0xC3},
        & status.orig_bytes.process32_next_w_bytes,
        & status.orig_bytes.process32_next_w_address, 7);

    configs.emplace_back("Module32FirstW", L"KERNEL32.DLL", patch_type::RETURN_FALSE,
        std::vector<uint8_t>{0x33, 0xC0, 0xC3},
        & status.orig_bytes.module32_first_w_bytes,
        & status.orig_bytes.module32_first_w_address, 7);

    configs.emplace_back("Module32NextW", L"KERNEL32.DLL", patch_type::RETURN_FALSE,
        std::vector<uint8_t>{0x33, 0xC0, 0xC3},
        & status.orig_bytes.module32_next_w_bytes,
        & status.orig_bytes.module32_next_w_address, 7);

    configs.emplace_back("K32EnumProcessModules", L"KERNEL32.dll", patch_type::RETURN_FALSE,
        std::vector<uint8_t>{0x33, 0xC0, 0xC3},
        & status.orig_bytes.enum_modules_bytes,
        & status.orig_bytes.enum_modules_address, 6);

    configs.emplace_back("EnumWindows", L"USER32.dll", patch_type::RETURN_TRUE,
        std::vector<uint8_t>{0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00, 0xC3},
        & status.orig_bytes.enum_windows_bytes,
        & status.orig_bytes.enum_windows_address, 6);

    configs.emplace_back("GetWindowInfo", L"USER32.dll", patch_type::RETURN_TRUE,
        std::vector<uint8_t>{0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00, 0xC3},
        & status.orig_bytes.get_window_info_bytes,
        & status.orig_bytes.get_window_info_address, 6);

    configs.emplace_back("GetWindowDisplayAffinity", L"USER32.dll", patch_type::WDA_NONE_,
        std::vector<uint8_t>{0x48, 0x85, 0xD2, 0x74, 0x06, 0xC7, 0x02, 0x00, 0x00, 0x00, 0x00, 0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3},
        & status.orig_bytes.window_display_affinity_bytes,
        & status.orig_bytes.window_display_affinity_address, 6);

    /*configs.emplace_back("GetFileVersionInfoA", L"VERSION.dll", patch_type::RETURN_FALSE,
        std::vector<uint8_t>{0x33, 0xC0, 0xC3},
        & status.orig_bytes.get_file_version_info_a_bytes,
        & status.orig_bytes.get_file_version_info_a_address, 6);

    configs.emplace_back("GetFileVersionInfoSizeA", L"VERSION.dll", patch_type::RETURN_FALSE,
        std::vector<uint8_t>{0x33, 0xC0, 0xC3},
        & status.orig_bytes.get_file_version_info_size_a_bytes,
        & status.orig_bytes.get_file_version_info_size_a_address, 6);*/

    configs.emplace_back("GetModuleHandleA", L"KERNEL32.dll", patch_type::RETURN_FALSE,
        std::vector<uint8_t>{0x48, 0x31, 0xC0, 0xC3},
        & status.orig_bytes.get_module_handle_a_bytes,
        & status.orig_bytes.get_module_handle_a_address, 6);

    configs.emplace_back("GetModuleHandleW", L"KERNEL32.dll", patch_type::RETURN_FALSE,
        std::vector<uint8_t>{0x48, 0x31, 0xC0, 0xC3},
        & status.orig_bytes.get_module_handle_w_bytes,
        & status.orig_bytes.get_module_handle_w_address, 6);

    configs.emplace_back("GetModuleHandleExA", L"KERNEL32.dll", patch_type::RETURN_FALSE,
        std::vector<uint8_t>{0x33, 0xC0, 0xC3},
        & status.orig_bytes.get_module_handle_ex_a_bytes,
        & status.orig_bytes.get_module_handle_ex_a_address, 6);

    configs.emplace_back("GetModuleHandleExW", L"KERNEL32.dll", patch_type::RETURN_FALSE,
        std::vector<uint8_t>{0x33, 0xC0, 0xC3},
        & status.orig_bytes.get_module_handle_ex_w_bytes,
        & status.orig_bytes.get_module_handle_ex_w_address, 6);

    configs.emplace_back("GetModuleFileNameA", L"KERNEL32.dll", patch_type::RETURN_FALSE,
        std::vector<uint8_t>{0x33, 0xC0, 0xC3},
        & status.orig_bytes.get_module_filename_a_bytes,
        & status.orig_bytes.get_module_filename_a_address, 6);

    configs.emplace_back("GetModuleFileNameW", L"KERNEL32.dll", patch_type::RETURN_FALSE,
        std::vector<uint8_t>{0x33, 0xC0, 0xC3},
        & status.orig_bytes.get_module_filename_w_bytes,
        & status.orig_bytes.get_module_filename_w_address, 6);

    configs.emplace_back("K32GetModuleFileNameExA", L"KERNEL32.dll", patch_type::RETURN_FALSE,
        std::vector<uint8_t>{0x33, 0xC0, 0xC3},
        & status.orig_bytes.k32_get_module_filename_ex_a_bytes,
        & status.orig_bytes.k32_get_module_filename_ex_a_address, 6);

    configs.emplace_back("K32GetModuleBaseNameA", L"KERNEL32.dll", patch_type::RETURN_FALSE,
        std::vector<uint8_t>{0x33, 0xC0, 0xC3},
        & status.orig_bytes.k32_get_module_base_name_a_bytes,
        & status.orig_bytes.k32_get_module_base_name_a_address, 6);

    // You can find this by loading nvd3dumx.dll in IDA and searching for 'chrome.exe' or 'firefox.exe'
    configs.emplace_back("NvD3DUmx_BrowserDetect", L"nvd3dumx.dll",
        "4C 8B DC 55 53 49 8D AB 68 FF",
        patch_type::CUSTOM_PATCH,
        std::vector<uint8_t>{0xC3}, // Simple RET instruction
        & status.orig_bytes.nvd3dumx_signature_bytes,
        & status.orig_bytes.nvd3dumx_signature_address, 10);

    return configs;
}

int patch_common_functions(HANDLE h_process, patch_status& status) {
    auto configs = get_patch_configs(status);
    int result = 0;

    for (const auto& config : configs) {
        if (apply_patch(h_process, status, config) != 0) {
            result = 1; // At least one patch failed, but continue with others
        }
    }

    return result;
}

bool undo_patches(patch_status& status, const std::string& config_path) {
    // Try to load patch info if not available in memory
    if (!status.undo_available && status.orig_bytes.process_id == 0) {
        if (!load_patch_info(status.orig_bytes, config_path)) {
            add_log(status, "No patch information available to undo", patch_status::log_level::WARNING);
            return false;
        }
    }

    // Check if the original process is still running
    if (!is_process_running(status.orig_bytes.process_id)) {
        add_log(status, "Original patched process is no longer running", patch_status::log_level::WARNING);
        delete_patch_info(config_path);
        status.undo_available = false;
        return false;
    }

    HANDLE h_process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, status.orig_bytes.process_id);
    if (!h_process) {
        add_log(status, "Could not open process for undo operation", patch_status::log_level::ERR);
        return false;
    }

    bool success = true;

    // Define a helper macro
#define RESTORE_PATCH(func_name, display_name) \
        if (status.orig_bytes.func_name##_address != 0 && !status.orig_bytes.func_name##_bytes.empty()) { \
            if (!restore_original_bytes(h_process, status.orig_bytes.func_name##_address, status.orig_bytes.func_name##_bytes)) { \
                add_log(status, "Failed to restore " display_name, patch_status::log_level::ERR); \
                success = false; \
            } else { \
                add_log(status, "Successfully restored " display_name, patch_status::log_level::SUCCESS); \
            } \
        }

    // Restore common patches with proper names
    RESTORE_PATCH(open_process, "OpenProcess");
    RESTORE_PATCH(window_display_affinity, "GetWindowDisplayAffinity");
    RESTORE_PATCH(process32_first_w, "Process32FirstW");
    RESTORE_PATCH(process32_next_w, "Process32NextW");
    RESTORE_PATCH(module32_first_w, "Module32FirstW");
    RESTORE_PATCH(module32_next_w, "Module32NextW");
    RESTORE_PATCH(enum_windows, "EnumWindows");
    RESTORE_PATCH(get_window_info, "GetWindowInfo");
    RESTORE_PATCH(enum_modules, "K32EnumProcessModules");
    // RESTORE_PATCH(get_file_version_info_a, "GetFileVersionInfoA");
    // RESTORE_PATCH(get_file_version_info_size_a, "GetFileVersionInfoSizeA");
    RESTORE_PATCH(get_module_handle_a, "GetModuleHandleA");
    RESTORE_PATCH(get_module_handle_w, "GetModuleHandleW");
    RESTORE_PATCH(get_module_handle_ex_a, "GetModuleHandleExA");
    RESTORE_PATCH(get_module_handle_ex_w, "GetModuleHandleExW");
    RESTORE_PATCH(get_module_filename_a, "GetModuleFileNameA");
    RESTORE_PATCH(get_module_filename_w, "GetModuleFileNameW");
    RESTORE_PATCH(k32_get_module_filename_ex_a, "K32GetModuleFileNameExA");
    RESTORE_PATCH(k32_get_module_base_name_a, "K32GetModuleBaseNameA");
    RESTORE_PATCH(nvd3dumx_signature, "NvD3DUmx_BrowserDetect");

#undef RESTORE_PATCH

    CloseHandle(h_process);

    if (success) {
        status.undo_available = false;
        status.is_patched = false;
        delete_patch_info(config_path);
        add_log(status, "All patches successfully reverted", patch_status::log_level::SUCCESS);
    }

    return success;
}

// Worker thread function to apply patches
void patching_thread(patch_status* status, const std::string& config_path) {
    while (status->is_running) {
        // Only proceed if auto-patch is enabled or manual patch was requested
        if (!status->auto_patch && !status->manual_patch_requested) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue;
        }

        if (status->wait_for_process) {
            // Check for nvcontainer.exe process
            std::vector<DWORD> process_ids = get_processes_by_name(L"nvcontainer.exe");

            if (process_ids.empty()) {
                if (status->auto_patch) {
                    status->status_message = "Waiting for nvcontainer.exe...";
                }
                else {
                    status->status_message = "Ready - nvcontainer.exe not found";
                }
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
                if (status->auto_patch) {
                    status->status_message = "Waiting for nvcontainer.exe with nvd3dumx.dll...";
                }
                else {
                    status->status_message = "Ready - nvcontainer.exe found but nvd3dumx.dll not loaded";
                }
                std::this_thread::sleep_for(std::chrono::seconds(1));
                continue;
            }

            // Found the process
            status->wait_for_process = false;
            DWORD nvcontainer_process_id = filtered_process_ids[0];
            status->target_process_id = nvcontainer_process_id;

            /*
                Check if this process is already patched, if we don't do this and have auto-patch on launch selected
                ...while it's already patched, it's gonna have an infinite loop of trying to patch the nvidia process
            */
            if (status->orig_bytes.process_id == nvcontainer_process_id && status->is_patched) {
                add_log(*status, "Cancelling the patch operation", patch_status::log_level::INFO);
                status->manual_patch_requested = false;

                // Auto close if requested
                if (status->auto_close)
                    status->is_running = false;

                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                continue;
            }

            add_log(*status, "Correct process found. PID: " + std::to_string(nvcontainer_process_id), patch_status::log_level::SUCCESS);

            // Open the process
            HANDLE h_process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, nvcontainer_process_id);
            if (!h_process) {
                add_log(*status, "Could not open process", patch_status::log_level::ERR);
                status->is_patched = false;
                status->wait_for_process = true;
                status->manual_patch_requested = false;
                continue;
            }

            // Apply patches using the new unified system
            add_log(*status, "Starting to apply patches...", patch_status::log_level::INFO);

            // Apply common patches (process/window enumeration)
            int error_code = patch_common_functions(h_process, *status);
            if (error_code) {
                add_log(*status, "Failed to apply patches", patch_status::log_level::ERR);
                CloseHandle(h_process);
                status->is_patched = false;
                status->wait_for_process = true;
                status->manual_patch_requested = false;
                continue;
            }

            CloseHandle(h_process);

            // Save patch information for persistence
            save_patch_info(status->orig_bytes, config_path);

            add_log(*status, "All patches applied successfully!", patch_status::log_level::SUCCESS);
            status->is_patched = true;
            status->undo_available = true;
            status->manual_patch_requested = false;

            // Auto close if requested
            if (status->auto_close)
                status->is_running = false;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

void apply_style(bool dark_mode) {
    auto& style = ImGui::GetStyle();

    // Layout settings
    style.WindowPadding = { 10.f, 10.f };
    style.PopupRounding = 3.f;
    style.FramePadding = { 8.f, 4.f };
    style.ItemSpacing = { 10.f, 8.f };
    style.ItemInnerSpacing = { 6.f, 6.f };
    style.IndentSpacing = 21.f;
    style.ScrollbarSize = 15.f;
    style.GrabMinSize = 8.f;
    style.WindowBorderSize = 1.f;
    style.ChildBorderSize = 0.f;
    style.PopupBorderSize = 1.f;
    style.FrameBorderSize = 0.f;
    style.TabBorderSize = 0.f;
    style.WindowRounding = 3.f;
    style.ChildRounding = 3.f;
    style.FrameRounding = 3.f;
    style.ScrollbarRounding = 3.f;
    style.GrabRounding = 3.f;
    style.TabRounding = 3.f;
    style.WindowTitleAlign = { 0.5f, 0.5f };
    style.ButtonTextAlign = { 0.5f, 0.5f };
    style.DisplaySafeAreaPadding = { 3.f, 3.f };

    auto& colors = style.Colors;

    if (dark_mode) {
        // Dark theme colors (original)
        colors[ImGuiCol_Text] = ImVec4(1.00f, 1.00f, 1.00f, 1.00f);
        colors[ImGuiCol_TextDisabled] = ImVec4(0.50f, 0.50f, 0.50f, 1.00f);
        colors[ImGuiCol_WindowBg] = ImVec4(0.06f, 0.06f, 0.06f, 1.00f);
        colors[ImGuiCol_PopupBg] = ImVec4(0.08f, 0.08f, 0.08f, 0.94f);
        colors[ImGuiCol_FrameBg] = ImVec4(0.21f, 0.21f, 0.21f, 0.54f);
        colors[ImGuiCol_FrameBgHovered] = ImVec4(0.21f, 0.21f, 0.21f, 0.78f);
        colors[ImGuiCol_FrameBgActive] = ImVec4(0.28f, 0.27f, 0.27f, 0.54f);
        colors[ImGuiCol_TitleBg] = ImVec4(0.17f, 0.17f, 0.17f, 1.00f);
        colors[ImGuiCol_TitleBgActive] = ImVec4(0.19f, 0.19f, 0.19f, 1.00f);
        colors[ImGuiCol_Button] = ImVec4(0.41f, 0.41f, 0.41f, 0.74f);
        colors[ImGuiCol_ButtonHovered] = ImVec4(0.41f, 0.41f, 0.41f, 0.78f);
        colors[ImGuiCol_ButtonActive] = ImVec4(0.41f, 0.41f, 0.41f, 0.87f);
        colors[ImGuiCol_Border] = ImVec4(0.30f, 0.30f, 0.30f, 0.50f);
        colors[ImGuiCol_CheckMark] = ImVec4(1.00f, 1.00f, 1.00f, 1.00f);
        colors[ImGuiCol_SliderGrab] = ImVec4(0.34f, 0.34f, 0.34f, 1.00f);
        colors[ImGuiCol_SliderGrabActive] = ImVec4(0.39f, 0.38f, 0.38f, 1.00f);
        colors[ImGuiCol_Header] = ImVec4(0.37f, 0.37f, 0.37f, 0.31f);
        colors[ImGuiCol_HeaderHovered] = ImVec4(0.38f, 0.38f, 0.38f, 0.37f);
        colors[ImGuiCol_HeaderActive] = ImVec4(0.37f, 0.37f, 0.37f, 0.51f);
    }
    else {
        // Light theme colors (improved with better checkboxes)
        colors[ImGuiCol_Text] = ImVec4(0.15f, 0.15f, 0.15f, 1.00f);
        colors[ImGuiCol_TextDisabled] = ImVec4(0.60f, 0.60f, 0.60f, 1.00f);
        colors[ImGuiCol_WindowBg] = ImVec4(0.98f, 0.98f, 0.98f, 0.95f);
        colors[ImGuiCol_PopupBg] = ImVec4(1.00f, 1.00f, 1.00f, 0.98f);
        colors[ImGuiCol_FrameBg] = ImVec4(0.88f, 0.88f, 0.88f, 1.00f);
        colors[ImGuiCol_FrameBgHovered] = ImVec4(0.82f, 0.82f, 0.82f, 1.00f);
        colors[ImGuiCol_FrameBgActive] = ImVec4(0.76f, 0.76f, 0.76f, 1.00f);
        colors[ImGuiCol_TitleBg] = ImVec4(0.92f, 0.92f, 0.92f, 1.00f);
        colors[ImGuiCol_TitleBgActive] = ImVec4(0.88f, 0.88f, 0.88f, 1.00f);
        colors[ImGuiCol_Button] = ImVec4(0.85f, 0.85f, 0.85f, 1.00f);
        colors[ImGuiCol_ButtonHovered] = ImVec4(0.75f, 0.75f, 0.75f, 1.00f);
        colors[ImGuiCol_ButtonActive] = ImVec4(0.65f, 0.65f, 0.65f, 1.00f);
        colors[ImGuiCol_Border] = ImVec4(0.60f, 0.60f, 0.60f, 0.80f);
        colors[ImGuiCol_CheckMark] = ImVec4(0.20f, 0.20f, 0.20f, 1.00f);
        colors[ImGuiCol_SliderGrab] = ImVec4(0.55f, 0.55f, 0.55f, 1.00f);
        colors[ImGuiCol_SliderGrabActive] = ImVec4(0.40f, 0.40f, 0.40f, 1.00f);
        colors[ImGuiCol_Header] = ImVec4(0.78f, 0.78f, 0.78f, 0.31f);
        colors[ImGuiCol_HeaderHovered] = ImVec4(0.72f, 0.72f, 0.72f, 0.37f);
        colors[ImGuiCol_HeaderActive] = ImVec4(0.68f, 0.68f, 0.68f, 0.51f);
    }

    // Common colors
    colors[ImGuiCol_BorderShadow] = ImVec4(0.00f, 0.00f, 0.00f, 0.00f);
}

std::string get_config_path() {
    char path[MAX_PATH];

    // Get the AppData\Roaming folder path
    if (GetEnvironmentVariableA("APPDATA", path, MAX_PATH) == 0) {
        // Fallback to current directory if APPDATA is not available
        GetModuleFileNameA(NULL, path, MAX_PATH);
        std::string dir(path);
        size_t pos = dir.find_last_of("\\/");
        std::string exe_dir = (pos != std::string::npos) ? dir.substr(0, pos + 1) : "";
        return exe_dir + DEFAULT_CONFIG_FILENAME;
    }

    std::string appdata_path(path);

    // Ensure path ends with backslash
    if (!appdata_path.empty() && appdata_path.back() != '\\') {
        appdata_path += "\\";
    }

    // Create a subdirectory
    appdata_path += "NoShadowPlayBS\\";
    CreateDirectoryA(appdata_path.c_str(), NULL);

    return appdata_path + DEFAULT_CONFIG_FILENAME;
}

// Initialize or repair settings that affect Windows
void init_autostart_settings(Config& config, patch_status& status, const std::string& config_path) {
    auto sync_setting = [&](auto& config_setting, auto actual_state) {
        if (config_setting != actual_state) {
            config_setting = actual_state;
            config.Save(config_path.c_str());
        }
        };

    sync_setting(config.startup_enabled, is_startup_enabled());
    sync_setting(config.start_menu_enabled, is_start_menu_enabled());

    status.startup_enabled = config.startup_enabled;
    status.start_menu_enabled = config.start_menu_enabled;
}

// WinMain - the Windows entry point
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
    // Check if running as administrator
    if (!is_running_as_administrator()) {
        MessageBoxA(NULL, "This program requires administrator privileges to run.\nPlease run as administrator and try again.", "Administrator Rights Required", MB_OK | MB_ICONERROR);
        return false;
    }

    // Verify that there is only one instance of our program
    if (is_another_instance_running()) {
        MessageBoxA(NULL, "Another instance of this program is already running.\nPlease close the other instance first.", "Multiple Instances Detected", MB_OK | MB_ICONINFORMATION);
        return false;
    }

    // Path
    std::string config_path = get_config_path();

    // Directory
    size_t pos = config_path.find_last_of("\\/");
    std::string config_dir = (pos != std::string::npos) ? config_path.substr(0, pos + 1) : "";

    // Load configuration
    Config config;
    config.Load(config_path.c_str());

    // Initialize status from config
    patch_status status;
    status.startup_enabled = config.startup_enabled;
    status.start_menu_enabled = config.start_menu_enabled;
    status.hide_log_window = config.hide_log_window;
    status.dark_mode = config.dark_mode;
    status.auto_close = config.auto_close;
    status.auto_patch = config.auto_patch;

    // Verify actual states of startup/start_menu and update config if needed
    init_autostart_settings(config, status, config_path);

    // Check for existing patch info
    if (load_patch_info(status.orig_bytes, config_path)) {
        if (is_process_running(status.orig_bytes.process_id)) {
            status.undo_available = true;
            status.is_patched = true;
            status.target_process_id = status.orig_bytes.process_id;
            add_log(status, "Found existing patch information for process ID: " + std::to_string(status.orig_bytes.process_id), patch_status::log_level::INFO);
        }
        else {
            delete_patch_info(config_path);
            add_log(status, "Found stale patch information - process no longer running", patch_status::log_level::WARNING);
        }
    }

    if (config.no_gui)
    {
        // Non-GUI mode (if still needed for debugging)
        patching_thread(&status, config_path);
        return 0;
    }

    // Initialize window
    WNDCLASSEX wc = {
        sizeof(WNDCLASSEX),
        CS_CLASSDC,
        wnd_proc,
        0L,
        0L,
        hInstance,
        LoadIcon(hInstance, MAKEINTRESOURCE(IDI_ICON1)), // Main icon
        LoadCursor(NULL, IDC_ARROW),
        (HBRUSH)(COLOR_WINDOW + 1),
        NULL,
        _T("NVIDIA Patcher"),
        LoadIcon(hInstance, MAKEINTRESOURCE(IDI_ICON1)) // Small icon
    };

    RegisterClassEx(&wc);
    HWND hwnd = CreateWindow(wc.lpszClassName, _T("NVIDIA Patcher"),
        WS_OVERLAPPEDWINDOW, // Now resizable and movable
        100, 100, 700, 550, NULL, NULL, wc.hInstance, NULL);

    LoadIcon(hInstance, MAKEINTRESOURCE(IDI_ICON1));

    // Apply dark theme BEFORE showing the window
    apply_native_titlebar_style(hwnd, status.dark_mode);

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

    // Write the imgui.ini to the program's directory
    std::string imgui_path = config_dir + "imgui.ini";
    io.IniFilename = imgui_path.c_str();

    // Setup style
    apply_style(status.dark_mode);

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
    std::thread worker_thread(patching_thread, &status, config_path);

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
        ImGui::SetNextWindowSize(io.DisplaySize);
        ImGui::Begin("NVIDIA Patcher", &status.is_running,
            ImGuiWindowFlags_NoTitleBar |
            ImGuiWindowFlags_NoResize |
            ImGuiWindowFlags_NoMove |
            ImGuiWindowFlags_NoCollapse |
            ImGuiWindowFlags_NoBringToFrontOnFocus);

        // Header with version and status
        ImGui::Text("NVIDIA Patcher v%s", VERSION);

        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("This tool is intended for educational and security research purposes only.");
        
        // Copyright tooltip indicator
        ImGui::SameLine(ImGui::GetWindowWidth() - 25); // Right-align
        ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.6f, 0.7f), "(?)");
        if (ImGui::IsItemHovered()) {
            ImGui::BeginTooltip();
            ImGui::PushTextWrapPos(ImGui::GetFontSize() * 25.0f); // Nice text wrapping
            ImGui::TextUnformatted(COPYRIGHT_INFO);
            ImGui::PopTextWrapPos();
            ImGui::EndTooltip();
        }

        ImGui::Separator();

        // Status panel
        ImGui::BeginChild("StatusPanel", ImVec2(0, 60), true);

        // Display current status with colored indicators
        ImGui::Text("Status: ");
        ImGui::SameLine();

        // Main status message (top section)
        if (status.is_patched) {
            ImGui::TextColored(ImVec4(0.0f, 1.0f, 0.0f, 1.0f), "Patched Successfully");
        }
        else if (status.manual_patch_requested) {
            ImGui::TextColored(ImVec4(0.0f, 0.75f, 1.0f, 1.0f), "Patching...");

            if (ImGui::IsItemHovered())
                ImGui::SetTooltip("Make sure Instant Replay is enabled in the NVIDIA Overlay");
        }
        else if (status.wait_for_process && status.auto_patch) {
            ImGui::TextColored(ImVec4(1.0f, 0.65f, 0.1f, 1.0f), "Waiting for NVIDIA process...");
        }
        else {
            // Ready state - only show error if there was one
            if (!status.status_message.empty() && status.status_message.find("Failed") != std::string::npos) {
                ImGui::TextColored(ImVec4(1.0f, 0.0f, 0.0f, 1.0f), status.status_message.c_str());
            }
            else {
                ImGui::TextColored(ImVec4(0.7f, 0.7f, 0.7f, 1.0f), "Ready");
            }
        }

        // Process status section (more technical details)
        ImGui::Text("Process: ");
        ImGui::SameLine();
        if (status.target_process_id != 0) {
            ImGui::TextColored(ImVec4(0.0f, 1.0f, 0.0f, 1.0f), "Targeting PID: %u", status.target_process_id);
        }
        else {
            // Only show additional status if not covered by main status
            if (!status.manual_patch_requested && !status.wait_for_process) {
                ImGui::TextColored(ImVec4(0.7f, 0.7f, 0.7f, 1.0f), "Not connected");
            }

            // Add tooltip with more details
            if (ImGui::IsItemHovered()) {
                ImGui::BeginTooltip();
                if (status.manual_patch_requested) {
                    ImGui::Text("Searching for NVIDIA container...");
                }
                else if (status.wait_for_process && status.auto_patch) {
                    ImGui::Text("Automatically scanning for process");
                }
                else {
                    ImGui::Text("Press 'Patch Now' to begin");
                }
                ImGui::EndTooltip();
            }
        }

        ImGui::EndChild();

        // Settings checkboxes
        ImGui::BeginChild("ControlsPanel", ImVec2(0, 115), true);

        if (ImGui::Checkbox("Auto-Patch on Launch", &status.auto_patch))
        {
            config.auto_patch = status.auto_patch;
            config.Save(config_path.c_str());
        }

        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("This will automatically start the patching process once the program is opened");

        ImGui::SameLine();

        if (ImGui::Checkbox("Auto-Close After Patching", &status.auto_close))
        {
            config.auto_close = status.auto_close;
            config.Save(config_path.c_str());
        }

        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("This will automatically close the program when patching is finished");

        ImGui::SameLine();
        
        if (ImGui::Checkbox("Run at Windows Startup", &status.startup_enabled))
        {
            config.startup_enabled = status.startup_enabled;
            config.Save(config_path.c_str());
            set_startup(status.startup_enabled);
        }

        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("This will make the program automatically run at Windows startup");

        if (ImGui::Checkbox("Add to Start Menu", &status.start_menu_enabled))
        {
            config.start_menu_enabled = status.start_menu_enabled;
            config.Save(config_path.c_str());
            set_start_menu_shortcut(status.start_menu_enabled);
        }

        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("This will add a shortcut to the program in your Start Menu");

        ImGui::SameLine();

        if (ImGui::Checkbox("Hide Log Window", &status.hide_log_window))
        {
            config.hide_log_window = status.hide_log_window;
            config.Save(config_path.c_str());
        }

        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("This will hide the 'Detailed Log' region from the GUI");

        ImGui::SameLine();

        if (ImGui::Checkbox("Enable Dark Theme", &status.dark_mode))
        {
            config.dark_mode = status.dark_mode;
            config.Save(config_path.c_str());
            apply_native_titlebar_style(hwnd, status.dark_mode);
            apply_style(status.dark_mode);
        }

        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("This will change the theme look of the program");

        // Main action buttons
        if (ImGui::Button("Patch Now", ImVec2(100, 30)) && !status.is_patched) {
            status.manual_patch_requested = true;
            status.wait_for_process = true;
            add_log(status, "Manual patch requested", patch_status::log_level::INFO);
        }

        ImGui::SameLine();

        // Only show Undo button if there are patches to undo
        if (status.undo_available || status.is_patched) {
            if (ImGui::Button("Undo Patches", ImVec2(120, 30))) {
                undo_patches(status, config_path);
            }
            ImGui::SameLine();
        }

        if (ImGui::Button("Close", ImVec2(100, 30))) {
            status.is_running = false;
        }

        ImGui::EndChild();

        // Show logs based on the user's choice
        if (!status.hide_log_window)
        {
            // Log display with title
            ImGui::Text("Detailed Log:");
            ImGui::BeginChild("LogRegion", ImVec2(0, 0), true,
                ImGuiWindowFlags_HorizontalScrollbar |
                ImGuiWindowFlags_AlwaysVerticalScrollbar);

            // Display placeholder when empty
            if (status.detailed_log.empty()) {
                ImGui::Text("Log is empty - patch activity will appear here");
            }
            else {
                // Display log text
                ImGui::PushTextWrapPos(0.0f); // Enable text wrapping
                ImGui::TextUnformatted(status.detailed_log.c_str());
                ImGui::PopTextWrapPos();
            }

            // Auto-scroll to keep up with new log entries
            if (ImGui::GetScrollY() >= ImGui::GetScrollMaxY() - 20)
            {
                ImGui::SetScrollHereY(1.0f);
            }

            ImGui::EndChild();
        }

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