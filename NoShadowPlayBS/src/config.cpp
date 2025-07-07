#include "config.h"
#include <INIReader/cpp/INIReader.h>
#include <Windows.h>
#include <fstream>
#include <string_view>

namespace {
    constexpr std::string_view CONFIG_SECTION = "Settings";

    // Helper function to show error messages
    void ShowConfigError(const char* message) {
        MessageBoxA(nullptr, message, "Configuration Error", MB_ICONERROR | MB_OK);
    }
} // namespace

bool Config::Load(const std::string& filename) {
    INIReader reader(filename.empty() ? DEFAULT_CONFIG_FILENAME : filename);

    if (reader.ParseError() < 0) {
        // Only set defaults if file doesn't exist
        if (GetFileAttributesA(filename.c_str()) == INVALID_FILE_ATTRIBUTES) {
            SetDefaults();
            return false; // File doesn't exist is not an error case
        }

        ShowConfigError("Failed to parse configuration file. Using defaults.");
        SetDefaults();
        return false;
    }

    try {
        no_gui = reader.GetBoolean(CONFIG_SECTION.data(), "no_gui", no_gui);
        startup_enabled = reader.GetBoolean(CONFIG_SECTION.data(), "startup_enabled", startup_enabled);
        start_menu_enabled = reader.GetBoolean(CONFIG_SECTION.data(), "start_menu_enabled", start_menu_enabled);
        hide_log_window = reader.GetBoolean(CONFIG_SECTION.data(), "hide_log_window", hide_log_window);
        dark_mode = reader.GetBoolean(CONFIG_SECTION.data(), "dark_mode", dark_mode);
        auto_close = reader.GetBoolean(CONFIG_SECTION.data(), "auto_close", auto_close);
        auto_patch = reader.GetBoolean(CONFIG_SECTION.data(), "auto_patch", auto_patch);

        return true;
    }
    catch (const std::exception& e) {
        ShowConfigError(e.what());
        SetDefaults();
        return false;
    }
}

bool Config::Save(const std::string& filename) const {
    try {
        std::ofstream file(filename.empty() ? DEFAULT_CONFIG_FILENAME : filename);
        if (!file.is_open()) {
            throw std::runtime_error("Could not open file for writing");
        }

        file << "[" << CONFIG_SECTION << "]\n"
            << "no_gui=" << (no_gui ? "true" : "false") << "\n"
            << "startup_enabled=" << (startup_enabled ? "true" : "false") << "\n"
            << "start_menu_enabled=" << (start_menu_enabled ? "true" : "false") << "\n"
            << "hide_log_window=" << (hide_log_window ? "true" : "false") << "\n"
            << "dark_mode=" << (dark_mode ? "true" : "false") << "\n"
            << "auto_close=" << (auto_close ? "true" : "false") << "\n"
            << "auto_patch=" << (auto_patch ? "true" : "false") << "\n";

        return file.good();
    }
    catch (const std::exception& e) {
        ShowConfigError(e.what());
        return false;
    }
}

void Config::SetDefaults() {
    no_gui = false;
    startup_enabled = false;
    start_menu_enabled = false;
    hide_log_window = false;
    dark_mode = true; // Default to dark mode as it's more common
    auto_close = false;
    auto_patch = false;
}