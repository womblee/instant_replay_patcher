#pragma once
#include <string>

#define DEFAULT_CONFIG_FILENAME "config.ini"

struct Config {
    bool no_gui = false;
    bool startup_enabled = false;
    bool start_menu_enabled = false;
    bool hide_log_window = false;
    bool dark_mode = true;
    bool auto_close = false;
    bool auto_patch = false;

    bool Load(const std::string& filename = "");
    bool Save(const std::string& filename = "") const;
    void SetDefaults();
};