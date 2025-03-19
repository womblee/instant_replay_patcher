#pragma once
#include <string>

struct Config
{
    bool no_gui = false; // This might still be useful for debugging or headless mode
    bool startup_enabled = false;
    bool auto_close = false;

    void Load(const std::string& filename);
    void Save(const std::string& filename);
};