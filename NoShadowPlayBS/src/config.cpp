#include "config.h"
#include <INIReader/cpp/INIReader.h>
#include <Windows.h>

void Config::Load(const std::string& filename)
{
    INIReader reader(filename);

    if (reader.ParseError() < 0)
    {
        no_gui = false;
        startup_enabled = false;
        auto_close = false;

        return;
    }

    no_gui = reader.GetBoolean("Settings", "no_gui", false);
    startup_enabled = reader.GetBoolean("Settings", "startup_enabled", false);
    auto_close = reader.GetBoolean("Settings", "auto_close", false);
}

void Config::Save(const std::string& filename)
{
    FILE* file = nullptr;
    errno_t err = fopen_s(&file, filename.c_str(), "w");

    if (err != 0 || !file)
    {
        // Handle error
        MessageBoxA(NULL, "Failed to save configuration file!", "Error", MB_ICONERROR);
        return;
    }

    fprintf(file, "[Settings]\n");
    fprintf(file, "no_gui=%s\n", no_gui ? "true" : "false");
    fprintf(file, "startup_enabled=%s\n", startup_enabled ? "true" : "false");
    fprintf(file, "auto_close=%s\n", auto_close ? "true" : "false");

    fclose(file);
}