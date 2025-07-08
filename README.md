# NVIDIA Patcher - Shadowplay Recording Restriction Bypass

A lightweight tool that enables NVIDIA Shadowplay to record content normally flagged as "restricted" by bypassing NVIDIA's content detection mechanisms.

![image](https://github.com/user-attachments/assets/1ab41da7-0ef1-4158-b122-857159cca709)

![image](https://github.com/user-attachments/assets/a75dae0b-321e-41c7-bc0f-f47d9f805711)

## Key Features
- **Automatic Detection**: Monitors and automatically patches the NVIDIA Container process (nvcontainer.exe)
- **List of patched functions**:
  - `OpenProcess`
  - `Process32FirstW`
  - `Process32NextW`
  - `Module32FirstW`
  - `Module32NextW`
  - `K32EnumProcessModules`
  - `EnumWindows`
  - `GetWindowInfo`
  - `GetWindowDisplayAffinity`
  - `GetFileVersionInfoA`
  - `GetFileVersionInfoSizeA`
  - `GetModuleHandleA`
  - `GetModuleHandleW`
  - `GetModuleHandleExA`
  - `GetModuleHandleExW`
  - `GetModuleFileNameA`
  - `GetModuleFileNameW`
  - `K32GetModuleFileNameExA`
  - `K32GetModuleBaseNameA`
  - `NvD3DUmx_BrowserDetect`
- **Patch Now**:
  - You can patch out the NVIDIA restrictions just with a press of a button!
- **Undo Patches**:
  - Revert the patches back to normal (only works for one session).
- **Options**:
  - Auto-patch on launch
  - Auto-close after successful patching option.
  - Run at Windows startup.
- **Minimalist Interface**: Clean, Dark-themed UI with easy-to-use controls.

## Usage
1. Download and run the `.exe` from Releases tab.
2. The tool will automatically detect and patch NVIDIA processes.
3. Configure settings as desired.
4. Click 'Patch Now' for patch to be applied.
5. Check the log window for patching status and details.

## Technical Details
This tool works by injecting memory patches into NVIDIA's container process, specifically targeting the functions that detect protected content. By bypassing these detection mechanisms, Shadowplay can record content from applications that would normally trigger the "Recording is not available due to restricted content" error.

## Credits
This project builds upon the foundation of [ShadowPlay_Patcher by furyzenblade](https://github.com/furyzenblade/ShadowPlay_Patcher), introducing a cleaner architecture, enhanced stability, an intuitive UI, and multiple additional patches to fully bypass NVIDIA Instant Replay protection mechanisms.

Make sure to check it out, I wouldn't have made this program without their research!
