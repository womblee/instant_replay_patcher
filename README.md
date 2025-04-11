# NVIDIA Patcher - Shadowplay Recording Restriction Bypass

A lightweight tool that enables NVIDIA Shadowplay to record content normally flagged as "restricted" by bypassing NVIDIA's content detection mechanisms.

![NVIDIA_Overlay_Wealthy-Grouse_11 04 2025](https://github.com/user-attachments/assets/39dc7809-32ec-4fc6-b8f6-be52067e78b2)

![NVIDIA_Overlay_Closed-Hagfish_11 04 2025](https://github.com/user-attachments/assets/6722c535-24f9-44de-aea0-b7bf5f338935)

## Key Features
- **Automatic Detection**: Monitors and automatically patches the NVIDIA Container process (nvcontainer.exe)
- **Protection Bypasses**: 
  - Patches `GetWindowDisplayAffinity` to prevent screen content protection detection.
  - Patches `Module32FirstW` to prevent process scanning mechanisms.
- **Undo Patches**:
  - Revert the patches back to normal (only works for one session).
- **Options**:
  - Run at Windows startup option.
  - Auto-close after successful patching option.
- **Minimalist Interface**: Clean, Dark-themed UI with easy-to-use controls.

## Usage
1. Download and run the `.exe` from Releases tab.
2. The tool will automatically detect and patch NVIDIA processes.
3. Configure startup and auto-close settings as desired.
4. Check the log window for patching status and details.

## Technical Details
This tool works by injecting memory patches into NVIDIA's container process, specifically targeting the functions that detect protected content. By bypassing these detection mechanisms, Shadowplay can record content from applications that would normally trigger the "Recording is not available due to restricted content" error.

## Credits
This project builds upon and improves [ShadowPlay_Patcher by furyzenblade](https://github.com/furyzenblade/ShadowPlay_Patcher), implementing cleaner code and a user-friendly interface.

Make sure to check it out, it explains how this bypass works a lot better than here.
