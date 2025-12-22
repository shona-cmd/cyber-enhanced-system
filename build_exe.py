#!/usr/bin/env python3
"""
Build script to create a standalone executable for NaashonSecureIoT using PyInstaller.
This script generates a single .exe file that can be installed on any Windows device.
"""

import os
import sys
import subprocess
import shutil

def build_exe():
    """Build the executable using PyInstaller."""
    print("Building NaashonSecureIoT executable...")

    # Ensure we're in the correct directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(script_dir)

    # PyInstaller command
    cmd = [
        sys.executable, "-m", "pyinstaller",
        "--onefile",  # Create a single executable file
        "--name", "naashon-iot",  # Name of the executable
        "--clean",  # Clean cache and temporary files
        "--noconfirm",  # Replace output directory without confirmation
        "naashon_secure_iot/core.py"  # Entry point script
    ]

    try:
        # Run PyInstaller
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
        print("PyInstaller completed successfully!")
        print(result.stdout)

        # Check if exe was created
        exe_path = os.path.join("dist", "naashon-iot.exe")
        if os.path.exists(exe_path):
            print(f"Executable created successfully: {exe_path}")
            print("The exe file can now be distributed and installed on any Windows device.")
        else:
            print("Warning: Executable not found in expected location.")

    except subprocess.CalledProcessError as e:
        print(f"Error building executable: {e}")
        print(f"stdout: {e.stdout}")
        print(f"stderr: {e.stderr}")
        return False
    except FileNotFoundError:
        print("PyInstaller not found. Please install it with: pip install PyInstaller")
        return False

    return True

if __name__ == "__main__":
    success = build_exe()
    sys.exit(0 if success else 1)
