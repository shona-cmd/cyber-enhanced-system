## Installation Instructions

### Standard Installation (Cross-Platform)

1.  Download the latest version of the software from [https://github.com/your-username/your-repo/releases](https://github.com/your-username/your-repo/releases).
2.  Extract the downloaded archive to a directory of your choice.
3.  Navigate to the extracted directory in your terminal.
4.  Run `pip install -r requirements.txt` to install the necessary dependencies.
5.  Run `python app.py` to start the application.

### Building Standalone Executable (Windows)

For users who prefer a standalone executable that can be installed on any Windows device without requiring Python:

1.  Ensure you have Python installed on your development machine.
2.  Install the dependencies: `pip install -r requirements.txt`
3.  Run the build script: `python build_exe.py`
4.  The executable `naashon-iot.exe` will be created in the `dist/` directory.
5.  Distribute the `naashon-iot.exe` file to target Windows devices.
6.  On the target device, simply double-click the `.exe` file to run the application. No additional installation required.

**Note:** The standalone executable includes all necessary dependencies and can run on any Windows device (Windows 7 SP1 and later) without requiring Python to be installed.
