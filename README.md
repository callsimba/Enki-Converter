![Screenshot 2024-11-03 190628](https://github.com/user-attachments/assets/72014d86-4d0b-4135-ab12-0d5810d3a314)

# Enki Converter

**Enki Converter** is a standalone tool designed to seamlessly convert `.EXE` files to `.DLL` and vice versa. It simplifies the conversion process, ensuring efficiency and reliability for developers. The tool is built using Python and features an easy-to-use GUI.

## Features

- **Convert `.EXE` to `.DLL`** and vice versa.
- **Optional Code Injection**: Allows you to inject code from `.o` or `.obj` files if desired.
- **Standalone GUI** with a simple and intuitive interface.
- **Customizable Colors and Styling**: Designed with a dark blue and gray theme.

## Requirements

- **Python** 3.7 or higher
- **Tkinter** (comes pre-installed with Python)
- **Pillow** (for image handling)
- **pefile** (for PE header modifications)

## Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/callsimba/Enki-Converter.git
   cd Enki-Converter


## Install dependencies:
```bash
pip install pillow pefile


Run the application:
```bash
python gui.py


## Usage
Launch the application by running gui.py.
Select File to Convert: Choose the .EXE or .DLL file you want to convert.
Optional Code Injection: If you have a code file (.o or .obj) to inject, select it. This step is optional.
Conversion Type: Choose the desired conversion type (EXE to DLL or DLL to EXE).
Click Convert. The converted file will be saved in the same directory as the original file with the appropriate extension.


## Project Structure
gui.py: Main application script with GUI and conversion logic.
requirements.txt: List of dependencies for the project.
icon.ico: Application icon.
logo.png: Logo displayed in the GUI.


## Building a Standalone Executable
To create a standalone executable using PyInstaller:
```bash
pyinstaller --onefile --noconsole --icon=icon.ico gui.py


## Contact
For questions, suggestions, or customization requests, feel free to reach out:

Telegram: @npx_react_native
website: www.callenki.com



