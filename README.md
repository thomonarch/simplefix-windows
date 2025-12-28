 ____  _                 _      _____ _      
/ ___|(_)_ __ ___  _ __ | | ___|  ___(_)_  __
\___ \| | '_ ` _ \| '_ \| |/ _ \ |_  | \ \/ /
 ___) | | | | | | | |_) | |  __/  _| | |>  < 
|____/|_|_| |_| |_| .__/|_|\___|_|   |_/_/\_\
                  |_|    
SimpleFix for Windows
SimpleFix is a lightweight Windows maintenance tool that brings together common repair actions, cleanup tasks, and a balanced debloat option. The goal is to provide a clear, safe, and straightforward utility without unnecessary features or noise.

Features
System Repair
Reset Windows Update components

Run SFC and DISM repairs

Flush DNS and network caches

Restore essential Windows services

Balanced Debloat
A safe, minimal debloat option that removes unnecessary preinstalled apps while keeping core Windows features intact. No aggressive removals and no risky changes.

One‑Click Utilities
Clear temporary files

Reset Microsoft Store

Restart Explorer

Rebuild icon cache

Restart networking

Interface
Built with Python and CustomTkinter

Simple, clean layout

No telemetry, ads, or background processes

Installation
Download the latest installer from the Releases page:

https://github.com/thomonarch/simplefix-windows/releases

Run SimpleFixInstaller.exe  and follow the prompts.

Requirements
Windows 10 or Windows 11

Administrator privileges for repair tools

Running from Source
Clone the repository:

git clone https://github.com/thomonarch/simplefix-windows.git
cd simplefix-windows

Create and activate a virtual environment:

python -m venv venv
venv\Scripts\activate

Install dependencies:

pip install -r requirements.txt

Run the application:

python simplefix.py

Building the Executable
py -m PyInstaller --onefile --noconsole simplefix.py

The executable will be created in:

dist/simplefix.exe

Installer
The project includes an Inno Setup script:

simplefix_installer.iss

Build it using:

ISCC.exe  simplefix_installer.iss

Project Philosophy
SimpleFix is built around three principles:

Safety — no destructive or irreversible actions

Clarity — every action is explained and predictable

Simplicity — one tool that replaces scattered commands

License
MIT License.
