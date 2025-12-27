[Setup]
AppName=SimpleFix
AppVersion=1.0
DefaultDirName={pf}\SimpleFix
DefaultGroupName=SimpleFix
OutputDir=dist
OutputBaseFilename=SimpleFixInstaller
Compression=lzma
SolidCompression=yes

[Files]
Source: "dist\simplefix.exe"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\SimpleFix"; Filename: "{app}\simplefix.exe"
Name: "{commondesktop}\SimpleFix"; Filename: "{app}\simplefix.exe"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional icons:"
