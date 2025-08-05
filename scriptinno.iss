; Arkive Inno Setup Script - Final
#define MyAppName "Arkive"
#define MyAppVersion "1.5"
#define MyAppPublisher "ANAN AZMAYEEN"
#define MyAppURL "https://www.arkivetool.com"
#define MyAppExeName "arkive.exe"

[Setup]
AppId={{C437846A-5408-4FD2-AE72-59A359F5F8F3}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName={pf}\Arkive
DefaultGroupName=Arkive
UninstallDisplayIcon={app}\{#MyAppExeName}
ArchitecturesAllowed=x64
ArchitecturesInstallIn64BitMode=x64
DisableProgramGroupPage=yes
LicenseFile=E:\ArkiveInstaller\License.txt
InfoBeforeFile=E:\ArkiveInstaller\README.txt
OutputDir=E:\ArkiveInstaller\Builds
OutputBaseFilename=ArkiveInstaller
SetupIconFile=E:\ArkiveInstaller\assets\arkive.ico
SolidCompression=yes
WizardStyle=modern

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop icon"; GroupDescription: "Additional Icons"; Flags: checkedonce

[Files]
Source: "E:\ArkiveInstaller\dist\arkive.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "E:\ArkiveInstaller\assets\*"; DestDir: "{app}\assets"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "E:\ArkiveInstaller\assets\arkive.ico"; DestDir: "{app}\assets"; Flags: ignoreversion


[Icons]
Name: "{autoprograms}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\assets\arkive.ico"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon; IconFilename: "{app}\assets\arkive.ico"

[Registry]
; File association for .arcx
Root: HKCR; Subkey: ".arcx"; ValueType: string; ValueName: ""; ValueData: "Arkive.arcxfile"; Flags: uninsdeletevalue
Root: HKCR; Subkey: "Arkive.arcxfile"; ValueType: string; ValueName: ""; ValueData: "Arkive Encrypted Archive"; Flags: uninsdeletevalue
Root: HKCR; Subkey: "Arkive.arcxfile\DefaultIcon"; ValueType: string; ValueName: ""; ValueData: "{app}\{#MyAppExeName},0"; Flags: uninsdeletevalue
Root: HKCR; Subkey: "Arkive.arcxfile\shell\open\command"; ValueType: string; ValueName: ""; ValueData: """{app}\{#MyAppExeName}"" ""%1"""; Flags: uninsdeletevalue

; Right-click context menu for all files
Root: HKCR; Subkey: "*\shell\Compress with Arkive"; ValueType: string; ValueName: ""; ValueData: "Compress with Arkive"
Root: HKCR; Subkey: "*\shell\Compress with Arkive\command"; ValueType: string; ValueName: ""; ValueData: """{app}\{#MyAppExeName}"" ""%1"""

Root: HKCR; Subkey: "*\shell\Extract with Arkive"; ValueType: string; ValueName: ""; ValueData: "Extract with Arkive"
Root: HKCR; Subkey: "*\shell\Extract with Arkive\command"; ValueType: string; ValueName: ""; ValueData: """{app}\{#MyAppExeName}"" ""%1"""

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "Launch Arkive"; Flags: nowait postinstall skipifsilent
