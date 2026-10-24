#ifndef AppVersion
  #define AppVersion "4.0.0"
#endif
#define MyAppName "IPA Studio Trusted"
#define MyAppExe "IPAStudio.exe"
[Setup]
AppId={{86E929F2-3212-4CBA-AEB9-C9033A70A537}
AppName={#MyAppName}
AppVersion={#AppVersion}
AppPublisher=IPA Studio Community Build
AppPublisherURL=https://github.com/pwnapplehat/iPASide
AppSupportURL=https://github.com/pwnapplehat/iPASide
DefaultDirName={localappdata}\Programs\IPA Studio Trusted
DefaultGroupName=IPA Studio Trusted
PrivilegesRequired=lowest
OutputDir=..\dist\installer
OutputBaseFilename=IPAStudio-Trusted-Setup-{#AppVersion}
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
UninstallDisplayIcon={app}\IPAStudio.exe
DisableDirPage=yes
DisableProgramGroupPage=yes
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"
[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Shortcuts"; Flags: unchecked
[Files]
Source: "..\publish\IPAStudio\*"; DestDir: "{app}"; Flags: recursesubdirs createallsubdirs ignoreversion
[Icons]
Name: "{group}\IPA Studio Trusted"; Filename: "{app}\IPAStudio.exe"
Name: "{autodesktop}\IPA Studio Trusted"; Filename: "{app}\IPAStudio.exe"; Tasks: desktopicon
[Run]
Filename: "{app}\IPAStudio.exe"; Description: "Launch IPA Studio Trusted"; Flags: nowait postinstall skipifsilent
