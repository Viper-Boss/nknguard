#ifndef AppVersion
  #define AppVersion "0.2.3-preview"
#endif
#ifndef BinaryPath
  #define BinaryPath "..\..\NKNGuard-Windows.exe"
#endif

[Setup]
AppId={{54223988-68FC-4C60-957D-BC436B5B7BEE}
AppName=NKNGuard
AppVersion={#AppVersion}
AppPublisher=NKNGuard Authors
AppPublisherURL=https://github.com/Viper-Boss/nknguard
DefaultDirName={localappdata}\Programs\NKNGuard
DefaultGroupName=NKNGuard
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
AppMutex=Local\NKNGuardClient
CloseApplications=no
RestartApplications=no
LicenseFile=..\..\LICENSE
InfoBeforeFile=README.txt
OutputDir=..\..\dist\windows
OutputBaseFilename=NKNGuard-Setup-{#AppVersion}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
UninstallDisplayIcon={app}\NKNGuard-Windows.exe

[Files]
Source: "{#BinaryPath}"; DestDir: "{app}"; Flags: ignoreversion
Source: "README.txt"; DestDir: "{app}"
Source: "..\..\LICENSE"; DestDir: "{app}"

[Icons]
Name: "{group}\NKNGuard"; Filename: "{app}\NKNGuard-Windows.exe"
Name: "{group}\Uninstall NKNGuard"; Filename: "{uninstallexe}"

[Run]
Filename: "{app}\NKNGuard-Windows.exe"; Description: "Launch NKNGuard"; Flags: nowait postinstall skipifsilent

[Code]
function InitializeUninstall(): Boolean;
var
  ExitCode: Integer;
  ConfigPath: String;
begin
  Result := False;
  if CheckForMutexes('Local\NKNGuardClient') then begin
    MsgBox('Exit NKNGuard from its tray menu before uninstalling. Closing the window only hides it.', mbError, MB_OK);
    exit;
  end;
  { Keep identity and pairing files. They are not installer-owned files. }
  if FileExists(ExpandConstant('{localappdata}\NKNGuard\state\shutdown.json')) then begin
    ConfigPath := ExpandConstant('{localappdata}\NKNGuard\config.yaml');
    if not ShellExec('runas', ExpandConstant('{app}\NKNGuard-Windows.exe'),
      '--config "' + ConfigPath + '" cleanup', '', SW_HIDE,
      ewWaitUntilTerminated, ExitCode) then begin
      MsgBox('Tunnel cleanup needs administrator approval. Uninstall was cancelled.', mbError, MB_OK);
      exit;
    end;
    if ExitCode <> 0 then begin
      MsgBox('Tunnel cleanup failed. Open NKNGuard and retry cleanup before uninstalling.', mbError, MB_OK);
      exit;
    end;
  end;
  Result := True;
end;
