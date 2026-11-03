#ifndef AppVersion
  #define AppVersion "0.2.20"
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

Source: "deps\wireguard-amd64-1.1.1.msi"; DestDir: "{app}\deps"; Flags: ignoreversion
Source: "deps\wireguard-amd64-1.1.1.msi"; Flags: dontcopy

[Icons]
Name: "{group}\NKNGuard"; Filename: "{app}\NKNGuard-Windows.exe"
Name: "{group}\Uninstall NKNGuard"; Filename: "{uninstallexe}"

[Run]
Filename: "{app}\NKNGuard-Windows.exe"; Description: "Launch NKNGuard"; Flags: nowait postinstall skipifsilent

[Code]
function WireGuardPresent(): Boolean;
begin
  Result := FileExists(ExpandConstant('{commonpf64}\WireGuard\wireguard.exe')) and
    FileExists(ExpandConstant('{commonpf64}\WireGuard\wg.exe'));
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var ExitCode: Integer; PackagePath: String;
begin
  Result := '';
  if WireGuardPresent() then exit;
  ExtractTemporaryFile('wireguard-amd64-1.1.1.msi');
  PackagePath := ExpandConstant('{tmp}\wireguard-amd64-1.1.1.msi');
  if CompareText(GetSHA256OfFile(PackagePath), '7bfed60ad61b785c914b38b61555a975488e1d3ec472dbfb2fcdf498fca75242') <> 0 then begin
    Result := 'WireGuard package integrity check failed.'; exit;
  end;
  WizardForm.StatusLabel.Caption := '正在安装官方 WireGuard，请允许管理员授权…';
  if not ShellExec('runas', ExpandConstant('{sys}\msiexec.exe'),
    '/i "' + PackagePath + '" /qn /norestart', '', SW_HIDE, ewWaitUntilTerminated, ExitCode) then begin
    Result := 'WireGuard 安装未获授权。请允许管理员授权后重试。'; exit;
  end;
  if (ExitCode <> 0) and (ExitCode <> 3010) then begin
    Result := 'WireGuard 安装失败，错误代码：' + IntToStr(ExitCode); exit;
  end;
  if ExitCode = 3010 then NeedsRestart := True;
  if not WireGuardPresent() then Result := 'WireGuard 安装未完成，请重启 Windows 后重试。';
end;

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
