#define AppName "AntiArchiveScanner"
#define AppVersion "1.0.0"
#define AppPublisher "AntiArchiveScanner"
#define AppExeName "AntiArchiveScanner.exe"
#define UpdaterExeName "Update.exe"

#define ProjectRoot "..\.."
#define BuildSource ProjectRoot + "\dist\AntiArchiveScanner"
#define UpdaterSource ProjectRoot + "\dist\AntiArchiveScannerUpdater"
#define OutputDirectory ProjectRoot + "\release\windows"

[Setup]
; AppId нельзя менять между версиями — по нему определяется обновление.
AppId={{E6217503-E573-4D76-9E67-86FCBE117109}

AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#AppPublisher}

DefaultDirName={localappdata}\Programs\{#AppName}
DefaultGroupName={#AppName}

UsePreviousAppDir=yes
DirExistsWarning=no

DisableProgramGroupPage=yes
PrivilegesRequired=lowest

OutputDir={#OutputDirectory}
OutputBaseFilename=AntiArchiveScanner-Setup

Compression=lzma2
SolidCompression=yes
WizardStyle=modern

ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible

UninstallDisplayName={#AppName}
UninstallDisplayIcon={app}\{#AppExeName}

SetupLogging=yes
CloseApplications=yes
RestartApplications=no

#ifdef SetupIconFile
SetupIconFile={#SetupIconFile}
#endif

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"
Name: "russian"; MessagesFile: "compiler:Languages\Russian.isl"

[Tasks]
; Галочка включена по умолчанию.
Name: "desktopicon"; \
    Description: "Создать значок AntiArchiveScanner на рабочем столе"; \
    GroupDescription: "Ярлыки:"

Name: "autostart"; \
    Description: "Автоматически запускать AntiArchiveScanner при входе в Windows"; \
    GroupDescription: "Автоматический запуск:"; \
    Flags: unchecked

[Files]
; Основная программа вместе с каталогом _internal.
Source: "{#BuildSource}\*"; \
    DestDir: "{app}"; \
    Flags: ignoreversion recursesubdirs createallsubdirs

; Отдельная программа обновления.
Source: "{#UpdaterSource}\*"; \
    DestDir: "{app}\Updater"; \
    Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
; Главное меню «Пуск».
Name: "{autoprograms}\{#AppName}"; \
    Filename: "{app}\{#AppExeName}"; \
    WorkingDir: "{app}"

; Ярлык программы обновления.
Name: "{autoprograms}\{#AppName}\Проверить обновления"; \
    Filename: "{app}\Updater\{#UpdaterExeName}"; \
    WorkingDir: "{app}\Updater"

; Ярлык на рабочем столе.
Name: "{autodesktop}\{#AppName}"; \
    Filename: "{app}\{#AppExeName}"; \
    WorkingDir: "{app}"; \
    Tasks: desktopicon

[Registry]
; Автозапуск — только если пользователь выбрал соответствующую задачу.
Root: HKCU; \
    Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; \
    ValueType: string; \
    ValueName: "{#AppName}"; \
    ValueData: """{app}\{#AppExeName}"""; \
    Tasks: autostart; \
    Flags: uninsdeletevalue

; Текущая установленная версия доступна Update.exe.
Root: HKCU; \
    Subkey: "Software\AntiArchiveScanner"; \
    ValueType: string; \
    ValueName: "InstallPath"; \
    ValueData: "{app}"; \
    Flags: uninsdeletekey

Root: HKCU; \
    Subkey: "Software\AntiArchiveScanner"; \
    ValueType: string; \
    ValueName: "Version"; \
    ValueData: "{#AppVersion}"; \
    Flags: uninsdeletekey

[Run]
; Inno Setup автоматически покажет эту запись как галочку
; на финальной странице установки.
Filename: "{app}\{#AppExeName}"; \
    Description: "Запустить {#AppName}"; \
    WorkingDir: "{app}"; \
    Flags: nowait postinstall skipifsilent runascurrentuser

[UninstallRun]
Filename: "taskkill.exe"; \
    Parameters: "/F /IM {#AppExeName}"; \
    Flags: runhidden skipifdoesntexist

Filename: "taskkill.exe"; \
    Parameters: "/F /IM {#UpdaterExeName}"; \
    Flags: runhidden skipifdoesntexist

[Code]

function IsUpgrade(): Boolean;
begin
  Result := RegKeyExists(
    HKEY_CURRENT_USER,
    'Software\Microsoft\Windows\CurrentVersion\Uninstall\' +
    ExpandConstant('{#SetupSetting("AppId")}_is1')
  );
end;


procedure StopRunningApplication();
var
  ResultCode: Integer;
begin
  Exec(
    'taskkill.exe',
    '/F /IM "{#AppExeName}"',
    '',
    SW_HIDE,
    ewWaitUntilTerminated,
    ResultCode
  );

  Exec(
    'taskkill.exe',
    '/F /IM "{#UpdaterExeName}"',
    '',
    SW_HIDE,
    ewWaitUntilTerminated,
    ResultCode
  );
end;


procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssInstall then
  begin
    StopRunningApplication();
  end;
end;


procedure CurUninstallStepChanged(
  CurUninstallStep: TUninstallStep
);
begin
  if CurUninstallStep = usUninstall then
  begin
    StopRunningApplication();
  end;
end;