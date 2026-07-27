#define AppName "AntiArchiveScanner"

#ifndef AppVersion
    #define AppVersion "1.0.0"
#endif

#define AppPublisher "AntiArchiveScanner"

#define AppExeName "AntiArchiveScanner.exe"

#define UpdaterName "AntiArchiveScannerUpdater"
#define UpdaterExeName "AntiArchiveScannerUpdater.exe"

#define ProjectRoot "..\.."

#define BuildSource ProjectRoot + "\dist\AntiArchiveScanner"

#define UpdaterSource ProjectRoot + "\dist\AntiArchiveScannerUpdater"

#define OutputDirectory ProjectRoot + "\release\windows"


[Setup]

; ---------------------------------------------------------
; Application identity
; ---------------------------------------------------------

; ВАЖНО:
; AppId нельзя менять между версиями.
; По нему Inno Setup определяет,
; что новая установка является обновлением.
AppId={{E6217503-E573-4D76-9E67-86FCBE117109}

AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#AppPublisher}

VersionInfoVersion={#AppVersion}
VersionInfoProductVersion={#AppVersion}
VersionInfoProductName={#AppName}
VersionInfoCompany={#AppPublisher}

; ---------------------------------------------------------
; Installation
; ---------------------------------------------------------

DefaultDirName={localappdata}\Programs\{#AppName}

DefaultGroupName={#AppName}

UsePreviousAppDir=yes

DirExistsWarning=no

DisableProgramGroupPage=yes

PrivilegesRequired=lowest

PrivilegesRequiredOverridesAllowed=dialog

; ---------------------------------------------------------
; Output
; ---------------------------------------------------------

OutputDir={#OutputDirectory}

OutputBaseFilename=AntiArchiveScanner-Setup

Compression=lzma2

SolidCompression=yes

WizardStyle=modern

; ---------------------------------------------------------
; Architecture
; ---------------------------------------------------------

ArchitecturesAllowed=x64compatible

ArchitecturesInstallIn64BitMode=x64compatible

; ---------------------------------------------------------
; Uninstall
; ---------------------------------------------------------

UninstallDisplayName={#AppName}

UninstallDisplayIcon={app}\{#AppExeName}

; ---------------------------------------------------------
; Application handling
; ---------------------------------------------------------

SetupLogging=yes

CloseApplications=yes

RestartApplications=no

#ifdef SetupIconFile
SetupIconFile={#SetupIconFile}
#endif


[Languages]

Name: "english"; \
    MessagesFile: "compiler:Default.isl"

Name: "russian"; \
    MessagesFile: "compiler:Languages\Russian.isl"


[Tasks]

Name: "desktopicon"; \
    Description: "Создать значок AntiArchiveScanner на рабочем столе"; \
    GroupDescription: "Ярлыки:"

Name: "autostart"; \
    Description: "Автоматически запускать AntiArchiveScanner при входе в Windows"; \
    GroupDescription: "Автоматический запуск:"; \
    Flags: unchecked


[InstallDelete]

; ---------------------------------------------------------
; Cleanup from old installer layouts
; ---------------------------------------------------------

; Старое имя updater из предыдущей версии проекта.
Type: files; \
    Name: "{app}\Updater\Update.exe"

; Старые spec/runtime-файлы не должны попадать
; между версиями в установленное приложение.
Type: files; \
    Name: "{app}\*.spec"


[Files]

; ---------------------------------------------------------
; Main application
; ---------------------------------------------------------

; PyInstaller используется в режиме --onedir.
; Поэтому необходимо копировать не только EXE,
; но и весь каталог вместе с _internal.
Source: "{#BuildSource}\*"; \
    DestDir: "{app}"; \
    Flags: ignoreversion recursesubdirs createallsubdirs


; ---------------------------------------------------------
; Updater
; ---------------------------------------------------------

Source: "{#UpdaterSource}\*"; \
    DestDir: "{app}\Updater"; \
    Flags: ignoreversion recursesubdirs createallsubdirs


[Icons]

; ---------------------------------------------------------
; Start menu
; ---------------------------------------------------------

Name: "{autoprograms}\{#AppName}"; \
    Filename: "{app}\{#AppExeName}"; \
    WorkingDir: "{app}"


; ---------------------------------------------------------
; Update shortcut
; ---------------------------------------------------------

Name: "{autoprograms}\{#AppName}\Проверить обновления"; \
    Filename: "{app}\Updater\{#UpdaterExeName}"; \
    WorkingDir: "{app}\Updater"


; ---------------------------------------------------------
; Desktop
; ---------------------------------------------------------

Name: "{autodesktop}\{#AppName}"; \
    Filename: "{app}\{#AppExeName}"; \
    WorkingDir: "{app}"; \
    Tasks: desktopicon


[Registry]

; ---------------------------------------------------------
; Autostart
; ---------------------------------------------------------

Root: HKCU; \
    Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; \
    ValueType: string; \
    ValueName: "{#AppName}"; \
    ValueData: """{app}\{#AppExeName}"""; \
    Tasks: autostart; \
    Flags: uninsdeletevalue


; ---------------------------------------------------------
; Application metadata
; ---------------------------------------------------------

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

; На финальной странице установки пользователь
; сможет оставить включённой галочку запуска.
Filename: "{app}\{#AppExeName}"; \
    Description: "Запустить {#AppName}"; \
    WorkingDir: "{app}"; \
    Flags: nowait postinstall skipifsilent runascurrentuser


[UninstallRun]

; При удалении приложения пытаемся завершить
; основной процесс.
Filename: "taskkill.exe"; \
    Parameters: "/F /IM {#AppExeName}"; \
    Flags: runhidden skipifdoesntexist

; И updater.
Filename: "taskkill.exe"; \
    Parameters: "/F /IM {#UpdaterExeName}"; \
    Flags: runhidden skipifdoesntexist


[Code]

function IsUpgrade(): Boolean;
begin
  Result :=
    RegKeyExists(
      HKEY_CURRENT_USER,
      'Software\Microsoft\Windows\CurrentVersion\Uninstall\' +
      ExpandConstant(
        '{#SetupSetting("AppId")}_is1'
      )
    );
end;


procedure StopApplication(
  ProcessName: String
);
var
  ResultCode: Integer;
begin

  Exec(
    'taskkill.exe',
    '/F /IM "' + ProcessName + '"',
    '',
    SW_HIDE,
    ewWaitUntilTerminated,
    ResultCode
  );

end;


procedure StopRunningApplication();
begin

  StopApplication(
    '{#AppExeName}'
  );

  StopApplication(
    '{#UpdaterExeName}'
  );

  ; Поддержка старого имени updater.
  StopApplication(
    'Update.exe'
  );

end;


procedure CurStepChanged(
  CurStep: TSetupStep
);
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