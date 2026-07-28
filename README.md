# AntiArchiveScanner

AntiArchiveScanner is a cross-platform desktop application for Windows and macOS that automatically monitors the user's Downloads folder and scans newly downloaded files and supported archives.

The scanner does not execute downloaded files. Archive contents are extracted only into controlled temporary directories and analyzed before user action is requested.

---

## Downloads

### Windows

Download the Windows installer:

https://raw.githubusercontent.com/Cobollt/Automated-defender/main/release/windows/AntiArchiveScanner-Setup.exe

### macOS

Download the macOS installer:

https://raw.githubusercontent.com/Cobollt/Automated-defender/main/release/macos/AntiArchiveScanner.dmg - In progres

---

## Supported platforms

- Windows 10 / 11
- macOS

Linux is not currently supported as a release platform.

---

## Main features

- Automatic monitoring of the Downloads folder
- Automatic scanning of newly downloaded files
- ZIP and TAR archive inspection
- Nested archive detection
- Protection against unsafe archive paths
- Archive bomb heuristics
- Suspicious executable signature detection
- Suspicious extension detection
- Suspicious string detection
- Entropy analysis
- SHA-256 calculation
- Risk classification:
  - SAFE
  - LOW
  - MEDIUM
  - HIGH
  - CRITICAL
- System notifications for dangerous results
- Actions for dangerous files:
  - Keep
  - Delete
  - Quarantine
- System-security integration where available
- Local quarantine fallback
- JSON and text scan reports
- Scan and action history
- Single-instance protection
- Optional autostart
- Update manifest with SHA-256 verification

---

## Safety model

AntiArchiveScanner does not execute files during scanning.

Archive extraction is restricted by:

- maximum extracted size;
- maximum number of files;
- maximum nested archive depth;
- compression-ratio limits;
- archive path validation;
- symbolic-link restrictions;
- temporary-directory isolation.

Potentially dangerous files can be sent to the operating system security provider first. If the operating system does not confirm isolation, AntiArchiveScanner can move the file to its own local quarantine.

---

## Windows installation

1. Download `AntiArchiveScanner-Setup.exe`.
2. Run the installer.
3. Follow the installation wizard.
4. Optionally enable automatic startup.
5. Launch AntiArchiveScanner.

Default installation location:

```text
%LOCALAPPDATA%\Programs\AntiArchiveScanner
```

Application data is stored under:

```text
%LOCALAPPDATA%\AntiArchiveScanner
```

---

## macOS installation

1. Download `AntiArchiveScanner.dmg`.
2. Open the DMG.
3. Drag `AntiArchiveScanner.app` to `Applications`.
4. Launch AntiArchiveScanner from `Applications`.

The updater is included inside the main application bundle and does not need to be installed separately.

Application data is stored under:

```text
~/Library/Application Support/AntiArchiveScanner
```

---

## Automatic updates

Update information is read from:

https://raw.githubusercontent.com/Cobollt/Automated-defender/main/release/update-manifest.json

The manifest contains:

- current release version;
- Windows installer URL and SHA-256;
- macOS installer URL and SHA-256.

Downloaded updates are verified against SHA-256 before installation is offered.

---

## Release structure

```text
release/
├── update-manifest.json
├── windows/
│   └── AntiArchiveScanner-Setup.exe
└── macos/
    └── AntiArchiveScanner.dmg
```

The project currently distributes installers directly from the repository rather than through GitHub Releases.

---

## Development setup

Python 3.14 is recommended for release builds.

Create a virtual environment:

### macOS

```bash
python3.12 -m venv .venv
source .venv/bin/activate
```

### Windows

```powershell
py -3.12 -m venv .venv
.venv\Scripts\Activate.ps1
```

Install dependencies:

```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Run tests:

```bash
python -m pytest -q
```

Run the application from source:

```bash
python app.py
```

---

## Build commands

### Run tests

```bash
python package_all.py test
```

### Clean build artifacts

```bash
python package_all.py clean
```

### Build with PyInstaller

```bash
python package_all.py build
```

### Create package for the current operating system

```bash
python package_all.py package --version 1.0.0
```

### Create a complete release for the current operating system

```bash
python package_all.py release --version 1.0.0
```

### Generate the update manifest

```bash
python package_all.py manifest --version 1.0.0
```

When both the Windows installer and macOS DMG are present:

```bash
python package_all.py manifest \
    --version 1.0.0 \
    --require-all
```

---

## Autostart

Check status:

```bash
python scripts/manage_autostart.py status
```

Enable:

```bash
python scripts/manage_autostart.py enable
```

Disable:

```bash
python scripts/manage_autostart.py disable
```

On Windows the application uses the current-user `Run` registry key.

On macOS the application uses a user LaunchAgent.

---

## Reports and local data

The application keeps:

```text
logs/
reports/
quarantine/
```

inside its platform-specific application data directory.

Reports include JSON and human-readable text versions.

History is stored in JSONL format.

---

## Repository

https://github.com/Cobollt/Automated-defender