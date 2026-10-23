"""Build standalone .exe with PyInstaller.
Usage: python build_exe.py
Output: dist/PQC_Migration_Toolkit.exe (GUI) and/or dist/PQC_CLI.exe (CLI)"""

import os, sys, site, shutil

def build():
    opts = [
        sys.executable, "-m", "PyInstaller",
        "--onefile",           # single .exe
        "--windowed",          # no console window for GUI
        "--name", "PQC_Migration_Toolkit",
        "--add-data", f"src{os.pathsep}src",
        "--hidden-import", "kyber_py.ml_kem.default_parameters",
        "--hidden-import", "dilithium_py.ml_dsa.default_parameters",
        "--hidden-import", "cryptography.hazmat.primitives.asymmetric.x25519",
        "--hidden-import", "cryptography.hazmat.primitives.asymmetric.rsa",
        "--hidden-import", "cryptography.hazmat.primitives.asymmetric.ec",
        "--hidden-import", "cryptography.hazmat.primitives.kdf.hkdf",
        "--hidden-import", "cryptography.x509",
        "--hidden-import", "matplotlib",
        "--hidden-import", "PIL._tkinter_finder",
        "--collect-all", "customtkinter",
        "--collect-all", "kyber_py",
        "--collect-all", "dilithium_py",
        "gui_app.py",
    ]
    print("Building GUI .exe...")
    os.system(" ".join(opts))
    print("Building CLI .exe...")
    opts_cli = list(opts)
    opts_cli[opts_cli.index("--windowed")] = "--console"
    opts_cli[opts_cli.index("--name") + 1] = "PQC_CLI"
    opts_cli[opts_cli.index("gui_app.py")] = "main.py"
    os.system(" ".join(opts_cli))

if __name__ == "__main__":
    build()
