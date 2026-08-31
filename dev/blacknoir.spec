# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec for Black Noir — LEAN core onefile console app.
#
# The frozen exe bundles only the core runtime (requests + beautifulsoup4 +
# stdlib). The optional cloud/local LLM SDKs (anthropic, openai) are NOT
# bundled: they pull very large transitive trees and are lazy-imported with a
# graceful heuristic fallback, so the exe runs in deterministic heuristic mode.
# To use cloud/Ollama LLM providers, run from source:  python main.py ...
import os
ROOT = os.path.dirname(os.path.abspath(SPECPATH))
from PyInstaller.utils.hooks import collect_submodules, collect_data_files

hiddenimports = collect_submodules('blacknoir') + ['bs4', 'requests', 'certifi']
datas = collect_data_files('certifi')

# Keep the binary small and the analysis clean: drop LLM SDKs, dev tooling, and
# unrelated heavy packages that happen to live in the global environment.
#
# curl_cffi stays excluded HERE on purpose (the AI build bundles it). This is
# the documented core-only binary, and curl_cffi carries a native libcurl. The
# cost is that BLACKNOIR_IMPERSONATE cannot take effect in this exe — http.py
# reports that honestly via transport_status() rather than pretending, so a
# lean-exe user is told the setting is inert instead of assuming it applied.
excludes = [
    'anthropic', 'openai', 'httpx', 'httpcore', 'pydantic', 'pydantic_core',
    'sentry_sdk', 'pytest', '_pytest', 'PyInstaller', 'tkinter',
    'pygame', 'yt_dlp', 'Crypto', 'Cryptodome', 'mutagen', 'brotli',
    'curl_cffi', 'websockets', 'numpy', 'pandas', 'scipy', 'matplotlib',
    'PIL', 'cv2', 'torch', 'tensorflow', 'sqlalchemy', 'notebook', 'IPython',
    'sympy', 'kivy', 'lxml',
]

a = Analysis(
    [os.path.join(ROOT, 'main.py')],
    pathex=[ROOT],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=excludes,
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz, a.scripts, a.binaries, a.datas, [],
    name='blacknoir',
    debug=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
