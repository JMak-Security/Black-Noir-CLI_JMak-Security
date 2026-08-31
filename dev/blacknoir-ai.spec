# -*- mode: python ; coding: utf-8 -*-
# AI-enabled onefile build: bundles the OpenAI + Anthropic SDKs so the exe can
# use cloud/Ollama LLM providers (chat, planning, vision) with keys from .env.
# Larger than the lean build, but self-contained. Junk global packages excluded.
import os
ROOT = os.path.dirname(os.path.abspath(SPECPATH))
from PyInstaller.utils.hooks import (collect_submodules, collect_data_files,
                                     collect_dynamic_libs)

hiddenimports = collect_submodules('blacknoir') + ['bs4', 'requests', 'certifi']
datas = collect_data_files('certifi')
binaries = []

# curl_cffi — optional browser-TLS transport (BLACKNOIR_IMPERSONATE). It used
# to sit in `excludes` below as unrelated global junk; it is now a declared
# optional dependency, so excluding it silently disabled the setting in the
# frozen exe. It ships a native libcurl plus its own cacert bundle, so the
# dynamic libs and data files must come along or the import fails at runtime.
# Still optional: http.py degrades to honest transport and says so if absent.
try:
    __import__('curl_cffi')
    hiddenimports += collect_submodules('curl_cffi')
    datas += collect_data_files('curl_cffi')
    binaries += collect_dynamic_libs('curl_cffi')
except Exception:
    pass
# Pillow is bundled for local EXIF/GPS extraction from input images.
for opt in ('openai', 'anthropic', 'httpx', 'httpcore', 'pydantic',
            'pydantic_core', 'jiter', 'distro', 'anyio', 'sniffio', 'h11',
            'PIL'):
    try:
        __import__(opt)
        hiddenimports += collect_submodules(opt)
        datas += collect_data_files(opt)
    except Exception:
        pass

# Suppress unrelated heavy packages that live in the global environment.
excludes = [
    'sentry_sdk', 'pytest', '_pytest', 'PyInstaller', 'tkinter',
    'pygame', 'yt_dlp', 'Crypto', 'Cryptodome', 'mutagen', 'brotli',
    'numpy', 'pandas', 'scipy', 'matplotlib', 'cv2',
    'torch', 'tensorflow', 'sqlalchemy', 'notebook', 'IPython', 'sympy',
    'kivy', 'lxml', 'websockets',
]

a = Analysis([os.path.join(ROOT, 'main.py')], pathex=[ROOT], binaries=binaries, datas=datas,
             hiddenimports=hiddenimports, hookspath=[], runtime_hooks=[],
             excludes=excludes, noarchive=False)
pyz = PYZ(a.pure)
exe = EXE(pyz, a.scripts, a.binaries, a.datas, [], name='blacknoir-ai',
          debug=False, strip=False, upx=True, upx_exclude=[],
          runtime_tmpdir=None, console=True, disable_windowed_traceback=False,
          target_arch=None, codesign_identity=None, entitlements_file=None)
