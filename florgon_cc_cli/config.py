import sys
from pathlib import Path

CC_API_URL = "https://api-cc.florgon.com/v1"
URL_OPEN_PROVIDER = "https://cc.florgon.com/o"
URL_PASTE_OPEN_PROVIDER = "https://cc.florgon.com/p"
URL_QR_PROVIDER = "https://cc.florgon.com/qr"

CONFIG_DIR = Path.home() / ".config" / "florgon-cc"
CONFIG_FILE = CONFIG_DIR / "config.toml"

if sys.platform == "win32":
    TEMP_FILES_DIR = Path.home()
else:
    TEMP_FILES_DIR = Path("/tmp")
