from pathlib import Path
# settings.py

# =========================================================
# PROJECT SETTINGS
# =========================================================
VERSION = "1.0"
# -------------------------
# DIRECTORY SETTINGS
# -------------------------


BASE_DIR = Path.home() / "cpo" / "output"

ENCODED_DIR = BASE_DIR / "encoded"
DECODED_DIR = BASE_DIR / "decoded"

OBFUSCATED_DIR = BASE_DIR / "obfuscated"
DEOBFUSCATED_DIR = BASE_DIR / "deobfuscated"

REPORT_DIR = BASE_DIR / "reports"


# -------------------------
# DEFAULT METHODS
# -------------------------

DEFAULT_ENCODER = "base64"
DEFAULT_OBFUSCATOR = "split"


# -------------------------
# FILE SETTINGS
# -------------------------

DEFAULT_OUTPUT_FILE = "output.txt"
AUTO_CREATE_DIRECTORIES = True
OVERWRITE_FILES = False


# -------------------------
# LOGGING / TERMINAL
# -------------------------

VERBOSE = True
ENABLE_LOGGING = True
SAVE_REPORTS = True


# -------------------------
# SECURITY / SAFETY
# -------------------------

MAX_FILE_SIZE_MB = 10
ALLOW_BINARY_FILES = False


# -------------------------
# SUPPORTED METHODS
# -------------------------

SUPPORTED_ENCODERS = [
    "base64",
    "hex",
    "rot13",
    "url"
]

SUPPORTED_OBFUSCATORS = [
    "split",
    "reverse",
    "unicode",
    "junk"
]


# =========================================================
# OPTIONAL BANNER
# =========================================================

BANNER = r"""
 ██████╗██████╗  ██████╗
██╔════╝██╔══██╗██╔═══██╗
██║     ██████╔╝██║   ██║
██║     ██╔═══╝ ██║   ██║
╚██████╗██║     ╚██████╔╝
 ╚═════╝╚═╝      ╚═════╝

 Custom Payload Obfuscator
"""