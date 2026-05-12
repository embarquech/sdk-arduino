#!/usr/bin/env bash

echo "============================================"
echo " Cryptnox SDK Arduino - Library Setup"
echo "============================================"
echo

# Detect default Arduino libraries directory per OS
if [[ "$OSTYPE" == "darwin"* ]]; then
    DEFAULT_ARDUINO_LIBS="$HOME/Documents/Arduino/libraries"
else
    DEFAULT_ARDUINO_LIBS="$HOME/Arduino/libraries"
fi

ARDUINO_LIBS="${1:-$DEFAULT_ARDUINO_LIBS}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "Arduino libraries directory: $ARDUINO_LIBS"
echo

mkdir -p "$ARDUINO_LIBS"

# Backup existing libraries
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="${ARDUINO_LIBS}_backup_${TIMESTAMP}"
echo "Creating backup at:"
echo "  $BACKUP_DIR"
cp -r "$ARDUINO_LIBS" "$BACKUP_DIR"
echo "Backup done."
echo

# Install SDK itself
SDK_DEST="$ARDUINO_LIBS/cryptnox-sdk-arduino-legacy"
echo "Installing cryptnox-sdk-arduino-legacy..."
rm -rf "$SDK_DEST"
cp -r "$SCRIPT_DIR" "$SDK_DEST"
echo "  OK"
echo

# ---------------------------------------------------------------------------
# Required library versions (checked against installed library.properties)
# ---------------------------------------------------------------------------
declare -A REQ_VERSION=(
    [AESLib]="2.3.6"
    [Adafruit_BusIO]="1.17.4"
    [Adafruit_PN532]="1.3.4"
    [Crypto]="0.4.0"
    [micro-ecc]="1.0.0"
)

# Returns the installed version from library.properties, or empty string
get_installed_version() {
    local props="$ARDUINO_LIBS/$1/library.properties"
    if [[ -f "$props" ]]; then
        grep -m1 "^version=" "$props" | cut -d= -f2 | tr -d '[:space:]'
    fi
}

# Returns 0 (true) if version $1 >= version $2
version_gte() {
    [ "$(printf '%s\n' "$1" "$2" | sort -V | head -1)" = "$2" ]
}

# Checks version and prints status; returns 0 if install needed, 1 if already OK
needs_install() {
    local name="$1"
    local dir="$2"
    local required="${REQ_VERSION[$dir]}"
    local installed
    installed=$(get_installed_version "$dir")
    if [[ -n "$installed" ]]; then
        if version_gte "$installed" "$required"; then
            echo "[OK]     $name $installed already installed."
            return 1
        else
            echo "[UPDATE] $name $installed < $required, updating..."
            return 0
        fi
    else
        echo "[INSTALL] $name not found, installing $required..."
        return 0
    fi
}

echo "Installing dependency libraries..."
echo

if command -v arduino-cli &>/dev/null; then
    echo "Using arduino-cli..."
    echo

    install_cli() {
        local name="$1"
        local dir="${2:-$name}"
        if needs_install "$name" "$dir"; then
            arduino-cli lib install "$name@${REQ_VERSION[$dir]}" || \
                echo "  WARNING: arduino-cli failed for $name."
        fi
        echo
    }

    install_cli "AESLib"         "AESLib"
    install_cli "Adafruit BusIO" "Adafruit_BusIO"
    install_cli "Adafruit PN532" "Adafruit_PN532"
    install_cli "Crypto"         "Crypto"
    install_cli "micro-ecc"      "micro-ecc"

elif command -v git &>/dev/null; then
    echo "arduino-cli not found. Using git clone..."
    echo

    install_git() {
        local name="$1"
        local dir="$2"
        local url="$3"
        if needs_install "$name" "$dir"; then
            rm -rf "$ARDUINO_LIBS/$dir"
            git clone --depth 1 "$url" "$ARDUINO_LIBS/$dir" || \
                echo "  WARNING: git clone failed for $name."
        fi
        echo
    }

    install_git "AESLib"         "AESLib"         "https://github.com/suculent/thinx-aes-lib"
    install_git "Adafruit BusIO" "Adafruit_BusIO" "https://github.com/adafruit/Adafruit_BusIO"
    install_git "Adafruit PN532" "Adafruit_PN532" "https://github.com/adafruit/Adafruit-PN532"
    install_git "micro-ecc"      "micro-ecc"      "https://github.com/kmackay/micro-ecc"

    # Crypto lives inside the arduinolibs monorepo — extract the subfolder
    if needs_install "Crypto" "Crypto"; then
        TMPDIR_CRYPTO=$(mktemp -d)
        if git clone --depth 1 https://github.com/rweather/arduinolibs "$TMPDIR_CRYPTO"; then
            rm -rf "$ARDUINO_LIBS/Crypto"
            cp -r "$TMPDIR_CRYPTO/libraries/Crypto" "$ARDUINO_LIBS/Crypto"
            echo "  OK"
        else
            echo "  WARNING: Failed to clone Crypto."
            echo "  Install manually from Arduino Library Manager: 'Crypto' by Rhys Weatherley"
        fi
        rm -rf "$TMPDIR_CRYPTO"
    fi
    echo

else
    echo "ERROR: Neither arduino-cli nor git is available."
    echo "Please install arduino-cli from: https://arduino.github.io/arduino-cli/"
    exit 1
fi

echo "============================================"
echo " Setup complete! Restart Arduino IDE."
echo "============================================"
