#!/bin/bash
# Specify the location of libcapstone.dylib so that macho-dumper can locate it

BINARY="/usr/bin/macho-dumper"
LIB_PATH="/usr/local/lib/libcapstone.dylib"

echo "[INFO] Checking if binary exists..."
if [ ! -f "$BINARY" ]; then
    echo "[ERROR] Binary $BINARY not found!"
    exit 1
fi

echo "[INFO] Fixing libcapstone path in binary..."
install_name_tool -change libcapstone..dylib "$LIB_PATH" "$BINARY"
if [ $? -ne 0 ]; then
    echo "[ERROR] Failed to change library path!"
    exit 1
fi
echo "[INFO] Library path fixed successfully."

echo "[INFO] Setting DYLD_LIBRARY_PATH..."
export DYLD_LIBRARY_PATH="/usr/local/lib:$DYLD_LIBRARY_PATH"
echo "[INFO] DYLD_LIBRARY_PATH is $DYLD_LIBRARY_PATH"

echo "[INFO] Running $BINARY..."
"$BINARY" "$@"
