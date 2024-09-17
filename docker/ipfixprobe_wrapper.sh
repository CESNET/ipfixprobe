#!/bin/bash
IMAGE_NAME="docker_ipfixprobe"

# Run the ipfixprobe on the input pcap file with defined script, and save the output CSV file to the output path.
PROCESS_SCRIPT_PATH=$1
INPUT_FILE_PATH=$2
OUTPUT_CSV_PATH=$3

if [ -z "$PROCESS_SCRIPT_PATH" ] || [ -z "$INPUT_FILE_PATH" ] || [ -z "$OUTPUT_CSV_PATH" ] ; then
    echo "Usage: $0 <process_script> <input_file_path> <output_csv_path>"
    exit 1
fi

CONT_BIN="$(which podman 2>/dev/null)"
if [ -z "$CONT_BIN" ]; then
   CONT_BIN="$(which docker 2>/dev/null)"
fi
if [ -z "$CONT_BIN" ]; then
   echo "Missing podman or docker."
   exit 2
fi

# Check if the Docker image exists
if ! $CONT_BIN image inspect "$IMAGE_NAME" >/dev/null 2>&1; then
    echo "Docker image '$IMAGE_NAME' not found. Attempting to build it..."

    # Determine the script directory
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    DOCKERFILE_PATH="$SCRIPT_DIR/Dockerfile"

    if [ ! -f "$DOCKERFILE_PATH" ]; then
        echo "Dockerfile not found at $DOCKERFILE_PATH"
        exit 3
    fi

    # Build the Docker image
    echo "Building Docker image '$IMAGE_NAME'..."
    $CONT_BIN build -t "$IMAGE_NAME" -f "$DOCKERFILE_PATH" "$SCRIPT_DIR"

    if [ $? -ne 0 ]; then
        echo "Failed to build Docker image."
        exit 4
    fi
fi


INPUT_FILE=$(basename "$INPUT_FILE_PATH")
PROCESS_SCRIPT=$(basename "$PROCESS_SCRIPT_PATH")
TMP_FOLDER="$(mktemp -d)"

cp "$INPUT_FILE_PATH" "$TMP_FOLDER/$INPUT_FILE"
cp "$PROCESS_SCRIPT_PATH" "$TMP_FOLDER/$PROCESS_SCRIPT"
chmod +x "$TMP_FOLDER/$PROCESS_SCRIPT"

"$CONT_BIN" run --privileged --rm -v $TMP_FOLDER:/output "$IMAGE_NAME"  "/output/$PROCESS_SCRIPT \"$INPUT_FILE\""
[ -f "$TMP_FOLDER/$INPUT_FILE.csv" ] && cp "$TMP_FOLDER/$INPUT_FILE.csv" "$OUTPUT_CSV_PATH" || echo "No output CSV file found."

# Clean up
rm "$TMP_FOLDER/$INPUT_FILE"
rm "$TMP_FOLDER/$PROCESS_SCRIPT"
[ -f "$TMP_FOLDER/$INPUT_FILE.csv" ] && rm "$TMP_FOLDER/$INPUT_FILE.csv"
rm -rf "$TMP_FOLDER"
