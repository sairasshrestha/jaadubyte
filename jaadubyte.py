import argparse
import json
import os
from PIL import Image
import magic  # For auto-detecting the file type by content
from io import BytesIO

# Load magic bytes from JSON file
MAGIC_BYTES_FILE = "magic_bytes.json"

def load_magic_bytes():
    try:
        with open(MAGIC_BYTES_FILE, "r") as file:
            return {k: bytes.fromhex(v) for k, v in json.load(file).items()}
    except FileNotFoundError:
        print(f"Error: {MAGIC_BYTES_FILE} not found. Please ensure the file exists.")
        exit(1)
    except json.JSONDecodeError:
        print(f"Error: {MAGIC_BYTES_FILE} contains invalid JSON.")
        exit(1)

MAGIC_BYTES = load_magic_bytes()

def detect_file_type_using_pil(file_path):
    """Auto-detect the true file type by attempting to open it with PIL."""
    try:
        with Image.open(file_path) as img:
            img.verify()  # Verifies that the file can be opened
            # Return the file type based on the image format (png, jpeg, gif, etc.)
            return img.format.lower()  # 'PNG', 'JPEG', 'GIF', etc.
    except Exception as e:
        print(f"Could not determine file type using PIL: {e}")
        return None

def verify_file_integrity(file_path, file_type):
    """Verify the integrity of the file for specific file types."""
    if file_type in ["png", "jpg", "jpeg", "gif"]:
        try:
            with Image.open(file_path) as img:
                img.verify()  # Verifies that the file can be opened
            print(f"File '{file_path}' is a valid {file_type} file.")
            return True
        except Exception as e:
            print(f"Integrity check failed for '{file_path}': {e}")
            return False
    else:
        print(f"Integrity check for '{file_type}' is not implemented.")
        return True  # Assume true for unsupported types

def correct_magic_bytes(input_file, file_type, output_file):
    if file_type not in MAGIC_BYTES:
        raise ValueError(f"Unknown file type: {file_type}. Check {MAGIC_BYTES_FILE} for supported types.")

    new_magic = MAGIC_BYTES[file_type]

    # Ensure input file exists
    if not os.path.exists(input_file):
        raise FileNotFoundError(f"Input file '{input_file}' not found.")

    # Verify integrity before fixing
    print("Checking file integrity before fixing...")
    if not verify_file_integrity(input_file, file_type):
        print(f"Warning: The file '{input_file}' may already be corrupted.")

    # Read input file
    with open(input_file, "rb") as infile:
        original_data = infile.read()

    # Replace magic bytes
    updated_data = new_magic + original_data[len(new_magic):]

    # Write to output file
    with open(output_file, "wb") as outfile:
        outfile.write(updated_data)

    print(f"Magic bytes updated successfully! New file saved as '{output_file}'.")

    # Verify integrity after fixing
    print("Checking file integrity after fixing...")
    if not verify_file_integrity(output_file, file_type):
        print(f"Warning: The file '{output_file}' may still not be valid. The suggested magic byte might not be correct.")

def main():
    parser = argparse.ArgumentParser(
        description="Jaadubyte: A tool to correct magic bytes in files.")
    parser.add_argument(
        "-f", "--file", required=True, help="Path to the input file.")
    parser.add_argument(
        "-c", "--correct", help="Target file type (e.g., 'png', 'jpg'). If not specified, the file type will be auto-detected.")
    parser.add_argument(
        "-o", "--output", required=True, help="Path to save the corrected output file.")

    args = parser.parse_args()

    # Auto-detect file type if not provided
    if not args.correct:
        file_type = detect_file_type_using_pil(args.file)
        if file_type:
            print(f"Auto-detected file type as '{file_type}'.")
        else:
            print("Error: Could not auto-detect the file type.")
            exit(1)
    else:
        file_type = args.correct

    try:
        correct_magic_bytes(args.file, file_type, args.output)
    except ValueError as ve:
        print(f"Error: {ve}")
    except FileNotFoundError as fnfe:
        print(f"Error: {fnfe}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

if __name__ == "__main__":
    main()
