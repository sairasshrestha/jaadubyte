import argparse
import json
import os
from PIL import Image

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

def verify_file_integrity(file_path, file_type):
    """Verify the integrity of the file for specific file types."""
    if file_type not in MAGIC_BYTES:
        print(f"Error: Unknown file type '{file_type}'")
        return False

    # Get the expected magic bytes for the file type
    expected_magic_bytes = MAGIC_BYTES[file_type]

    # Check if the actual file's starting bytes match the expected magic bytes
    with open(file_path, "rb") as file:
        file_magic = file.read(len(expected_magic_bytes))
        if file_magic != expected_magic_bytes:
            print(f"Error: The file's magic bytes do not match expected {file_type} magic bytes.")
            return False

    # Attempt to open the file with PIL
    try:
        with Image.open(file_path) as img:
            img.verify()  # Verifies that the file can be opened and is a valid image
        print(f"File '{file_path}' is a valid {file_type} file.")
        return True
    except Exception as e:
        print(f"Integrity check failed for '{file_path}': {e}")
        return False

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

def brute_force_magic_bytes(input_file, output_file):
    """Brute-force all known magic bytes and check integrity."""
    successful_magic = None
    for file_type, magic in MAGIC_BYTES.items():
        print(f"Trying {file_type} magic bytes...")
        # Replace the magic bytes
        with open(input_file, "rb") as infile:
            original_data = infile.read()

        updated_data = magic + original_data[len(magic):]
        temp_output = f"{output_file}_{file_type}"

        with open(temp_output, "wb") as temp_outfile:
            temp_outfile.write(updated_data)

        if verify_file_integrity(temp_output, file_type):
            print(f"Success! File '{input_file}' is valid as a {file_type}.")
            successful_magic = (file_type, temp_output)
            break
        else:
            # Clean up temporary files
            os.remove(temp_output)

    if successful_magic:
        file_type, final_output = successful_magic
        print(f"Final valid file found: {final_output}")
        # Rename final file with appropriate extension (remove the magic byte type from the filename)
        os.rename(final_output, f"{output_file}.{file_type}")
        print(f"File successfully saved as {output_file}.{file_type}.")
    else:
        print("No valid magic byte found. The file may be corrupted.")

def main():
    parser = argparse.ArgumentParser(
        description="Jaadubyte: A tool to correct magic bytes in files.")
    parser.add_argument(
        "-f", "--file", required=True, help="Path to the input file.")
    parser.add_argument(
        "-c", "--correct", help="Target file type (e.g., 'png', 'jpg'). If not specified, the file type will be auto-detected.")
    parser.add_argument(
        "-o", "--output", required=True, help="Path to save the corrected output file.")
    parser.add_argument(
        "--brute", action="store_true", help="Brute force the magic byte & detects the correct magic bytes & extension for your file.")

    args = parser.parse_args()

    # Check if the file exists
    if not os.path.exists(args.file):
        print(f"Error: File '{args.file}' not found.")
        exit(1)

    # Try rendering the file
    try:
        with Image.open(args.file) as img:
            img.verify()  # Verify if the image can be opened and is valid
        print(f"File '{args.file}' renders successfully.")
    except Exception as e:
        print(f"INFO: File '{args.file}' couldn't be rendered. Proceeding to brute force.")
        # If the file can't be rendered, proceed with brute force without asking to continue
        if args.brute:
            brute_force_magic_bytes(args.file, args.output)
            return

    if args.brute:
        print("Would you like to brute-force all possible file types? (y/n)")
        user_input = input().lower()
        if user_input == 'y':
            brute_force_magic_bytes(args.file, args.output)
        else:
            print("Brute force cancelled.")
    else:
        if args.correct:
            correct_magic_bytes(args.file, args.correct, args.output)
        else:
            print("Error: You must either specify a correct file type with --correct or use --brute for brute-forcing.")
            exit(1)

if __name__ == "__main__":
    main()
