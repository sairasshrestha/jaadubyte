# Jaadubyte

**Jaadubyte** is a command-line tool designed to fix and correct the magic bytes of a file, ensuring it has the correct file signature based on its contents. This tool is particularly useful for dealing with files that have been renamed or have incorrect magic bytes (file signatures).

## Features

- **Magic Byte Correction**: Fixes incorrect magic bytes in files and updates their extensions.
- **File Integrity Check**: Verifies file integrity before and after the magic byte correction.
- **Auto Detection**: Automatically detects the correct file type (when no type is specified).
- **Brute Force**: Attempts to brute force the correct file type using all available magic bytes if the file integrity cannot be determined.

## Installation

You need to have Python 3 and the `Pillow` library installed to use this tool.

### Prerequisites

- Python 3
- Pillow library (`pip install pillow`)

### Clone the Repository

To clone the repository, use the following command:

```bash
git clone https://github.com/sairasshrestha/jaadubyte.git
cd jaadubyte
