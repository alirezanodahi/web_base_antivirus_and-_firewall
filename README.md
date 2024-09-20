# Security Scanner and Firewall
for network and security 

## Overview

This project consists of three main components:

1. **File Scanner**: Scans individual files using the VirusTotal API.
2. **Folder Scanner**: Scans all files in a specified directory for potential threats.
3. **Firewall**: A basic implementation that filters incoming packets based on defined rules.

## Features

- **File Scanner**: 
  - Calculates file hashes and retrieves analysis from VirusTotal.
  - Supports files up to 32MB for direct scanning; larger files are uploaded for analysis.
  
- **Folder Scanner**: 
  - Iterates through all files in a directory and its subdirectories.
  - Implements rate limiting to comply with VirusTotal's API usage policies.

- **Firewall**: 
  - Allows or discards incoming packets based on predefined rules.
  - Supports DNS request handling.

## Directory Structure

The project directory should be organized as follows:

- **`project-directory/`**: Root directory of the project
  - **`file_scanner.py`**: Script for scanning individual files using VirusTotal.
  - **`folder_scanner.py`**: Script for scanning all files in a specified folder.
  - **`firewall.py`**: Implementation of a basic firewall to manage packet filtering.
  - **`key.py`**: (Optional) File to store the VirusTotal API key.
  - **`firewall_rules.txt`**: Text file containing the rules for the firewall.

## Usage

1. **File Scanner**:
   - Run the script and provide the path to the file you want to scan.
   - The script will return the analysis results from VirusTotal.

2. **Folder Scanner**:
   - Run the script and enter the path to the folder you wish to scan.
   - The script will analyze each file and summarize the results.

3. **Firewall**:
   - Ensure the `firewall_rules.txt` file is configured with the appropriate rules.
   - Run the script to start filtering packets based on the defined rules.

## Requirements

- Python 3.x
- Required libraries: `requests`, `vt` (VirusTotal client)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Special thanks to the VirusTotal team for providing the API.
