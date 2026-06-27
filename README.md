# cli-claude45-haiku-csharp

A cross-platform CLI tool for encrypting and decrypting files using rclone-compatible encryption. Built with C# and .NET 10.

## Overview

This tool provides secure file encryption/decryption with:
- **File encryption**: AES-256-GCM for strong symmetric encryption
- **Password-based key derivation**: PBKDF2 with random salt generation
- **Multiple filename encoding options**: base32, base64, hex
- **Secure password input**: Masked password prompts in terminal
- **Cross-platform support**: Windows, Linux, macOS

## Installation

### Via Scoop (Windows)

```bash
scoop bucket add llm-supermarket https://github.com/llm-supermarket/scoop-bucket.git
scoop install cli-claude45-haiku-csharp
```

### Via Homebrew (macOS/Linux)

```bash
brew tap llm-supermarket/tap
brew install cli-claude45-haiku-csharp
```

### From Source

```bash
git clone https://github.com/llm-supermarket/cli-claude45-haiku-csharp.git
cd cli-claude45-haiku-csharp
dotnet publish -c Release -o ./bin/publish
./bin/publish/Cli encrypt -i <file>
```

## Usage

### Encrypt a File

```bash
# Interactive (prompts for password)
cli-claude45-haiku-csharp encrypt -i secret.txt

# With explicit password (⚠️ WARNING: visible in process list, use env var instead)
cli-claude45-haiku-csharp encrypt -i secret.txt --password "MyPassword123"

# Specify output file
cli-claude45-haiku-csharp encrypt -i secret.txt -o secret.encrypted

# With custom salt (hex format)
cli-claude45-haiku-csharp encrypt -i secret.txt -s "0102030405060708090a0b0c0d0e0f10"

# With custom filename encoding
cli-claude45-haiku-csharp encrypt -i secret.txt -e base64
```

### Decrypt a File

```bash
# Interactive (prompts for password)
cli-claude45-haiku-csharp decrypt -i secret.encrypted

# With explicit password
cli-claude45-haiku-csharp decrypt -i secret.encrypted --password "MyPassword123"

# Specify output file
cli-claude45-haiku-csharp decrypt -i secret.encrypted -o secret.decrypted
```

## Security Best Practices

### Password Handling

**Never use `--password` in production**. Instead, use environment variables:

```bash
# Set password in environment variable
export RCLONE_PASSWORD="YourSecurePassword"

# Clear the variable when done
unset RCLONE_PASSWORD

# Or use on a single command
RCLONE_PASSWORD="password" cli-claude45-haiku-csharp encrypt -i file.txt
```

### Clearing Shell History

When using `--password`, your command might be visible in shell history:

```bash
# Clear bash history
history -c
# or
history -w

# Clear zsh history
fc -p

# Clear PowerShell history
Clear-History
```

### File Handling

- Always verify encrypted files before deleting originals
- Use random salts for additional security (generated automatically)
- Store encryption keys separately from encrypted data

## Filename Encoding

The tool supports multiple encoding formats for encrypted filenames:

| Encoding | Use Case | Example |
|----------|----------|---------|
| `base32` | Default, URL-safe, efficient | `KJHDSVFJHSDVF===` |
| `base64` | Compact, widely compatible | `K3hDfV+jK2x==` |
| `hex` | Human-readable, debugging | `1f7c437d5f` |

```bash
cli-claude45-haiku-csharp encrypt -i file.txt -e base64
cli-claude45-haiku-csharp decrypt -i <encrypted_filename> -e base64
```

## Examples

### Encrypt a sensitive document

```bash
# Encrypt with automatic salt
cli-claude45-haiku-csharp encrypt -i confidential.pdf -o confidential.encrypted

# Or with custom encoding for filename support
cli-claude45-haiku-csharp encrypt -i confidential.pdf -e base32
```

### Batch encryption

```bash
#!/bin/bash
# Encrypt all .txt files
for file in *.txt; do
  cli-claude45-haiku-csharp encrypt -i "$file" -o "${file}.encrypted"
done
```

### Using with environment variable

```bash
# Set password once
export RCLONE_PASSWORD="MySecurePassword"

# Encrypt multiple files
cli-claude45-haiku-csharp encrypt -i file1.txt -o file1.encrypted
cli-claude45-haiku-csharp encrypt -i file2.txt -o file2.encrypted
cli-claude45-haiku-csharp encrypt -i file3.txt -o file3.encrypted

# When done, clear it
unset RCLONE_PASSWORD
```

## Technical Details

### Encryption Algorithm

- **File Content**: AES-256-GCM (256-bit key, 12-byte IV, 16-byte authentication tag)
- **Key Derivation**: PBKDF2 with SHA-256 (compatible with rclone standards)
- **Salt**: 16 bytes, randomly generated or user-provided

### File Format

Encrypted files contain:
1. Header: `RCLONE` (6 bytes)
2. Version: `00 00` (2 bytes)
3. Salt: 16 bytes (random or user-provided)
4. IV/Nonce: 12 bytes (random)
5. Ciphertext: variable length
6. Authentication Tag: 16 bytes

### Similar Tools

- https://github.com/rclone/rclone
- https://github.com/mcolatosti/rclonedecrypt
- https://github.com/br0kenpixel/rclone-rcc
- @fyears/rclone-crypt
