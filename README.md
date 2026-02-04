# bbtsdecrypt

A Go-based utility for decrypting BBTS (Broadband Transport Stream) encrypted media files, as used by iQiyi.

## Overview

bbtsdecrypt is a command-line tool designed to decrypt Transport Stream (TS) files that are protected with AES encryption according to the BBTS (Broadband Transport Stream) specification used by iQiyi. Based on similar encryption standards, it extracts encryption information from the stream's Service Description Table (SDT) and uses it to decrypt the video and audio content.

## Features

- 🔓 Decrypts AES-encrypted BBTS (Broadband Transport Stream) transport streams used by iQiyi
- 📊 Automatic IV extraction from SDT (Service Description Table)
- ⚡ Multi-threaded packet processing
- 📈 Real-time progress tracking with ETA
- 🖥️ Cross-platform support (Windows, Linux, macOS)
- 🎯 Support for multiple video and audio PIDs

## System Requirements

- Go 1.24.2 or higher
- For building on Windows: `rsrc` tool for embedding resources
- CGO enabled (for optimal performance)

## Installation

### Using Pre-built Binaries

Download the latest binary for your platform from the [Releases](https://github.com/ReiDoBrega/bbtsdecrypt/releases) page:

- **Windows**: `bbtsdecrypt-windows-amd64.exe`
- **Linux**: `bbtsdecrypt-linux-amd64` or `bbtsdecrypt-linux-arm64`
- **macOS**: `bbtsdecrypt-darwin-amd64` or `bbtsdecrypt-darwin-arm64`

### Building from Source

```bash
git clone https://github.com/ReiDoBrega/bbtsdecrypt.git
cd bbtsdecrypt
go build -o bbtsdecrypt
```

#### Windows Build with Icon

```bash
# Install rsrc tool
go install github.com/akavel/rsrc@latest

# Generate resource file
rsrc -ico icon.ico -o rsrc.syso

# Build
go build -o bbtsdecrypt.exe
```

## Usage

```bash
bbtsdecrypt [options] <input.bbts> <output>
```

### Options

- `--key <key>`: AES-128 decryption key in hex format (32 characters / 128-bit) - **required**
- `--show-progress`: Display progress bar during decryption
- `--no-audio`: Remove audio from output (video only)
- `--no-video`: Remove video from output (audio only)
- `--help`: Show help message

### Examples

```bash
# Decrypt with AES key
./bbtsdecrypt --key 0123456789abcdef0123456789abcdef encrypted.bbts decrypted.ts

# Decrypt and show progress
./bbtsdecrypt --key 0123456789abcdef0123456789abcdef --show-progress encrypted.bbts decrypted.ts

# Video only (remove audio)
./bbtsdecrypt --key 0123456789abcdef0123456789abcdef --no-audio encrypted.bbts video_only.ts

# Audio only (remove video)
./bbtsdecrypt --key 0123456789abcdef0123456789abcdef --no-video encrypted.bbts audio_only.ts
```

## How It Works

1. **Stream Parsing**: Reads the transport stream and identifies TS packets (188 bytes each)
2. **SDT Extraction**: Parses the Service Description Table to locate encryption metadata
3. **IV Detection**: Extracts the initialization vector from the SDT service names (mdcm format)
4. **Decryption**: Uses AES-128-CTR mode to decrypt video and audio packets
5. **Stream Reconstruction**: Outputs the decrypted transport stream

### Supported Encryption

- **Algorithm**: AES-128-CTR (Counter Mode)
- **IV Format**: Extracted from SDT descriptor tag 0x48
- **PID Support**: Video (0x0100) and Audio (0x0101) PIDs

## Technical Details

### MPEG-TS Structure

The tool processes standard MPEG-TS packets:
- Packet size: 188 bytes
- Sync byte: 0x47
- PID extraction from packet header
- Payload adaptation field handling

### Encryption Metadata

Encryption information is stored in the SDT (Service Description Table) as a service name containing:

```
mdcm|[provider]|[service]|[IV_HEX]
```

Example: `mdcm|Provider|Service|12345678901234567890123456789012`

## Performance

- **Progress Display**: Real-time progress bar with ETA
- **Multi-threaded**: Efficient packet processing with concurrent operations
- **Memory Efficient**: Streams data without loading entire file into memory

## Development

### Building for All Platforms

```bash
# Native builds (Windows, Linux, macOS)
go build -v -ldflags="-s -w" -o bbtsdecrypt

# Docker cross-compilation for ARM64
docker run --rm --platform linux/arm64 \
  -v $PWD:/workspace \
  -w /workspace \
  -e CGO_ENABLED=1 \
  -e GOOS=linux \
  -e GOARCH=arm64 \
  golang:1.24 \
  go build -v -o bbtsdecrypt
```

### Dependencies

- Standard Go library only (no external dependencies)

## CI/CD

Automated builds are available via GitHub Actions. Binaries are built for:
- Windows AMD64
- Linux AMD64
- Linux ARM64
- macOS AMD64
- macOS ARM64

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

## Support

For issues, questions, or suggestions, please open an issue on [GitHub Issues](https://github.com/ReiDoBrega/bbtsdecrypt/issues).

---

**Note**: This tool is designed for educational and authorized use only. Ensure you have proper authorization before decrypting any protected media.
