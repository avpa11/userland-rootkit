# Project 1 — Covert Channel Remote Administration Toolkit

A userland rootkit implementing a **Commander** (controller) and **Victim** (agent) that communicate exclusively through a covert UDP channel using pcap-based port knocking for session initiation.

## Architecture Overview

```
Commander                           Victim
   |                                  |
   |--- port knock (UDP 5001-5003) -->|  (pcap capture)
   |                                  |
   |<============= Session ==========>|  (UDP 7777 covert channel)
   |                                  |
   |<------- Watch events ------------|  (UDP 9999 collector port)
```

### Communication

- **Port knocking**: Commander sends 3 sequential raw IP packets to ports 5001, 5002, 5003. Each packet's IP ID field encodes a verifiable knock sequence using `protocol_encode_ip_id()`. The victim captures these via pcap and validates the IP ID before accepting.
- **Covert channel**: After knock, both sides communicate via raw IP packets with UDP encapsulation on port 7777. Payload bytes are XOR-obfuscated using a session-derived key. Uses sequence numbers and checksums.
- **Watch events**: File/directory change alerts are sent asynchronously from victim to commander on UDP port 9999.

### Protocol

Custom binary protocol over raw IP/UDP. All multi-byte fields are in network byte order (big-endian). Payload bytes are XOR-obfuscated using a key derived from `OBFUSCATION_KEY_BASE ^ SEQ_INIT`.
- 4-byte sequence number
- 1-byte command identifier
- 2-byte payload length
- Variable-length XOR-obfuscated payload (up to ~1380 bytes)
- 2-byte internet checksum (RFC 1071)

## Build

### Requirements

- GCC or Clang
- libpcap
- pthreads
- Linux: kernel headers (linux/input.h for keylogger)
- macOS: ApplicationServices framework (for keylogger event tap)

### Compile

#### For Linux

```bash
sudo apt-get install -y libpcap-dev 2>&1
```

```bash
make
```

This produces two binaries: `commander` and `victim`.

```bash
make clean   # Remove binaries
```

## Usage

### Victim

Run as root (required for pcap capture and keylogger):

```bash
sudo ./victim
```

The victim starts listening for port-knock sequences on UDP ports 5001-5003 via pcap. Once a valid knock is received, it opens the covert channel on UDP port 7777.

**Process concealment**: On startup, the victim overwrites its argv[0] to appear as `[kworker/u16:4]` in process listings.

### Commander

```bash
./commander [victim_ip] [--connect|-c]
```

Options:
- `victim_ip` — Target IP (default: 127.0.0.1)
- `--connect` / `-c` — Auto-connect on startup

### Commander Menu

| #  | Option |
|----|--------|
| 1  | Connect to victim (port-knock + session start) |
| 2  | Set victim IP |
| 3  | Exit |

Once connected:

| #  | Option |
|----|--------|
| 1  | Start keylogger |
| 2  | Stop keylogger |
| 3  | Transfer keylog file from victim |
| 4  | Transfer file to victim |
| 5  | Transfer file from victim |
| 6  | Watch a file on victim |
| 7  | Watch a directory on victim |
| 8  | Run program on victim |
| 9  | Send heartbeat |
| 10 | Disconnect |
| 11 | Uninstall victim |
| 12 | Exit (warns to disconnect first) |

### Keylogger

- **Linux**: Reads from `/dev/input/event*` devices. Default: `/dev/input/event0`. Use `auto` for automatic selection.
- **macOS**: Uses CGEventTap (requires Accessibility permission). Defaults to `event-tap`.
- Keylog file: `/tmp/victim_keylog.log` on the victim. Keylogger responses include the device path used.

### /etc/shadow Handling

When the commander requests a file watch on `/etc/shadow`, the victim captures a snapshot of the file contents on the first watch. Subsequent changes trigger alerts that compare the shadow file's user list against the snapshot, reporting specific user additions/removals.

## Platform Support

| Feature | Linux | macOS |
|---------|-------|-------|
| Port knocking (pcap) | Full | Full |
| Covert channel | Full | Full |
| Keylogger | /dev/input/event* | CGEventTap |
| Process concealment | argv[0] overwrite + prctl | argv[0] overwrite |
| File/directory watch | Full | Full |
| Remote command execution | Full | Full |
| File transfer | Full | Full |
| Uninstall | Full | Full |

## Architecture Notes

- All session communication uses raw IP packets with sequence-numbered payloads and checksums
- Payloads are XOR-obfuscated using a session-derived key for basic traffic obfuscation
- File transfers and command output use an ACK-based streaming protocol
- Watch events are sent on a separate UDP port (collector/9999) to avoid interfering with command/response traffic
- The victim uses raw sockets for sending and pcap for receiving (promiscuous mode on loopback)
- The commander uses raw sockets for sending and pcap for receiving session responses
- File watches use `stat()` polling; directory watches use content hashing via FNV-1a
- Uninstall triggers victim shutdown after acknowledge

## Limitations

- Best tested on loopback; pcap interface selection varies by platform
- Single session at a time
- No encryption on the covert channel (only XOR obfuscation)
- Keylogger requires elevated permissions (root for Linux, Accessibility for macOS)
