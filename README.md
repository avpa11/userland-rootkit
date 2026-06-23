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

- **Port knocking**: Commander sends 3 sequential UDP packets to ports 5001, 5002, 5003. The victim captures these via pcap (no open ports initially).
- **Covert channel**: After knock, both sides bind UDP port 7777. All commands/responses go through a custom protocol with sequencing and checksums.
- **Watch events**: File/directory change alerts are sent asynchronously from victim to commander on UDP port 9999.

### Protocol

Custom binary protocol over UDP:
- 4-byte sequence number (network byte order)
- 1-byte command identifier
- 2-byte payload length (network byte order)
- Variable-length payload (up to ~1380 bytes)
- 2-byte internet checksum

## Build

### Requirements

- GCC or Clang
- libpcap
- pthreads
- Linux: kernel headers (linux/input.h for keylogger)
- macOS: ApplicationServices framework (for keylogger event tap)

### Compile

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
- Keylog file: `/tmp/victim_keylog.log` on the victim.

### /etc/shadow Handling

When the commander requests a file watch on `/etc/shadow`, the victim automatically redirects to a directory watch on `/etc/` instead. File watch events (create, modify, delete) will fire for any change within `/etc/`.

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

- All session communication uses sequence-numbered packets with checksums
- File transfers and command output use an ACK-based streaming protocol
- Watch events are sent on a separate UDP port (collector/9999) to avoid interfering with command/response traffic
- The victim uses `stat()` polling for file watches and `opendir()` with content hashing for directory watches
- Uninstall triggers victim shutdown after acknowledge

## Limitations

- Local loopback only by default (pcap on `lo0`/`lo`)
- Single session at a time
- No encryption on the covert channel
- Keylogger requires elevated permissions (root for Linux, Accessibility for macOS)
