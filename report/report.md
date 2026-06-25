# Project 1

# Report


[**Purpose 3**](#purpose)

[**Requirements 3**](#requirements)

[**Platforms 4**](#platforms)

[**Language 4**](#language)

[**Documents 4**](#documents)

[**Findings 5**](#findings)

# Purpose {#purpose}

This project implements a userland rootkit consisting of a *Commander* (controller) and a *Victim* (agent). The system uses pcap-based port knocking to establish a covert session, and all subsequent command-and-control traffic flows through a custom binary protocol over UDP. Key features include keystroke logging, remote command execution, bidirectional file transfer, file/directory change monitoring, and process concealment. The project demonstrates practical knowledge of covert network channels, raw socket/pcap packet capture, kernel-level input interception, process manipulation through argv/environ tampering, and reliable protocol design over unreliable transport.

# Requirements {#requirements}

| Task | Status |
| ----- | ----- |
| Port-knocking session initiation via pcap | Fully implemented |
| Covert channel over UDP with custom binary protocol | Fully implemented |
| Sequence numbering and checksum validation | Fully implemented |
| ACK-based reliable streaming for file transfer and command output | Fully implemented |
| Keylogger (Linux: evdev, macOS: CGEventTap) | Fully implemented |
| Remote command execution with output streaming | Fully implemented |
| File transfer: Commander→Victim (upload) | Fully implemented |
| File transfer: Victim→Commander (download) | Fully implemented |
| File watch with change detection via stat polling | Fully implemented |
| Directory watch with content-hash-based change detection | Fully implemented |
| /etc/shadow indirect monitoring via /etc/ directory redirect | Fully implemented |
| Process name concealment (Linux: prctl + argv overwrite, macOS: argv + env zeroing) | Fully implemented |
| Uninstall command: remote shutdown of victim agent | Fully implemented |
| Watch events pushed asynchronously on separate UDP port (collector) | Fully implemented |
| Commander interactive menu with disconnected/connected state machine | Fully implemented |

# Platforms {#platforms}

The covert channel toolkit has been tested on:

* macOS 15 (Sequoia) on Apple Silicon
* Ubuntu 24.04 LTS

Linux builds require libpcap-dev and kernel headers. macOS builds link against the ApplicationServices framework for CGEventTap. The Makefile auto-detects the platform and includes the appropriate linker flags.

# Language {#language}

* ISO C99 (compiled with `-std=gnu99`)
* Compiles with gcc and clang with `-Wall -Wextra -Wpedantic -O2`
* Zero compilation warnings

# Documents {#documents}

* [Design](https://docs.google.com/document/d/1E_SxiU-GNSdg5bUCbIQUer4lstPOumzpewAjldYbCXM/edit?usp=drive_link)
* [Testing](testing.md)
* [User Guide](user-guide.md)

# Findings {#findings}

## Architecture

The project is implemented as two standalone binaries (`commander` and `victim`) compiled from four source files:

| File | Lines | Purpose |
|------|-------|---------|
| `src/Commander.c` | 1135 | Interactive controller: menu UI, port knock, session management, all command dispatching |
| `src/Victim.c` | ~1600 | Agent: pcap knock detection, covert channel server, watch polling, command processing |
| `src/protocol.c` | 141 | Packet serialization/deserialization, internet checksum, command name lookup |
| `src/protocol.h` | 87 | Constants, struct definitions, API declarations |
| `src/keylogger.c` | 624 | Platform-specific keystroke capture (Linux evdev, macOS EventTap) |
| `src/keylogger.h` | 40 | Keylogger state struct and API |

## Port Knocking

The victim starts with no open sockets, listening for knock packets exclusively through pcap on the loopback interface (`lo`/`lo0`). A BPF filter restricts capture to `udp dst portrange 5001-5003`. The commander sends three single-byte UDP datagrams to ports 5001, 5002, 5003 with payload bytes 0x00, 0x01, 0x02 at 150ms intervals. The victim's pcap handler validates the source IP consistency, payload-byte-to-index matching, and a 2-second sequence timeout. On success, pcap is closed, UDP ports 7777 (covert) and 9999 (collector) are bound, and a session is activated with the peer's IP address locked in.

## Covert Channel Protocol

The custom protocol over UDP uses network-byte-order fields: 4-byte sequence number, 1-byte command, 2-byte payload length, variable payload (max ~1380 bytes), and 2-byte internet checksum (RFC 1071). Sequence numbers start at `0x13370000`. Stale packets (seq < expected) are silently discarded; mismatch packets trigger an error response. The command set includes heartbeat, keylogger start/stop, command execution with output streaming, file get/put with chunked transfer, file/directory watch, disconnect, and uninstall. Response commands include OK, ERROR, and ACK.

Multi-packet operations (file transfer, command output) use an ACK-based stop-and-wait streaming protocol. Each chunk is acknowledged before the next is sent, providing reliable delivery over lossy UDP.

## Keylogger

The keylogger on Linux opens `/dev/input/eventN` in non-blocking mode and polls for `EV_KEY` events. On macOS, it creates a CGEventTap for `kCGEventKeyDown` and schedules it on a dedicated CFRunLoop thread. Both platforms map known keycodes (A-Z, 0-9, Space, Enter, Tab, Backspace, Escape) to human-readable tokens; unknown keys are logged as `[KEY_N]`. Log file is `/tmp/victim_keylog.log`. The keylogger thread uses a mutex to protect the log file handle and running flag.

## File/Directory Watching

File watches use `stat()` polling (once per second in the session poll loop) to track `st_mtime` and `st_size`. Directory watches compute a FNV-1a-derived hash over a sorted list of directory entries including each entry's `st_mtime`, `st_size`, and `st_mode`. Change events are sent asynchronously on the collector port (UDP 9999) using a lightweight `network_message_t` structure.

## Process Concealment

The victim renames itself to `[kworker/u16:4]` on startup. On Linux, `prctl(PR_SET_NAME)` sets the kernel-side process name, and argv[0] is overwritten by locating the end of the environment block and zeroing out the contiguous argv/environ memory region. On macOS, the total extent of argv + environ memory is computed and zeroed after writing the concealment string. DYLD_INSERT_LIBRARIES and DYLD_LIBRARY_PATH are stripped.

## Challenges Encountered

1. **pcap interface selection**: `pcap_open_live("any")` is Linux-specific. The code falls back to `lo0` (macOS) then `lo` (other BSDs), then enumerates all devices via `pcap_findalldevs`.

2. **Link-layer header handling**: pcap provides different datalink types (DLT_LINUX_SLL, DLT_NULL, DLT_EN10MB, DLT_RAW). The knock handler must compute the correct IP header offset for each.

3. **Sequence number synchronization**: Both sides must agree on initial sequence values and increment behavior. The commander increments `next_seq` before each send; the victim increments `expected_seq` upon receipt before processing. The commander's `expected_response_seq` starts matching the victim's `next_seq`.

4. **UDP address binding for collector**: Both sides bind UDP port 9999. The victim uses it to send watch events; the commander uses it to receive them. SO_REUSEADDR/SO_REUSEPORT is enabled to allow binding.

5. **/etc/shadow restriction**: Direct file watch on `/etc/shadow` is prohibited per requirements. Solved by detecting the path and transparently redirecting to a directory watch on `/etc/` on the victim side.

## Limitations

- Communication works over loopback only (pcap on `lo0`/`lo`).
- Single session at a time.
- No encryption or authentication beyond the fixed port-knock sequence.
- Process concealment is cosmetic: it hides from `ps`/`htop` but not from tools that inspect open files, sockets, or memory maps.
- Keylogger requires root (Linux) or Accessibility permission (macOS).
- Port knock sequence and covert channel ports are fixed constants.
