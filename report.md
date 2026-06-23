# Project 1 — Report: Covert Channel Remote Administration Toolkit

## Abstract

This report details the design and implementation of a userland rootkit consisting of two components: a **Commander** (controller) and a **Victim** (agent). The system uses pcap-based port knocking to establish a session, then communicates exclusively through a covert UDP channel with a custom binary protocol. Features include keylogging, file transfer, remote command execution, file/directory monitoring, and process concealment.

---

## 1. System Design

### 1.1 High-Level Architecture

```
┌──────────────┐                              ┌──────────────┐
│  Commander   │                              │    Victim    │
│              │── port knock (UDP 5001-5003)─→│ (pcap)       │
│              │                              │              │
│              │←── session (UDP 7777) ──────→│ (UDP socket) │
│              │                              │              │
│              │←── watch events (UDP 9999) ──│ (UDP socket) │
└──────────────┘                              └──────────────┘
```

### 1.2 Components

| Component | Source File | Purpose |
|-----------|-------------|---------|
| Commander | `src/Commander.c` | Interactive controller with menu-driven interface |
| Victim | `src/Victim.c` | Agent that runs on the target machine |
| Protocol | `src/protocol.c` / `protocol.h` | Packet framing, checksums, command definitions |
| Keylogger | `src/keylogger.c` / `keylogger.h` | Platform-specific keystroke capture |

---

## 2. Port Knocking

### 2.1 Mechanism

The port-knock sequence uses 3 UDP ports (5001, 5002, 5003) by default. The commander sends a single byte to each port in ascending order, where the byte value equals the port index (0, 1, 2).

The victim captures all UDP traffic via pcap with a BPF filter:
```
udp dst portrange 5001-5003
```

Key design decisions:
- **No open ports**: The victim uses pcap in promiscuous mode to snoop all matching packets without binding any sockets.
- **Source IP binding**: Once a knock sequence starts from a source IP, only packets from that same IP are accepted for the remainder of the sequence. A different source IP resets the sequence.
- **Timeout**: If the full sequence of 3 knocks is not received within 2 seconds, the sequence resets.
- **Sequence validation**: Each packet's payload byte must match the expected port index. Any mismatch resets the sequence.

### 2.2 Session Activation

Upon successful knock, the victim:
1. Closes the pcap handle (stops listening for knocks on all ports).
2. Binds UDP port 7777 for covert communication.
3. Binds UDP port 9999 for watch event notifications.
4. Sets the allowed peer address and begins sequencing at 0x13370000.

---

## 3. Covert Channel Protocol

### 3.1 Packet Format

```
|  Seq Num (4B)  |  Command (1B)  |  Payload Len (2B)  |  Payload (variable)  |  Checksum (2B)  |
```

All multi-byte fields are in network byte order (big-endian).

### 3.2 Command Set

| Value | Name | Direction | Description |
|-------|------|-----------|-------------|
| 0x01 | DISCONNECT | C→V | End session |
| 0x02 | HEARTBEAT | C→V | Keep-alive |
| 0x10 | KEYLOG_START | C→V | Start keylogger with device path |
| 0x11 | KEYLOG_STOP | C→V | Stop keylogger |
| 0x30 | EXEC_CMD | C→V | Run a command |
| 0x31 | EXEC_OUTPUT | V→C | Stream command output |
| 0x40 | FILE_GET | C→V | Request file download |
| 0x41 | FILE_DATA | V→C | Stream file data |
| 0x42 | FILE_PUT_BEGIN | C→V | Start file upload |
| 0x43 | FILE_PUT_CHUNK | C→V | Upload file chunk |
| 0x44 | FILE_PUT_END | C→V | Finalize file upload |
| 0x50 | WATCH_FILE | C→V | Start file watch |
| 0x51 | WATCH_DIR | C→V | Start directory watch |
| 0xFE | UNINSTALL | C→V | Shutdown victim |
| 0xF0 | OK | V→C | Success response |
| 0xF1 | ERROR | V→C | Error response |
| 0xF2 | ACK | V→C | Chunk acknowledge |

### 3.3 Sequence Numbers

Both sides maintain two sequence counters:
- `next_seq`: The sequence number for the next outgoing packet.
- `expected_seq`: The sequence number for the next expected incoming packet.

Both counters are initialized to `0x13370000u` at session start.

On the victim side, when a correct sequence number is received, `expected_seq` is incremented before processing the command. Stale packets (seq < expected) are silently ignored. Mismatches (seq > expected) cause an error response.

On the commander side, the expected response sequence starts matching the initial SEQ_INIT value from the victim.

### 3.4 Checksums

Uses the standard Internet checksum (RFC 1071): 16-bit one's complement sum, with end-around carry, of all bytes in the packet excluding the checksum field itself.

### 3.5 Streaming Protocol

For multi-packet operations (file transfers and command execution output), an ACK-based window protocol is used:

1. Sender transmits a data packet (FILE_DATA or EXEC_OUTPUT).
2. Receiver validates the packet and sends an ACK (CMD_ACK).
3. Sender waits for the ACK before sending the next chunk.
4. After the final chunk, sender transmits a completion packet (CMD_OK or CMD_ERROR).

This prevents UDP buffer overflow and ensures reliable delivery over the lossy channel.

### 3.6 Watch Event Notification Channel

File/directory watch events are sent on a separate UDP port (9999) using a simpler message format. This separation prevents watch alerts from interfering with command/response sequencing on the covert channel.

The watch message format (`network_message_t`):
```
| message_type (int) | filename (char) | payload (512B) | payload_len (int) |
```

The commander runs a collector listener thread on port 9999 to print received watch events.

---

## 4. Implemented Features

### 4.1 Keylogger

The keylogger captures keyboard events and writes them to `/tmp/victim_keylog.log`.

**Linux implementation**: Opens `/dev/input/eventN` with `O_RDONLY | O_NONBLOCK`. Uses `poll()` to wait for input events, then reads `struct input_event` records. Only captures `EV_KEY` events with value 1 (press) or 2 (repeat). Key codes are mapped to human-readable characters.

**macOS implementation**: Creates a CGEventTap for `kCGEventKeyDown` events. Requires Accessibility permission. The callback formats key codes into readable text. The tap runs on a CFRunLoop in a separate thread.

**Supported key mappings**: A-Z, 0-9, Space, Return/Enter, Tab, Backspace/Delete, Escape. Unknown keys are logged as `[KEY_N]` where N is the raw keycode.

### 4.2 Remote Command Execution

Uses `fork()` + `exec()` to run commands via `/bin/sh -c`. Standard output and standard error from the child process are captured through a pipe and streamed back to the commander via the EXEC_OUTPUT/ACK protocol.

If the command produces no output, `(no output)` is sent as a placeholder. The commander displays the exit status (value or signal) when the command completes.

### 4.3 File Transfer

**Commander → Victim (upload)**: Three-phase protocol:
1. `CMD_FILE_PUT_BEGIN` — Sends the destination path; victim creates a `.part` temp file.
2. `CMD_FILE_PUT_CHUNK` — Repeated for each chunk of file data; victim writes to the temp file.
3. `CMD_FILE_PUT_END` — Victim closes the temp file and renames it to the target path.

**Victim → Commander (download)**: Uses `CMD_FILE_GET` to request a file, then the victim streams data via `CMD_FILE_DATA` chunks. The commander writes to a `.part` temp file and renames on completion.

### 4.4 File Watching

Uses `stat()` polling in the victim's main event loop (once per second when session is active):

- **File watch**: Tracks `st_mtime` and `st_size`. Detects creation, modification, and deletion.
- **Directory watch**: Computes a hash signature over sorted directory entries (names + mtime + size + mode). Detects any content change within the directory.

Changes trigger watch events sent to the commander's collector port.

### 4.5 /etc/shadow Special Handling

Per requirements, the /etc/shadow file cannot be watched directly. When the commander requests a file watch on `/etc/shadow`:

The commander detects the path and informs the user it will watch the parent directory instead. It sends the unchanged `/etc/shadow` path to the victim. On the victim side, `watch_remote_file()` calls `path_is_shadow()` which detects `/etc/shadow` and automatically redirects to a directory watch on `/etc/`. This ensures any changes to shadow or other files in `/etc` are detected.

### 4.6 Process Concealment

On startup, the victim calls `conceal_process()` which modifies `argv[0]` memory to display `[kworker/u16:4]` in process listings.

**Linux**: After `prctl(PR_SET_NAME)`, it finds the end of the environment block relative to argv[0] and overwrites argv[0] with the concealment string, followed by null bytes to clear remaining argv entries and environment strings from the contiguous memory block.

**macOS**: Calculates the total length of argv + environ memory, then overwrites argv[0] with the concealment string and zeroes the remaining memory. Also strips `DYLD_INSERT_LIBRARIES` and `DYLD_LIBRARY_PATH` environment variable values to prevent detection via library injection traces.

### 4.7 Uninstall

The uninstall command sends `CMD_UNINSTALL`. The victim acknowledges, deactivates the session, and sets `g_running = 0` to exit the main loop. The commander also exits after the uninstall.

---

## 5. Implementation Details

### 5.1 Commander State Machine

The commander operates in two states:

**Disconnected**:
- Can set victim IP
- Can initiate connection (port knock + session open)
- Can exit

**Connected**:
- Full feature access (keylogger, file transfer, watches, commands)
- Can disconnect (returns to disconnected state)
- Can uninstall (exits commander)
- Exit warns to disconnect first

### 5.2 Victim Event Loop

The victim alternates between two polling states:

**Knock polling** (no session active):
- `pcap_dispatch()` in a loop, blocking for up to 500ms
- BPF filter on UDP port range 5001-5003
- Knock sequence validation with timeout

**Session polling** (session active):
- `select()` on covert socket with 1-second timeout
- Process incoming covert packets
- Poll watch targets for changes

### 5.3 Concurrency

- **Victim keylogger**: Runs in a dedicated thread. Mutex-protected access to the log file and running flag.
- **Commander collector**: Runs in a dedicated thread. Listens for watch events on UDP port 9999.
- **Victim command execution**: Uses `fork()` to create a child process. Parent reads output from pipe and streams to commander.

---

## 6. Security Considerations

- No encryption on the covert channel.
- Port knock sequence is fixed (no one-time password or challenge-response).
- Covert channel uses a simple fixed port (7777).
- Process concealment only hides from ps/htop; it does not hide from tools that scan open files, sockets, or memory maps.
- Nothing prevents detection via packet capture analysis of the custom protocol.

---

## 7. Platform Compatibility

The code supports both Linux and macOS with platform-specific implementations where needed:

| Feature | Linux | macOS |
|---------|-------|-------|
| pcap interface | `lo` | `lo0` |
| Keylogger | `/dev/input/event*` evdev | CGEventTap |
| Process concealment | `prctl` + argv overwrite | argv overwrite + env stripping |
| Pthreads | Yes | Yes |
| Sockets | POSIX | POSIX |

---

## 8. What Was Fixed

The following requirements were addressed during review:

1. **`/etc/shadow` handling**: Added `path_is_shadow()` detection on the victim and commander-side awareness. When a file watch targets `/etc/shadow`, it is automatically converted to a directory watch on `/etc/`.

2. **Process name concealment**: Rewrote `conceal_process()` to properly overwrite `argv[0]` on both platforms. Linux uses the argv/environ contiguous memory overwrite technique. macOS calculates memory extent and zeroes argv/environ after the concealment string. DYLD env var stripping retained for macOS.

3. **Compilation**: All warnings resolved. Builds cleanly with `-Wall -Wextra -Wpedantic -std=gnu99 -O2`.
