# Project 1

# User Guide


# Purpose

The Covert Channel Remote Administration Toolkit is a userland rootkit consisting of two components:

- **Victim** — An agent that runs on the target machine. It listens for a port-knock sequence via pcap, and on valid knock, opens a covert communication channel over UDP.
- **Commander** — An interactive controller that connects to the victim, issues commands, and receives responses over the covert channel.

Features include keystroke logging, remote command execution, bidirectional file transfer, file/directory change monitoring with asynchronous alerts, and process concealment.

# Installing

## Obtaining

```
git clone <repository-url>
cd source
```

## Requirements

| Dependency | Linux | macOS |
|-----------|-------|-------|
| GCC or Clang | required | required |
| libpcap | `sudo apt-get install libpcap-dev` | pre-installed |
| pthreads | pre-installed | pre-installed |
| linux/input.h (keylogger) | kernel headers | N/A |
| ApplicationServices (keylogger) | N/A | pre-installed |
| Root or sudo | required (pcap + keylogger) | required (pcap, keylogger needs Accessibility) |

## Building

```bash
make
```

This produces two binaries: `commander` and `victim`.

The Makefile auto-detects macOS vs Linux and adds `-framework ApplicationServices` when building on Darwin. Both binaries compile with `-O2 -Wall -Wextra -Wpedantic -std=gnu99`.

```bash
make clean  # Remove binaries
```

# Running

## Victim

The victim must run **as root** (for pcap capture and keylogger access):

```bash
sudo ./victim
```

The victim starts in **listening mode**, silently capturing UDP traffic on ports 5001-5003 via pcap — no sockets are open initially. The process renames itself to `[kworker/u16:4]` to appear benign in process listings.

**macOS keylogger note**: The keylogger uses CGEventTap on macOS, which requires Accessibility permission. Grant Terminal (or iTerm2) Accessibility access in System Preferences → Privacy & Security → Accessibility.

## Commander

```bash
./commander [victim_ip] [--connect|-c]
```

| Argument | Purpose |
| ----- | ----- |
| `victim_ip` | IPv4 address of the victim. Defaults to 127.0.0.1. |
| `--connect` / `-c` | Auto-connect on startup: port-knock then open session before showing the menu. |
| `--help` / `-h` | Print usage. |

# Menu Reference

## Disconnected Menu (initial state)

| # | Action |
|---|--------|
| 1 | Connect to victim — performs port knock sequence, opens covert session |
| 2 | Set victim IP — prompts for a new IPv4 address |
| 3 | Exit |

## Connected Menu (session active)

| # | Action |
|---|--------|
| 1 | Start keylogger — prompts for keyboard device path (default: `auto`) |
| 2 | Stop keylogger |
| 3 | Transfer keylog file from victim — downloads `/tmp/victim_keylog.log` |
| 4 | Transfer file **to** victim — upload a local file to the victim |
| 5 | Transfer file **from** victim — download a file from the victim |
| 6 | Watch a file on victim — monitors file for creation, modification, deletion |
| 7 | Watch a directory on victim — monitors directory for content changes |
| 8 | Run program on victim — executes a command via `/bin/sh -c`, streams output back |
| 9 | Send heartbeat — keep-alive check |
| 10 | Disconnect — closes session, returns to disconnected menu |
| 11 | Uninstall victim — shuts down victim agent and exits commander |
| 12 | Exit — prompts to disconnect first (clean exit) |

# Port Knocking Protocol

Commander sends 3 UDP datagrams to ports 5001, 5002, and 5003 on the victim IP. Each datagram contains a single byte matching the port index (0, 1, 2). Knock interval is 150ms.

The victim captures these via pcap with a BPF filter for `udp dst portrange 5001-5003`. The sequence must:
- Arrive from a **single, consistent source IP** (a different IP resets the sequence).
- Contain the **correct payload byte** for each port (mismatch resets the sequence).
- Complete within **2 seconds** (timeout resets the sequence).

# Covert Channel

After a successful knock, both sides bind UDP port 7777. All command and response traffic uses a custom binary protocol with:
- 4-byte sequence numbers (starting from `0x13370000`)
- 1-byte command identifier
- 2-byte payload length
- Variable-length payload (max ~1380 bytes)
- 2-byte internet checksum (RFC 1071)

Watch events are sent asynchronously on a separate UDP port (9999) so they do not interfere with command/response traffic. The commander has a dedicated collector listener thread on this port.

# Keylogger

## Linux

The keylogger reads from `/dev/input/event*` devices. When prompted for a device path:
- Enter a specific path like `/dev/input/event3`
- Enter `auto` to use the platform default (`/dev/input/event0`)
- Press Enter (blank) to use the default

Requires root privileges to open the input device.

## macOS

The keylogger uses a CGEventTap registered for `kCGEventKeyDown` events. When prompted:
- Enter `auto` or press Enter to use the event tap

Requires Accessibility permission granted to the terminal application.

## Keylog File

Keystrokes are logged to `/tmp/victim_keylog.log` on the victim. Known keys (A-Z, 0-9, Space, Enter, Tab, Backspace, Escape) are mapped to readable characters. Unknown keys appear as `[KEY_N]`. Sessions are delimited by START/STOP timestamps.

# File Transfer

## Upload (Commander → Victim)

1. Prompts for local source path and remote destination path (defaults to basename of local file).
2. Commander sends the file in chunks via `CMD_FILE_PUT_BEGIN`, `CMD_FILE_PUT_CHUNK` (per-chunk), and `CMD_FILE_PUT_END`.
3. Victim writes to a `.part` temp file and renames on completion.
4. Each chunk is acknowledged before the next is sent (reliable delivery).

## Download (Victim → Commander)

1. Prompts for remote path on victim and local destination path (defaults to basename of remote file).
2. Commander sends `CMD_FILE_GET` with the remote path.
3. Victim streams data in `CMD_FILE_DATA` chunks.
4. Commander writes to a `.part` temp file and renames on completion.

# File and Directory Watching

File watches use `stat()` polling every second while a session is active. The victim tracks `st_mtime` and `st_size`.

Directory watches compute a hash signature over sorted directory entries (name + stat info). Any change to the directory's entries or their metadata triggers an alert.

**Special case — `/etc/shadow`**: Per requirements, `/etc/shadow` cannot be watched directly. When a file watch is requested for `/etc/shadow`, it is transparently converted to a directory watch on `/etc/`. Any change within `/etc/` will generate an alert.

Watch alerts appear asynchronously on the commander console prefixed with `[collector] Alert:`.

# Remote Command Execution

Commands are executed on the victim via `/bin/sh -c <command>`. Standard output and standard error are captured through a pipe and streamed back to the commander. Exit status is reported when the command completes. If a command produces no output, `(no output)` is displayed.

# Process Concealment

On startup, the victim overwrites its process name in argv[0] to `[kworker/u16:4]`. This is visible in `ps`, `htop`, and similar tools. Environment variables that could reveal the origin (DYLD_INSERT_LIBRARIES, DYLD_LIBRARY_PATH on macOS) are also cleared.

# Uninstall

The uninstall command (menu option 11):
1. Sends `CMD_UNINSTALL` to the victim.
2. Victim acknowledges, deactivates the session, and exits.
3. Commander exits.
4. The victim binary is **not deleted** from disk — uninstall only terminates the running process.

# Examples

## Typical Session

**Terminal 1 (Victim):**
```bash
$ sudo ./victim
Victim agent started (pcap-based knock detection)
```

**Terminal 2 (Commander):**
```bash
$ ./commander 127.0.0.1 --connect
Commander started
Collector listening on UDP port 9999
Connecting to 127.0.0.1...
Port-knocking 127.0.0.1 on UDP ports 5001 5002 5003
Session active with 127.0.0.1
```

**Commander menu — starting keylogger:**
```
> 1
Keyboard device path [auto]:
Victim OK: keylogger started for event-tap
```

**Commander menu — running a command:**
```
> 8
Program/command to run on victim: uname -a
Victim output:
Darwin hostname 24.5.0 Darwin Kernel Version 24.5.0 ...
Victim OK: command exited with status 0
```

**Commander menu — transferring a file:**
```
> 5
Remote file path on victim: /etc/hosts
Local destination path [hosts]:
Requesting /etc/hosts from victim...
Victim OK: transferred /etc/hosts
```

**Commander menu — watching a file:**
```
> 6
Remote file path to watch: /tmp/test.txt
Victim OK: watching file /tmp/test.txt
```

After modifying the file on the victim:
```
[collector] Alert: File watch: /tmp/test.txt (changed (size=42))
```

**Commander menu — disconnecting:**
```
> 10
Victim ACK: disconnect ok

Commander Menu
Victim: 127.0.0.1
...
> 3
Commander exiting
```

# Troubleshooting

| Issue | Solution |
|-------|----------|
| `Unable to open capture interface` (victim) | Run victim as root. Ensure pcap is installed. |
| `bind UDP port` errors | Check that ports 7777 and 9999 are not in use. |
| `cannot create event tap` (macOS keylogger) | Grant Accessibility permission to the terminal in System Preferences. |
| `cannot open /dev/input/eventN` (Linux keylogger) | Ensure the device path exists and is readable as root. |
| Commander times out waiting for response | Verify the victim is running and the knock sequence completed. Check network connectivity. |
| `bind UDP port 9999 failed` (commander) | The collector port is already in use. Only one commander instance can run at a time with the default port. |
| `Invalid menu choice` | Enter a number corresponding to the desired menu option. |
