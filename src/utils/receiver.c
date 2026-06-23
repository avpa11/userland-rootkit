#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define PORT 9999
#define FILE_CHUNK 512

struct NetworkMessage {
    int message_type;
    char filename;
    char payload[FILE_CHUNK];
    int payload_len;
};

int main() {
    int sock;
    struct sockaddr_in server_addr;
    struct NetworkMessage incoming;

    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) return 1;

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    if (bind(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) return 1;

    printf("Collector listening on port %d...\n", PORT);

    while (1) {
        int bytes = recvfrom(sock, &incoming, sizeof(struct NetworkMessage), 0, NULL, NULL);
        if (bytes < 0) continue;

        if (incoming.message_type == 1) {
            printf("[ALERT] Directory Event: %s\n", incoming.payload);
        } 
        else if (incoming.message_type == 2) {
            // File block transfers logic (omitted here for brevity)
        } 
        else if (incoming.message_type == 3) {
            // Feature: Parse and display execution results
            if (incoming.payload_len > 0) {
                printf("[EXEC OUTPUT]: %s", incoming.payload);
            } else {
                printf("[EXEC COMPLETE]\n");
            }
        }
    }
    close(sock);
    return 0;
}
