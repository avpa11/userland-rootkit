#include <stdio.h>
#include "kb_listener.h" // Forward declaration

void kb_init(int fd) {
    printf("Keyboard initialized\n");
}

int kb_setup_listener(const char* device_path) {
    int fd = open(device_path, O_RDONLY);
    if (fd < 0) {
        perror("Error opening device");
        return -1;
    }
    
    // Initialize the keyboard listener state
    kb_state_init();
    
    printf("Listening on device: %s\n", device_path);
    kb_start_capture(fd);
    
    return 0;
}
