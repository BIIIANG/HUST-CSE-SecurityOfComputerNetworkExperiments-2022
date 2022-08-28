#define VPN_VIRTUAL_IP_POOL "192.168.53."
#define VPN_SERVER_VIRTUAL_IP "192.168.53.1"
#define VPN_INTERNAL_NET "192.168.60.0/24"
#define VPN_SERVER_REAL_IP "10.0.2.8"
#define VPN_SERVER_PORT 4433

#define NO_ERROR 0
#define SETUP_TLS_ERROR -1
#define SETUP_TCP_ERROR -1
#define SSL_CONNECTION_ERROR -1
#define TUN_DEVICE_ERROR -1
#define PIPE_ERROR -1
#define INET_FUNC_ERROR -1
#define AUTHENTICATION_ERROR -1

#define CHK_EXP_STR_RET(exp, strErr) \
    if (exp) {                       \
        printf(strErr);              \
        return;                      \
    }

#define CHK_EXP_STR_RET_VAL(exp, strErr, returnCode) \
    if (exp) {                                       \
        printf(strErr);                              \
        return (returnCode);                         \
    }

#define CHK_EXP_STR_RET_STR(exp, strErr, returnCode, strSucc) \
    CHK_EXP_STR_RET_VAL(exp, strErr, returnCode)              \
    else {                                                    \
        printf(strSucc);                                      \
    }

#define CHK_EXP_STR_EXIT(exp, strErr, exitCode, ...) \
    if (exp) {                                       \
        printf(strErr, ##__VA_ARGS__);               \
        exit(exitCode);                              \
    }

#define CHK_EXP_STR_EXIT_STR(exp, strErr, exitCode, strSucc, ...) \
    CHK_EXP_STR_EXIT(exp, strErr, exitCode, ##__VA_ARGS__)        \
    else {                                                        \
        printf(strSucc);                                          \
    }

#define CHK_SSL_STR_RET(exp, strErr, ...) \
    if (exp) {                            \
        printf(strErr, ##__VA_ARGS__);    \
        ERR_print_errors_fp(stderr);      \
        return;                           \
    }

#define CHK_SSL_STR_RET_VAL(exp, strErr, returnCode, ...) \
    if (exp) {                                            \
        printf(strErr, ##__VA_ARGS__);                    \
        ERR_print_errors_fp(stderr);                      \
        return (returnCode);                              \
    }

#define CHK_SSL_EXIT(exp, exitCode)  \
    if (exp) {                       \
        ERR_print_errors_fp(stderr); \
        exit(exitCode);              \
    }

#define CHK_SSL_STR_EXIT(exp, strErr, exitCode, ...) \
    if (exp) {                                       \
        printf(strErr, ##__VA_ARGS__);               \
        ERR_print_errors_fp(stderr);                 \
        exit(exitCode);                              \
    }

#define CHK_SSL_STR_EXIT_STR(exp, strErr, exitCode, strSucc, ...) \
    CHK_SSL_STR_EXIT(exp, strErr, exitCode, ##__VA_ARGS__)        \
    else {                                                        \
        printf(strSucc);                                          \
    }

void printPrintable(char* buf, int len) {
    if (len >= 20) {
        printf("(%u.%u.%u.%u => %u.%u.%u.%u)\n", (uint8_t)buf[12], (uint8_t)buf[13], (uint8_t)buf[14],
               (uint8_t)buf[15], (uint8_t)buf[16], (uint8_t)buf[17], (uint8_t)buf[18], (uint8_t)buf[19]);
    }
    printf("\033[2m");
    int chrPerLine = 16;
    int lineNum = len / chrPerLine + (len % chrPerLine == 0 ? 0 : 1);
    for (int line = 0; line < lineNum; line++) {
        for (int i = 0; i < chrPerLine; i++) {
            printf("%02x ", (unsigned char)buf[line * chrPerLine + i]);
        }
        for (int i = 0; i < chrPerLine; i++) {
            if (isprint(buf[line * chrPerLine + i])) {
                putchar(buf[line * chrPerLine + i]);
            } else {
                printf("·");
            }
        }
        if (line != lineNum - 1) { putchar('\n'); }
    }
    printf("\n\033[0m");
}
