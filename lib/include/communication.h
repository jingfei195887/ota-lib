#ifndef __INC_COMMUNICTION_H
#define __INC_COMMUNICTION_H

#ifdef __cplusplus
extern "C" {
#endif

#define  MAX_FD             4
#define  MAX_BUF_LEN        1024
#define  DISCNNT_TIME       20*1000
#define  FD_NAME_LEN        24
#define  FD_CALL_BACK_LEN   24
#define  ACTIVE_NOW         1
#define  ACTIVE_LATER       0

typedef struct {
    int      active;
    int      fd;
    int      start;
    int      rd_cursor;
    char     buf[MAX_BUF_LEN];
    void     (*read)(void *);
    void     (*process)(void *, int);
    void     *arg;
    char     fd_name[FD_NAME_LEN];
    char     call_back_name[FD_CALL_BACK_LEN];
} FD;

typedef enum handshake_status {
    HANDSHAKE_OK,
    HANDSHAKE_ERROR,
    HANDSHAKE_AlREADY,
} handshake_status_e;


extern handshake_status_e get_handshake_status(int timeout_s);
extern void tcp_poll_enable();
extern void tcp_poll_disable();
extern int  client_handshake_to_server();
extern int tcp_listen();
extern void close_listen();
extern void closeCnnt(int fd);
extern int tcp_client_init(int timeout_s);
extern void close_client();
extern void wait_ms(int ms_unit);
#ifdef __cplusplus
}
#endif

#endif  /*__INC_COMMUNICTION_H*/