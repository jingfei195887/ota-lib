#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <strings.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <stdlib.h>
#include <sys/poll.h>
#include <pthread.h>
#include <time.h>
#include "system_cfg.h"
#include "slots_parse.h"
#include "communication.h"
#include "crc32.h"


static pthread_t          tid;
static bool               polling = false;
static FD                 fdt[MAX_FD];
static int                global_poll_fd_num = 0;
static struct             pollfd global_poll_fds[MAX_FD];
static pthread_mutex_t    mutex   = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t    recv_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t     recv_cond = PTHREAD_COND_INITIALIZER;
static pthread_cond_t     handshake_cond = PTHREAD_COND_INITIALIZER;
static uint8_t            *global_recv_msg = NULL;
static int                client_sock_fd = -1;
static int                server_sock_fd = -1;

static int tcp_send(ota_op_t *op, uint8_t *senddata, ssize_t len);

#if DEBUGMODE
static void hexdump8(const void *ptr, size_t len)
{
    unsigned long address = (unsigned long)ptr;
    size_t count;
    size_t i;

    for (count = 0 ; count < len; count += 16) {
        for (i = 0; i < MIN(len - count, 16); i++) {
            PRINTF("%02hhx ", *(const uint8_t *)(address + i));
        }

        PRINTF("\n");
        address += 16;
    }
}
#endif

static void set_server_socket(int fd)
{
    pthread_mutex_lock(&mutex);
    server_sock_fd = fd;
    pthread_mutex_unlock(&mutex);
}

static int get_server_socket()
{
    int ret = -1;
    pthread_mutex_lock(&mutex);
    ret = server_sock_fd;
    pthread_mutex_unlock(&mutex);
    return ret;
}

static void set_client_socket(int fd)
{
    pthread_mutex_lock(&mutex);
    client_sock_fd = fd;
    pthread_mutex_unlock(&mutex);
}

static int get_client_socket()
{
    int ret = -1;
    pthread_mutex_lock(&mutex);
    ret = client_sock_fd;
    pthread_mutex_unlock(&mutex);
    return ret;
}

static int put_data(uint8_t *target, int offset, const uint8_t *value,
                    size_t size)
{
    for (size_t i = 0; i < size; i++, offset++) {
        *(target + offset) = value[i];
    }

    return offset;
}

static int put_char(uint8_t *target, int offset, uint8_t value)
{
    return put_data(target, offset, &value, sizeof(value));
}

handshake_status_e get_handshake_status(int timeout_s)
{
    struct timespec time_to_wait = {0, 0};
    pthread_mutex_lock(&mutex);

    if (timeout_s > 0) {
        time_to_wait.tv_sec = time(NULL) + timeout_s;

        if (0 != pthread_cond_timedwait(&handshake_cond, &mutex, &time_to_wait)) {
            PRINTF_CRITICAL("wait handshake error %s\n", strerror(errno));
            pthread_mutex_unlock(&mutex);
            return HANDSHAKE_ERROR;
        }
    }
    else {
        pthread_cond_wait(&handshake_cond, &mutex);
    }

    pthread_mutex_unlock(&mutex);
    return HANDSHAKE_OK;
}

static void set_handshake_status(bool val)
{
    pthread_mutex_lock(&mutex);
    pthread_cond_signal(&handshake_cond);
    pthread_mutex_unlock(&mutex);
}

static void init_fd_array()
{
    pthread_mutex_lock(&mutex);
    memset(fdt, 0, MAX_FD * sizeof(FD));
    pthread_mutex_unlock(&mutex);
}

static void update_fd_array()
{
    int i;
    pthread_mutex_lock(&mutex);
    global_poll_fd_num = 0;

    for (i = 0; i < MAX_FD; i++) {
        if (fdt[i].active) {
            global_poll_fds[global_poll_fd_num].fd = fdt[i].fd;
            global_poll_fds[global_poll_fd_num].events = POLLIN;
            global_poll_fd_num++;
        }
    }

    pthread_mutex_unlock(&mutex);
}

static int get_empty_node(int fd)
{
    int i;
    pthread_mutex_lock(&mutex);

    /* check if fd alread in the fds */
    for (i = 0; i < MAX_FD; i++) {
        if (fdt[i].fd == fd) {
            pthread_mutex_unlock(&mutex);
            return i;
        }
    }

    /* get an empty node */
    for (i = 0; i < MAX_FD; i++) {
        if (!fdt[i].active && (fdt[i].fd <= 0)) {
            pthread_mutex_unlock(&mutex);
            return i;
        }
    }

    pthread_mutex_unlock(&mutex);
    return -1;
}

static int get_node_by_fd(int fd)
{
    int i;
    pthread_mutex_lock(&mutex);

    for (i = 0; i < MAX_FD; i++) {
        if (fdt[i].fd == fd) {
            pthread_mutex_unlock(&mutex);
            return i;
        }
    }

    pthread_mutex_unlock(&mutex);
    return -1;
}

static int add_fd_array(int fd, void (*func)(void *), void (*process)(void *,
                        int),
                        void *arg, int is_active_now, char *fd_name, char *call_back_name)
{
    int node = get_empty_node(fd);

    if ((node >= MAX_FD) || (node < 0)) {
        PRINTF_CRITICAL("get fd node error\n");
        return -1;
    }

    pthread_mutex_lock(&mutex);
    memset(&fdt[node], 0, sizeof(FD));
    fdt[node].fd = fd;
    fdt[node].read = func;
    fdt[node].process = process;
    fdt[node].arg = arg;
    fdt[node].rd_cursor = 0;
    fdt[node].active = is_active_now;
    snprintf(fdt[node].fd_name, FD_NAME_LEN, "%s", fd_name);
    snprintf(fdt[node].call_back_name, FD_CALL_BACK_LEN, "%s", call_back_name);
    pthread_mutex_unlock(&mutex);
    update_fd_array();
    return 0;
}

#if 0
static int fdIsActive(int fd)
{
    int node = get_node_by_fd(fd);

    if ((node >= MAX_FD) || (node < 0)) {
        PRINTF_CRITICAL("get fd node error\n");
        return -1;
    }

    return fdt[node].active;
}

static void enableFdNode()
{
    int i;
    pthread_mutex_lock(&mutex);

    for (i = 0; i < MAX_FD; i++) {
        if (fdt[i].fd > 0 && !fdt[i].active)
            fdt[i].active = ACTIVE_NOW;
    }

    pthread_mutex_unlock(&mutex);
    update_fd_array();
}
#endif

static void delFdNode(int fd)
{
    int node = get_node_by_fd(fd);

    if ((node >= MAX_FD) || (node < 0)) {
        PRINTF_CRITICAL("get fd node error\n");
        return;
    }

    pthread_mutex_lock(&mutex);
    memset(&fdt[node], 0, sizeof(FD));
    pthread_mutex_unlock(&mutex);
    update_fd_array();
}

static void fdSelect()
{
    FD *fdt_ready;
    int i;
    int fd_num;
    struct pollfd poll_fds;
    int node = -1;
    PRINTF_INFO("OTA polling...%d\n", global_poll_fd_num);

    fd_num = poll(global_poll_fds, global_poll_fd_num, 1000);

    if (fd_num == 0) {
        PRINTF_INFO("OTA waiting for handshake...\n");
        return;
    }

    /* skip EAGIN and EINTR */
    if (fd_num < 0 && errno != EAGAIN && errno != EINTR) {
        PRINTF_CRITICAL("poll error: %s\n", strerror(errno));

        for (i = 0; i < MAX_FD; i++) {
            if (fdt[i].active == ACTIVE_NOW) {
                poll_fds.fd = fdt[i].fd;
                poll_fds.events = POLLIN;
                fd_num = poll(&poll_fds, 1, 0);

                if ((fd_num < 0) && (errno == EBADF)) {
                    PRINTF_INFO("delete fdt[%d].fd = %d", i, fdt[i].fd);
                    delFdNode(fdt[i].fd);
                }
            }
        }

        return;
    }

    for (i = 0; i < global_poll_fd_num; i++) {
        if (global_poll_fds[i].revents & POLLIN) {
            node = get_node_by_fd(global_poll_fds[i].fd);

            if ((node >= MAX_FD) || (node < 0)) {
                PRINTF_CRITICAL("get fd node error");
                return;
            }

            fdt_ready = &(fdt[node]);

            if (fdt_ready->active == ACTIVE_NOW) {
                PRINTF_INFO("global_poll_fds %d:%s is active, call handler %s\n", fdt_ready->fd,
                            fdt_ready->fd_name, fdt_ready->call_back_name);
                fdt_ready->read(fdt_ready);
            }
        }
    }
}

void *msg_poller(void *arg)
{
    while (polling) {
        fdSelect();
    }

    pthread_exit(NULL);
}

void tcp_poll_enable()
{
    polling = true;

    /* create pthread poll recv msg */
    pthread_create(&tid, NULL, msg_poller, NULL);

    /* detach a thread */
    pthread_detach(tid);
}

void tcp_poll_disable()
{
    polling = false;
}

static int msg_wrapper(int cmd, uint8_t *data, uint16_t data_len, uint8_t *out)
{
    uint16_t i = 0;
    ota_msg_head_struct_t *head;
    uint16_t total_len = data_len + MSG_HEAD_SIZE;
    int offset = MSG_HEAD_SIZE;

    if (!out) {
        PRINTF_CRITICAL("msg wrapper para error\n");
        return -1;
    }

    if (cmd >= OTA_CMD_MAX) {
        PRINTF_CRITICAL("msg wrapper cmd = %s error\n",
                        get_ota_cmd_str(cmd));
        return -1;
    }

    if (total_len > MAX_SEND_LENGTH) {
        PRINTF_CRITICAL("msg wrapper send length error,cmd = %s length = %d\n",
                        get_ota_cmd_str(cmd), data_len);
        return -1;
    }

    /* head */
    head = (ota_msg_head_struct_t *)out;
    head->flag1 = OTA_START_MAGIC;
    head->len = data_len;
    head->cmd = cmd;
    head->crc = 0;
    head->flag2 = OTA_END_MAGIC;

    /* data */
    if ((0 != data_len) && (NULL != data)) {
        for (i = 0; i < data_len; i++) {
            offset = put_char(out, offset, data[i]);
        }
    }

    /* crc */
    head->crc = crc32(0, out, total_len);

#if DEBUGMODE > 1
    PRINTF("send msg:\n");
    hexdump8((void *)out, total_len);
#endif

    return 0;
}


static int msg_unwrapper(uint8_t *scr)
{
    ota_msg_head_struct_t *head;
    uint16_t total_len;
    uint32_t crc_val;

    if (!scr) {
        PRINTF_CRITICAL("msg unwrapper para error\n");
        return -1;
    }

    head = (ota_msg_head_struct_t *)scr;
    total_len = head->len + MSG_HEAD_SIZE;

    if ((total_len > MAX_RECV_LENGTH) || (total_len < MSG_HEAD_SIZE)) {
        PRINTF_CRITICAL("msg len error, total_len:%d\n", total_len);
        return -1;
    }

    if (head->flag1 != OTA_START_MAGIC) {
        PRINTF_CRITICAL("flag1 is 0x%04x, expect 0x%04x \n", head->flag1,
                        OTA_START_MAGIC);
        return -1;
    }

    if (head->flag2 != OTA_END_MAGIC) {
        PRINTF_CRITICAL("flag2 is 0x%04x, expect 0x%04x \n", head->flag2,
                        OTA_END_MAGIC);
        return -1;
    }

    crc_val = head->crc;
    head->crc = 0;
    head->crc = crc32(0, scr, total_len);

    if (crc_val != head->crc) {
        PRINTF_CRITICAL("crc = 0x%08x error, expect 0x%08x \n", crc_val, head->crc);
        return -1;
    }

    return 0;
}


static void recv_msg(FD *fd_item)
{
    int i;
    int recv_length;
    int one_msg_len;
    int fd = fd_item->fd;
    ota_msg_head_struct_t *head;

    PRINTF_DBG("recv msg start\n");
    pthread_mutex_lock(&recv_mutex);

    recv_length = recv(fd, fd_item->buf + fd_item->rd_cursor,
                       sizeof(fd_item->buf) - fd_item->rd_cursor, 0);

    if (recv_length > 0) {
        PRINTF_DBG("read cureor is begin %d\n", fd_item->rd_cursor);

        /* dump msg */
        for (i = 0; i < recv_length; i++) {
            PRINTF_DBG("fd_item->buf[%d] = 0x%x\n", i,
                       fd_item->buf[fd_item->rd_cursor + i]);
        }

        PRINTF_DBG("read cureor is end %d\n", fd_item->rd_cursor + recv_length);

        fd_item->rd_cursor += recv_length;

        while (fd_item->rd_cursor >= MSG_HEAD_SIZE) {
            head = (ota_msg_head_struct_t *)(fd_item->buf);
            one_msg_len = head->len + MSG_HEAD_SIZE;

            PRINTF_DBG("one msg len is %d\n", one_msg_len);

            /* msg head check */
            if ((head->flag1 == OTA_START_MAGIC) && (head->flag2 == OTA_END_MAGIC) &&
                    (one_msg_len <= MAX_RECV_LENGTH) && (one_msg_len >= MSG_HEAD_SIZE)) {

                PRINTF_DBG("msg complete\n");

                /* all complete recved */
                if (fd_item->rd_cursor >= one_msg_len) {
                    fd_item->rd_cursor -= one_msg_len;
                    PRINTF_INFO("start process\n");

                    if (fd_item->process) {
                        fd_item->process(fd_item, one_msg_len);
                    }

                    /* clear msg */
                    if (fd_item->rd_cursor > 0) {
                        memmove(fd_item->buf, fd_item->buf + one_msg_len, fd_item->rd_cursor);
                    }
                }
                else {
                    PRINTF_INFO("wait for complete msg\n");
                    break;
                }
            }
            else {
                PRINTF_INFO("msg head remove\n");

                for (i = 0; i < fd_item->rd_cursor; i++) {
                    head = (ota_msg_head_struct_t *)(fd_item->buf + i);
                    one_msg_len = head->len + MSG_HEAD_SIZE;

                    if ((head->flag1 == OTA_START_MAGIC) && (head->flag2 == OTA_END_MAGIC) &&
                            (one_msg_len <= MAX_RECV_LENGTH) && (one_msg_len >= MSG_HEAD_SIZE)) {
                        fd_item->rd_cursor -= i;
                        memmove(fd_item->buf, fd_item->buf + i, fd_item->rd_cursor);
                        PRINTF_INFO("remove complete\n");
                        break;
                    }
                }

                if (i == fd_item->rd_cursor) {
                    fd_item->rd_cursor = 0;
                }
            }
        }
    }

    /* recv_length is 0 indicates that the peer socket is closed properly */
    else if ((recv_length == 0) || (errno != EINTR && errno != EAGAIN)) {
        perror("client recv msg callback");
        closeCnnt(fd);
    }

    pthread_mutex_unlock(&recv_mutex);
}

int sever_reply_handshake_to_client(int fd, int len)
{
    ota_op_t op;
    int ret = -1;
    uint8_t msg[MAX_SEND_LENGTH] = {0};

    op.fd = fd;
    op.cmd = OTA_CMD_CHECK_AP_OK;
    op.timeout_ms = 5000;
    /* don't care recv cmd */
    /* op.expect_recv_cmd = OTA_CMD_CHECK_AP_OK; */

    ret = msg_wrapper(op.cmd, NULL, 0, msg);

    if (ret < 0) {
        PRINTF_CRITICAL("msg wrapper error\n");
        return -1;
    }

    ret = tcp_send(&op, msg, 0 + MSG_HEAD_SIZE);

    if (ret < 0) {
        PRINTF_CRITICAL("tcp send error\n");
        return -1;
    }

    set_handshake_status(true);
    return 0;
}

static void server_msg_process(FD *fd_item, int len)
{
    int ret = -1;
    ota_msg_head_struct_t *head = (ota_msg_head_struct_t *)(fd_item->buf);

    if (!head) {
        PRINTF_CRITICAL("para error\n");
        return;
    }

    ret = msg_unwrapper((uint8_t *)head);

    if (ret < 0) {
        PRINTF_CRITICAL("msg unwrapper error\n");
        return;
    }

    switch (head->cmd) {
        case OTA_CMD_CHECK_AP:
            sever_reply_handshake_to_client(fd_item->fd, len);
            break;

        default:
            PRINTF_CRITICAL("unknow cmd\n");
            break;
    }

    return;
}

static void tcpAccept(FD *fd_item)
{
    int optval = 1;
    int cnntsock;
    struct sockaddr_in cliaddr;
    int addrlen  = sizeof(cliaddr);

    /* On success, accept return a file descriptor for the accepted socket (a nonnegative integer).
       On error, -1 is returned, errno is set to indicate the error */
    cnntsock = accept(fd_item->fd, (struct sockaddr *)&cliaddr,
                      (socklen_t *)&addrlen);

    if (cnntsock <= 0) {
        PRINTF_CRITICAL("tcp accept error: %s\n", strerror(errno));

        if ((cnntsock != -1) || (errno != EWOULDBLOCK)) {
            PRINTF_CRITICAL("tcp accept error: %s, re-listen\n", strerror(errno));
            closeCnnt(fd_item->fd);
            tcp_listen();
        }
    }
    else {
        optval = 1;
        fcntl(cnntsock, F_SETFL, O_NONBLOCK);
        setsockopt(cnntsock, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval,
                   sizeof(int));
        add_fd_array(cnntsock, (void *)recv_msg,  (void *)server_msg_process, NULL,
                     ACTIVE_NOW, inet_ntoa(cliaddr.sin_addr), "server_recv_msg");
        PRINTF_INFO("tcp accepted: %s\n", inet_ntoa(cliaddr.sin_addr));
    }
}

int tcp_listen()
{
    int listensock;
    int recode;
    int flags;
    int optval = 1;
    struct sockaddr_in servaddr;

    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port   = htons(CHIPA_HANDSHAKE_LISTEN_PORT);
    servaddr.sin_addr.s_addr = 0;

    listensock = socket(PF_INET, SOCK_STREAM, 0);

    if (listensock < 0) {
        PRINTF_CRITICAL("tcp listen socket error\n");
        return -1;
    }

    flags = fcntl(listensock, F_GETFL);
    fcntl(listensock, F_SETFL, flags | O_NONBLOCK);

    if (-1 == setsockopt(listensock, SOL_SOCKET, SO_REUSEADDR,
                         (const void *)&optval,
                         sizeof(int))) {
        PRINTF_CRITICAL("setsockopt error %s\n", strerror(errno));
        close(listensock);
        return -1;
    }

    recode = bind(listensock, (struct sockaddr *)&servaddr, sizeof(servaddr));

    if (recode != 0) {
        PRINTF_CRITICAL("bind error %s\n", strerror(errno));
        close(listensock);
        return -1;
    }

    if (listen(listensock, 5) != 0) {
        PRINTF_CRITICAL("tcp listen error %s\n", strerror(errno));
        close(listensock);
        return -1;
    }

    init_fd_array();
    add_fd_array(listensock, (void *)tcpAccept, NULL, NULL, ACTIVE_NOW,
                 "listensock",
                 "tcpAccept");

    PRINTF_INFO("tcp listen begin, fd num = %d\n", global_poll_fd_num);
    PRINTF_INFO("listensock = %d\n", listensock);
    set_server_socket(listensock);

    return 0;
}

void closeCnnt(int fd)
{
    int node = get_node_by_fd(fd);

    if ((node >= MAX_FD) || (node < 0)) {
        PRINTF_CRITICAL("get fd node error\n");
        return;
    }

    close(fd);
    PRINTF_INFO("listensock %d closed\n", fd);
    delFdNode(fd);
}

void close_listen()
{
    int fd = get_server_socket();
    PRINTF_INFO("close listensock  = %d\n", fd);
    closeCnnt(fd);
}


void wait_ms(int ms_unit)
{
    struct timeval tv;
    fd_set readfds;
    FD_ZERO(&readfds);
    tv.tv_sec = ms_unit / 1000;
    tv.tv_usec = (ms_unit % 1000) * 1000;
    select(0, &readfds, NULL, NULL, &tv);
}


int tcp_client_connect(int sock_fd, struct sockaddr_in *server_addr,
                       int retry_cnt)
{
    int reconnect_times = 0;
    int res = -1;

    if (!server_addr) {
        PRINTF_CRITICAL("para error\n");
        return -1;
    }

    while (1) {
        PRINTF_INFO("try %d for connet ap1 ip=%s\n",  reconnect_times,
                    CHIPA_HANDSHAKE_IP);

        if ((retry_cnt > 0) && (reconnect_times == retry_cnt)) {
            PRINTF_INFO("time out\n");
            break;
        }

        reconnect_times++;

        res = connect(sock_fd, (struct sockaddr *)server_addr,
                      sizeof(struct sockaddr_in));

        if (0 == res) {
            PRINTF_INFO("socket connect succeed\n");
            break;
        }

        else if (errno == EINPROGRESS) {
            PRINTF_CRITICAL("connect in progress: %s\n", strerror(errno));
            wait_ms(1000);
            continue;
        }

        else if (errno == EALREADY) {
            PRINTF_CRITICAL("connect in already progress: %s\n", strerror(errno));
            wait_ms(1000);
            continue;
        }

        else if (errno == EISCONN) {
            PRINTF_CRITICAL("alread connected: %s\n", strerror(errno));
            res = 0;
            break;
        }

        else {
            PRINTF_CRITICAL("connect error:: %s\n", strerror(errno));
            wait_ms(1000);
            continue;
        }
    }

    return res;
}

static void client_msg_process(FD *fd_item, int len)
{
    if (global_recv_msg) {
        memcpy(global_recv_msg, (void *)(fd_item->buf), len);
        global_recv_msg = NULL;
        pthread_cond_signal(&recv_cond);
    }
    else {
        PRINTF_CRITICAL("msg process error\n");
    }
}

int tcp_client_init(int timeout_s)
{
    /* create a socket */
    struct sockaddr_in server_addr = {0};
    int flags;
    int sock_fd = -1;

    memset(&server_addr, 0, sizeof(struct sockaddr_in));

    sock_fd = socket(AF_INET, SOCK_STREAM, 0);

    if (sock_fd < 0) {
        PRINTF_CRITICAL("creat socket for tcp client error\n");
        return -1;
    }

    /* sever information */
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(CHIPA_HANDSHAKE_LISTEN_PORT);
    inet_pton(AF_INET, CHIPA_HANDSHAKE_IP, &(server_addr.sin_addr.s_addr));

    /* set non-blocking mode on socket */
    flags = fcntl(sock_fd, F_GETFL, 0);
    fcntl(sock_fd, F_SETFL, flags | O_NONBLOCK);

    /* connect server */
    if (0 != tcp_client_connect(sock_fd, &server_addr, timeout_s)) {
        PRINTF_CRITICAL("tcp connect timeout\n");
        return -1;
    }

    /* add to global poll fds */
    init_fd_array();
    add_fd_array(sock_fd, (void *)recv_msg, (void *)client_msg_process, NULL,
                 ACTIVE_NOW, inet_ntoa(server_addr.sin_addr), "client_recv_msg");

    set_client_socket(sock_fd);
    return 0;
}

void close_client()
{
    int fd = get_client_socket();
    closeCnnt(fd);
}

static int tcp_send(ota_op_t *op, uint8_t *senddata, ssize_t len)
{
    ssize_t havesend = 0;
    int selres;
    int ret = -1;
    int cnt = 10;
    int timeout_ms = op->timeout_ms;
    int sock_fd = op->fd;

    while (cnt--) {
        fd_set wfds;
        struct timeval tv;
        FD_ZERO(&wfds);
        FD_SET(sock_fd, &wfds);
        tv.tv_sec = (timeout_ms / cnt) / 1000;
        tv.tv_usec = ((timeout_ms / cnt) % 1000) * 1000;

        selres = select(sock_fd + 1, NULL, &wfds, NULL, &tv);

        switch (selres) {
            case -1:
                PRINTF_CRITICAL("select error: %s", strerror(errno));
                //closeCnnt(sock_fd);
                return -1;

            case 0:
                PRINTF_CRITICAL("select time out");
                continue;

            default:
                if (FD_ISSET(sock_fd, &wfds)) {
                    ret = send(sock_fd, senddata + havesend,  len - havesend, 0);

                    if (ret == 0 || (ret < 0 && (errno != EINTR && errno != EAGAIN ))) {
                        PRINTF_CRITICAL("tcp send error: %s", strerror(errno));
                        //closeCnnt(sock_fd);
                        return -1;
                    }

                    havesend += ret;
                    PRINTF_DBG("havesend= %d\n", (int)havesend);

                    if (havesend == len) {
                        PRINTF_DBG("send over %d\n", (int)len);
                        return 0;
                    }
                }

                break;
        }
    }

    if (havesend != len) {
        PRINTF_CRITICAL("send error len = %d havesend= %d\n", (int)len, (int)havesend);
        return -1;
    }
    else {
        return 0;
    }
}

static int tcp_recv(ota_op_t *op, uint8_t *recv_buf)
{
    struct timespec time_to_wait = {0, 0};

    pthread_mutex_lock(&recv_mutex);
    global_recv_msg = recv_buf;
    time_to_wait.tv_sec = time(NULL) + (op->timeout_ms / 1000);

    if (0 != pthread_cond_timedwait(&recv_cond, &recv_mutex,
                                    &time_to_wait)) {
        PRINTF_CRITICAL("wait tcp recv error : %s\n", strerror(errno));
        pthread_mutex_unlock(&recv_mutex);
        return -1;
    }

    pthread_mutex_unlock(&recv_mutex);

    return 0;
}

int client_handshake_to_server()
{
    ota_op_t op;
    int ret = -1;
    uint8_t msg[MAX_SEND_LENGTH] = {0};
    ota_msg_head_struct_t *head;

    op.fd = get_client_socket();
    op.cmd = OTA_CMD_CHECK_AP;
    op.timeout_ms = 5000;
    op.expect_recv_cmd = OTA_CMD_CHECK_AP_OK;

    ret = msg_wrapper(op.cmd, NULL, 0, msg);

    if (ret < 0) {
        PRINTF_CRITICAL("msg wrapper error\n");
        return -1;
    }

    ret = tcp_send(&op, msg, 0 + MSG_HEAD_SIZE);

    if (ret < 0) {
        PRINTF_CRITICAL("tcp send error\n");
        return -1;
    }

    ret = tcp_recv(&op, msg);

    if (ret < 0) {
        PRINTF_CRITICAL("tcp recv error\n");
        return -1;
    }


    ret = msg_unwrapper(msg);

    if (ret < 0) {
        PRINTF_CRITICAL("msg unwrapper error\n");
        return -1;
    }

    head = (ota_msg_head_struct_t *)msg;

    if (head->cmd != (op.expect_recv_cmd)) {
        PRINTF_CRITICAL("cmd = %s  error, expect %s \n", get_ota_cmd_str(head->cmd),
                        get_ota_cmd_str(op.expect_recv_cmd));
        return -1;
    }

    set_handshake_status(true);
    return 0;
}
