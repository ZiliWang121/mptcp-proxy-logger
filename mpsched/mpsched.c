#define _GNU_SOURCE
#include <linux/tcp.h>
#include <linux/mptcp.h>
#include <linux/in.h>
#include <sys/socket.h>
#include <string.h>
#include <stdlib.h>
#include "mpsched.h"

#ifndef SOL_TCP
#define SOL_TCP 6
#endif

int get_sub_info(int fd, struct MPTCPResult* out) {
    struct mptcp_info minfo;
    struct tcp_info others[NUM_SUBFLOWS];
    struct tcp_info initial;
    struct mptcp_meta_info meta_info;
    struct mptcp_sub_info others_info[NUM_SUBFLOWS];

    memset(&minfo, 0, sizeof(minfo));
    minfo.tcp_info_len = sizeof(struct tcp_info);
    minfo.sub_len = sizeof(others);
    minfo.meta_len = sizeof(struct mptcp_meta_info);
    minfo.meta_info = &meta_info;
    minfo.initial = &initial;
    minfo.subflows = &others;
    minfo.sub_info_len = sizeof(struct mptcp_sub_info);
    minfo.total_sub_info_len = sizeof(others_info);
    minfo.subflow_info = &others_info;

    socklen_t len = sizeof(minfo);
    if (getsockopt(fd, SOL_TCP, MPTCP_INFO, &minfo, &len) < 0) {
        return -1;
    }

    out->count = 0;
    for (int i = 0; i < NUM_SUBFLOWS; i++) {
        if (others[i].tcpi_state != 1) break;
        out->subflow[i][0] = others[i].tcpi_segs_out;
        out->subflow[i][1] = others[i].tcpi_rtt;
        out->subflow[i][2] = others[i].tcpi_snd_cwnd;
        out->subflow[i][3] = others[i].tcpi_unacked;
        out->subflow[i][4] = others[i].tcpi_total_retrans;
        out->subflow[i][5] = others_info[i].dst_v4.sin_addr.s_addr;
        out->subflow[i][6] = others[i].tcpi_rcv_ooopack;
        out->subflow[i][7] = others[i].tcpi_snd_wnd;
        out->subflow[i][8] = 0;
        out->count++;
    }
    return 0;
}

int persist_state(int fd) {
    int val = MPTCP_INFO_FLAG_SAVE_MASTER;
    return setsockopt(fd, SOL_TCP, MPTCP_INFO, &val, sizeof(val));
}
