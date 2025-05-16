// File: mpsched/mpsched.go
// Go-native equivalent of mpsched.c for MPTCP subflow metrics
// Provides: PersistState(fd int), GetSubInfo(fd int) ([][9]uint32, error)

package mpsched

/*
#cgo CFLAGS: -Wall
#include <linux/tcp.h>
#include <linux/mptcp.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <string.h>
#include <stdlib.h>

#define NUM_SUBFLOWS 8

struct MPTCPResult {
    unsigned int subflow[NUM_SUBFLOWS][9]; // Each subflow has 9 fields
    int count;
};

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
        out->subflow[i][8] = 0; // reserved
        out->count++;
    }
    return 0;
}

int persist_state(int fd) {
    int val = MPTCP_INFO_FLAG_SAVE_MASTER;
    return setsockopt(fd, SOL_TCP, MPTCP_INFO, &val, sizeof(val));
}
*/
import "C"
import (
    "fmt"
)

// PersistState mimics mpsched.persist_state(fd) to persist MPTCP master 
info
func PersistState(fd int) error {
    if C.persist_state(C.int(fd)) != 0 {
        return fmt.Errorf("persist_state failed on fd %d", fd)
    }
    return nil
}

// GetSubInfo mimics mpsched.get_sub_info(fd)
// Returns a slice of subflows, each with 9 uint32 metrics:
// [0]=segs_out, [1]=rtt, [2]=snd_cwnd, [3]=unacked, [4]=retrans,
// [5]=dst_ip, [6]=rcv_ooopack, [7]=snd_wnd, [8]=reserved
func GetSubInfo(fd int) ([][9]uint32, error) {
    var res C.struct_MPTCPResult
    if C.get_sub_info(C.int(fd), &res) != 0 {
        return nil, fmt.Errorf("get_sub_info failed on fd %d", fd)
    }
    count := int(res.count)
    out := make([][9]uint32, count)
    for i := 0; i < count; i++ {
        for j := 0; j < 9; j++ {
            out[i][j] = uint32(res.subflow[i][j])
        }
    }
    return out, nil
}

