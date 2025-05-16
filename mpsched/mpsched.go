package mpsched

/*
#cgo CFLAGS: -Wall
#cgo LDFLAGS: -lmpsched
#include "mpsched.h"
*/
import "C"
import (
    "fmt"
)

func PersistState(fd int) error {
    if C.persist_state(C.int(fd)) != 0 {
        return fmt.Errorf("persist_state failed on fd %d", fd)
    }
    return nil
}

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
