
package main

/*
#include <stdlib.h>
#include <sys/socket.h>
#include <linux/tcp.h>

#define MPTCP_INFO_FLAG_SAVE_MASTER 1
static int persist_mptcp_state(int fd) {
    int val = MPTCP_INFO_FLAG_SAVE_MASTER;
    return setsockopt(fd, IPPROTO_TCP, MPTCP_INFO, &val, sizeof(val));
}
*/
import "C"

import (
    "fmt"
    "net"
    "strconv"
    "strings"
    "syscall"

    log "github.com/sirupsen/logrus"
    flag "github.com/spf13/pflag"
)

const IPPROTO_MPTCP = 262
const BUF_SIZE = 65536

var (
    remoteAddr   net.IP
    remotePort   int
    localPort    int
    mode         string
    transparent  bool
    disableMPTCP bool
    logLevel     string
    taskCounter  int = 0
)

func main() {
    var err error

    flag.BoolVarP(&transparent, "transparent", "t", false, "Enable transparent mode")
    flag.StringVarP(&mode, "mode", "m", "", "specify mode (server or client)")
    flag.IntVarP(&localPort, "port", "p", 0, "local bind port")
    flag.BoolVar(&disableMPTCP, "disable-mptcp", false, "Disable MPTCP")
    flag.StringVar(&logLevel, "log-level", "info", "Set log level: debug, info, warn, error")
    var rAddr *string = flag.StringP("remote", "r", "", "remote address (ex. 127.0.0.1:8080)")
    flag.Parse()

    level, err := log.ParseLevel(logLevel)
    if err != nil {
        log.Warnf("Invalid log level '%s', defaulting to info", logLevel)
        level = log.InfoLevel
    }
    log.SetLevel(level)
    if level == log.DebugLevel {
        log.SetReportCaller(true)
    }

    if localPort == 0 || mode == "" {
        flag.Usage()
        return
    }

    if mode != "server" && mode != "client" {
        flag.Usage()
        return
    }

    if !transparent {
        if *rAddr == "" {
            flag.Usage()
            return
        }
        addrs := strings.Split(*rAddr, ":")
        if len(addrs) != 2 {
            flag.Usage()
            return
        }

        remoteAddr = net.ParseIP(addrs[0])
        if remoteAddr == nil {
            resolvedAddr, err := net.ResolveIPAddr("ip4", addrs[0])
            if err != nil {
                log.Error(err)
                flag.Usage()
                return
            }
            remoteAddr = resolvedAddr.IP.To4()
        }

        remotePort, err = strconv.Atoi(addrs[1])
        if err != nil {
            flag.Usage()
            return
        }
    }

    log.Infof("starting proxy...")
    if disableMPTCP {
        doProxy(syscall.IPPROTO_IP, syscall.IPPROTO_IP)
    } else {
        if mode == "client" {
            doProxy(syscall.IPPROTO_IP, IPPROTO_MPTCP)
        } else if mode == "server" {
            doProxy(IPPROTO_MPTCP, syscall.IPPROTO_IP)
        }
    }

    log.Errorf("mode %s is not supported", mode)
}

const SO_ORIGINAL_DST = 80

func getOriginalDestination(sockfd int) (net.IP, int, error) {
    addr, err := syscall.GetsockoptIPv6Mreq(sockfd, syscall.IPPROTO_IP, SO_ORIGINAL_DST)
    log.Debugf("getOriginalDst(): SO_ORIGINAL_DST=%+v
", addr)
    if err != nil {
        return nil, 0, err
    }

    ip := net.IPv4(addr.Multiaddr[4], addr.Multiaddr[5], addr.Multiaddr[6], addr.Multiaddr[7])
    port := int(addr.Multiaddr[2])<<8 | int(addr.Multiaddr[3])

    return ip, port, nil
}

func doProxy(bindProtocol, connectProtocol int) {
    fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, bindProtocol)
    if err != nil {
        log.Fatal(err)
    }
    defer syscall.Close(fd)

    err = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
    if err != nil {
        log.Fatal(err)
    }

    bindAddr := syscall.SockaddrInet4{Port: localPort}
    if transparent {
        bindAddr.Addr = [4]byte{0, 0, 0, 0}
        err = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_TRANSPARENT, 1)
        if err != nil {
            log.Error(err)
            return
        }
        err = syscall.SetsockoptString(fd, syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, "upfgtp")
        if err != nil {
            log.Errorf("Failed to bind socket to device upfgtp: %v", err)
            return
        }
    } else {
        bindAddr.Addr = [4]byte{0, 0, 0, 0}
    }

    err = syscall.Bind(fd, &bindAddr)
    if err != nil {
        log.Fatal(err)
    }

    err = syscall.Listen(fd, 5)
    if err != nil {
        log.Fatal(err)
    }
    log.Printf("Started to listening...")

    for {
        log.Infof("Waiting to accept connections on port %d...", localPort)
        fd2, rAddr, err := syscall.Accept(fd)
        log.Infof("Accept returned: fd=%d, err=%v", fd2, err)
        if err != nil {
            log.Fatal(err)
        }
        log.Printf("Accepted connection (fd=%d)", fd2)

        remoteSockAddr := &syscall.SockaddrInet4{}
        if transparent {
            ip, port, err := getOriginalDestination(fd2)
            if err != nil {
                log.Printf("failed to get original destination %s", err)
                continue
            }
            copy(remoteSockAddr.Addr[:], ip.To4())
            remoteSockAddr.Port = port
        } else {
            copy(remoteSockAddr.Addr[:], remoteAddr.To4())
            remoteSockAddr.Port = remotePort
        }

        go func(taskID, fdCopy int) {
            go handleConnection(fdCopy, rAddr.(*syscall.SockaddrInet4), remoteSockAddr, connectProtocol)

            // ==== BEGIN: Injected Metrics Logic ====
            ret := C.persist_mptcp_state(C.int(fdCopy))
            if ret != 0 {
                log.Errorf("Failed to persist MPTCP state for fd=%d", fdCopy)
            } else {
                log.Infof("Successfully persisted MPTCP state for fd=%d", fdCopy)
            }
            // ==== END: Injected Metrics Logic ====
        }(taskCounter, fd2)

        taskCounter++
    }
}

func handleConnection(fd int, src, dst *syscall.SockaddrInet4, connectProtocol int) error {
    defer syscall.Close(fd)

    rFd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, syscall.IPPROTO_TCP)
    if err != nil {
        log.Error(err)
        return err
    }
    defer syscall.Close(rFd)

    const MPTCP_ENABLED = 42
    err = syscall.SetsockoptInt(rFd, syscall.IPPROTO_TCP, MPTCP_ENABLED, 0)
    if err != nil {
        log.Warnf("Disabling MPTCP may not be supported: %v", err)
    }

    err = syscall.SetsockoptInt(rFd, syscall.SOL_TCP, syscall.TCP_NODELAY, 1)
    if err != nil {
        log.Error(err)
        return err
    }

    err = syscall.Connect(rFd, dst)
    if err != nil {
        log.Error(err)
        return err
    }

    srcAddr := net.IPv4(src.Addr[0], src.Addr[1], src.Addr[2], src.Addr[3])
    dstAddr := net.IPv4(dst.Addr[0], dst.Addr[1], dst.Addr[2], dst.Addr[3])
    endpoints := fmt.Sprintf("src=%s:%d dst=%s:%d", srcAddr.String(), src.Port, dstAddr.String(), dst.Port)
    log.Printf("connected to remote(%s)", endpoints)

    err = copyFdStream(fd, rFd)
    if err != nil {
        log.Error(err)
    }

    log.Printf("proxy finished(%s)", endpoints)
    return nil
}

func isEpollEventFlagged(events []syscall.EpollEvent, fd int, flag int) bool {
    for _, event := range events {
        if int(event.Fd) != fd {
            continue
        }
        if int(event.Events)&flag > 0 {
            return true
        }
    }
    return false
}

func copyFdStream(fd1 int, fd2 int) error {
    epfd, err := syscall.EpollCreate1(0)
    if err != nil {
        return err
    }
    defer syscall.Close(epfd)

    epWritefd, err := syscall.EpollCreate1(0)
    if err != nil {
        return err
    }
    defer syscall.Close(epWritefd)

    var eventFd1 syscall.EpollEvent
    var eventFd2 syscall.EpollEvent
    var eventWriteFd1 syscall.EpollEvent
    var eventWriteFd2 syscall.EpollEvent

    events := make([]syscall.EpollEvent, 10)
    eventsWrite := make([]syscall.EpollEvent, 10)

    eventFd1.Events = syscall.EPOLLIN | syscall.EPOLLRDHUP
    eventFd1.Fd = int32(fd1)
    syscall.EpollCtl(epfd, syscall.EPOLL_CTL_ADD, fd1, &eventFd1)

    eventFd2.Events = syscall.EPOLLIN | syscall.EPOLLRDHUP
    eventFd2.Fd = int32(fd2)
    syscall.EpollCtl(epfd, syscall.EPOLL_CTL_ADD, fd2, &eventFd2)

    eventWriteFd1.Events = syscall.EPOLLOUT
    eventWriteFd1.Fd = int32(fd1)
    syscall.EpollCtl(epWritefd, syscall.EPOLL_CTL_ADD, fd1, &eventWriteFd1)

    eventWriteFd2.Events = syscall.EPOLLOUT
    eventWriteFd2.Fd = int32(fd2)
    syscall.EpollCtl(epWritefd, syscall.EPOLL_CTL_ADD, fd2, &eventWriteFd2)

    b := make([]byte, BUF_SIZE)
    for {
        nevents, err := syscall.EpollWait(epfd, events, -1)
        if err != nil {
            if err == syscall.EINTR {
                continue
            }
            return err
        }
        waitEvents := events[:nevents]

        nevents, err = syscall.EpollWait(epWritefd, eventsWrite, 0)
        if err != nil {
            if err == syscall.EINTR {
                continue
            }
            return err
        }
        eventsWritable := eventsWrite[:nevents]

        close := isEpollEventFlagged(waitEvents, fd1, syscall.EPOLLRDHUP) || isEpollEventFlagged(waitEvents, fd2, syscall.EPOLLRDHUP)

        fds := []int{fd1, fd2}
        for fdIdx := range fds {
            readFd := fds[fdIdx]
            writeFd := fds[(fdIdx+1)%len(fds)]

            if !isEpollEventFlagged(waitEvents, readFd, syscall.EPOLLIN) {
                continue
            }
            close = false

            if !isEpollEventFlagged(eventsWritable, writeFd, syscall.EPOLLOUT) {
                continue
            }

            readSize, _, err := syscall.Recvfrom(readFd, b, syscall.MSG_DONTWAIT)
            if err != nil {
                return err
            }
            if readSize == 0 {
                return nil
            }

            _, err = syscall.Write(writeFd, b[:readSize])
            if err != nil {
                return err
            }
        }

        if close {
            return nil
        }
    }
}
