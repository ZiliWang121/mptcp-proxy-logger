package main

import (
//	"fmt"
	"net"
	"syscall"

	log "github.com/sirupsen/logrus"
	flag "github.com/spf13/pflag"
)

const IPPROTO_MPTCP = 262
const BUF_SIZE = 65536
const SO_ORIGINAL_DST = 80

var (
	localPort int
	logLevel  string
)

func main() {
	flag.IntVarP(&localPort, "port", "p", 0, "local bind port")
	flag.StringVar(&logLevel, "log-level", "info", "Set log level: debug, info, warn, error")
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

	if localPort == 0 {
		flag.Usage()
		return
	}

	log.Infof("starting proxy on port %d...", localPort)
	doProxy(IPPROTO_MPTCP, syscall.IPPROTO_IP)
}

func getOriginalDestination(sockfd int) (net.IP, int, error) {
	addr, err := syscall.GetsockoptIPv6Mreq(sockfd, syscall.IPPROTO_IP, SO_ORIGINAL_DST)
	log.Debugf("getOriginalDst(): SO_ORIGINAL_DST=%+v\n", addr)
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

	err = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_TRANSPARENT, 1)
	if err != nil {
		log.Fatalf("Failed to set IP_TRANSPARENT: %v", err)
	}

	err = syscall.SetsockoptString(fd, syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, "upfgtp")
	if err != nil {
		log.Fatalf("Failed to bind to device 'upfgtp': %v", err)
	}

	bindAddr := syscall.SockaddrInet4{
		Port: localPort,
		Addr: [4]byte{0, 0, 0, 0},
	}
	if err := syscall.Bind(fd, &bindAddr); err != nil {
		log.Fatal(err)
	}

	if err := syscall.Listen(fd, 5); err != nil {
		log.Fatal(err)
	}
	log.Infof("Listening on port %d", localPort)

	for {
		fd2, rAddr, err := syscall.Accept(fd)
		log.Infof("Accept returned: fd=%d, err=%v", fd2, err)
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("Accepted connection (fd=%d)", fd2)

		ip, port, err := getOriginalDestination(fd2)
		if err != nil {
			log.Printf("failed to get original destination: %s", err)
			continue
		}
		remoteSockAddr := &syscall.SockaddrInet4{
			Port: port,
		}
		copy(remoteSockAddr.Addr[:], ip.To4())

		go handleConnection(fd2, rAddr.(*syscall.SockaddrInet4), remoteSockAddr, connectProtocol)
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

	if err := syscall.Connect(rFd, dst); err != nil {
		log.Error(err)
		return err
	}

	srcAddr := net.IPv4(src.Addr[0], src.Addr[1], src.Addr[2], src.Addr[3])
	dstAddr := net.IPv4(dst.Addr[0], dst.Addr[1], dst.Addr[2], dst.Addr[3])
	log.Infof("Connected: %s:%d → %s:%d", srcAddr, src.Port, dstAddr, dst.Port)

	err = copyFdStream(fd, rFd)
	if err != nil {
		log.Error(err)
	}

	log.Infof("Proxy finished (%s:%d)", srcAddr, src.Port)
	return nil
}

func isEpollEventFlagged(events []syscall.EpollEvent, fd int, flag int) bool {
	for _, event := range events {
		if int(event.Fd) == fd && int(event.Events)&flag > 0 {
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

	register := func(epfd int, fd int, flags uint32) {
		event := syscall.EpollEvent{Fd: int32(fd), Events: flags}
		syscall.EpollCtl(epfd, syscall.EPOLL_CTL_ADD, fd, &event)
	}

	register(epfd, fd1, syscall.EPOLLIN|syscall.EPOLLRDHUP)
	register(epfd, fd2, syscall.EPOLLIN|syscall.EPOLLRDHUP)
	register(epWritefd, fd1, syscall.EPOLLOUT)
	register(epWritefd, fd2, syscall.EPOLLOUT)

	buf := make([]byte, BUF_SIZE)

	for {
		events := make([]syscall.EpollEvent, 10)
		nr, err := syscall.EpollWait(epfd, events, -1)
		if err != nil && err != syscall.EINTR {
			return err
		}

		eventsWrite := make([]syscall.EpollEvent, 10)
		nw, err := syscall.EpollWait(epWritefd, eventsWrite, 0)
		if err != nil && err != syscall.EINTR {
			return err
		}

		close := isEpollEventFlagged(events[:nr], fd1, syscall.EPOLLRDHUP) ||
			isEpollEventFlagged(events[:nr], fd2, syscall.EPOLLRDHUP)

		for _, pair := range [][2]int{{fd1, fd2}, {fd2, fd1}} {
			readFd, writeFd := pair[0], pair[1]
			if !isEpollEventFlagged(events[:nr], readFd, syscall.EPOLLIN) ||
				!isEpollEventFlagged(eventsWrite[:nw], writeFd, syscall.EPOLLOUT) {
				continue
			}

			n, _, err := syscall.Recvfrom(readFd, buf, syscall.MSG_DONTWAIT)
			if err != nil || n == 0 {
				return err
			}
			if _, err := syscall.Write(writeFd, buf[:n]); err != nil {
				return err
			}
		}

		if close {
			return nil
		}
	}
}
