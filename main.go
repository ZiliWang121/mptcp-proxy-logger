package main

import (
	"fmt"
	"net"
	"os"        // 用于包装 fd
	"os/exec"   // 新增：用于调用 proxy_logger_fd.py
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
	logLevel     string // Add a command-line option to set log level
	taskCounter  int = 0 // 新增：每次连接递增 task_id（用于 logger 记录）
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

	// Parse and apply log level
	level, err := log.ParseLevel(logLevel)
	if err != nil {
		log.Warnf("Invalid log level '%s', defaulting to info", logLevel)
		level = log.InfoLevel
	}
	log.SetLevel(level)

	// Enable caller reporting in debug mode
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
	// this code is copied from https://gist.github.com/fangdingjun/11e5d63abe9284dc0255a574a76bbcb1
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

	if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
		log.Fatal(err)
	}

	bindAddr := syscall.SockaddrInet4{Port: localPort}
	if transparent {
		bindAddr.Addr = [4]byte{0, 0, 0, 0}
		if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_TRANSPARENT, 1); err != nil {
			log.Error(err)
			return
		}
		if err := syscall.SetsockoptString(fd, syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, "upfgtp"); err != nil {
			log.Errorf("Failed to bind socket to device upfgtp: %v", err)
			return
		}
	} else {
		bindAddr.Addr = [4]byte{0, 0, 0, 0}
	}

	if err := syscall.Bind(fd, &bindAddr); err != nil {
		log.Fatal(err)
	}
	if err := syscall.Listen(fd, 5); err != nil {
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

		// determine remoteSockAddr
		remoteSockAddr := &syscall.SockaddrInet4{}
		if transparent {
			ip, port, err := getOriginalDestination(fd2)
			if err != nil {
				log.Printf("failed to get original destination %s", err)
				syscall.Close(fd2)
				continue
			}
			copy(remoteSockAddr.Addr[:], ip.To4())
			remoteSockAddr.Port = port
		} else {
			copy(remoteSockAddr.Addr[:], remoteAddr.To4())
			remoteSockAddr.Port = remotePort
		}

		// —— 1）冻结当前的 taskID
		taskID := taskCounter

		// —— 2）马上异步调用 persist_state，不阻塞
		go func(fdCopy, tID int) {
			sockFile := os.NewFile(uintptr(fdCopy), fmt.Sprintf("persist-socket-%d", fdCopy))
			cmd := exec.Command("python3", "/home/vagrant/proxy_logger_fd.py",
				"--mode", "persist",
				"--fd", "3",
				"--task", strconv.Itoa(tID),
			)
			cmd.ExtraFiles = []*os.File{sockFile}
			if out, err := cmd.CombinedOutput(); err != nil {
				log.Errorf("persist failed: %v\n%s", err, out)
			} else {
				log.Infof("persist done: %s", out)
			}
			// sockFile.Close()  // Python may still hold it briefly
		}(fd2, taskID)

		// —— 3）启动代理处理，并自增计数
		go handleConnection(taskID, fd2, rAddr.(*syscall.SockaddrInet4), remoteSockAddr, connectProtocol)
		taskCounter++
	}
}

func handleConnection(taskID, fd int, src, dst *syscall.SockaddrInet4, connectProtocol int) error {
	// Always use standard TCP for the outgoing socket
	rFd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, syscall.IPPROTO_TCP)
	if err != nil {
		log.Error(err)
		return err
	}
	// defer syscall.Close(rFd)

	// disable mptcp on outgoing
	const MPTCP_ENABLED = 42
	if err := syscall.SetsockoptInt(rFd, syscall.IPPROTO_TCP, MPTCP_ENABLED, 0); err != nil {
		log.Warnf("Disabling MPTCP may not be supported: %v", err)
	}
	if err := syscall.SetsockoptInt(rFd, syscall.SOL_TCP, syscall.TCP_NODELAY, 1); err != nil {
		log.Error(err)
		return err
	}
	if err := syscall.Connect(rFd, dst); err != nil {
		log.Error(err)
		return err
	}

	srcAddr := net.IPv4(src.Addr[0], src.Addr[1], src.Addr[2], src.Addr[3])
	dstAddr := net.IPv4(dst.Addr[0], dst.Addr[1], dst.Addr[2], dst.Addr[3])
	endpoints := fmt.Sprintf("src=%s:%d dst=%s:%d", srcAddr, src.Port, dstAddr, dst.Port)
	log.Printf("connected to remote(%s)", endpoints)

	// 在转发过程中异步调用 log，确保 socket 仍然打开
	go func(fdCopy, tID int) {
		// 可以调整 Sleep 时间，如果数据太快
		// time.Sleep(200 * time.Millisecond)

		sockFile := os.NewFile(uintptr(fdCopy), fmt.Sprintf("proxy-socket-%d", fdCopy))
		cmd := exec.Command("python3", "/home/vagrant/proxy_logger_fd.py",
			"--mode", "log",
			"--fd", "3",
			"--task", strconv.Itoa(tID),
		)
		cmd.ExtraFiles = []*os.File{sockFile}
		if out, err := cmd.CombinedOutput(); err != nil {
			log.Errorf("logger failed: %v\noutput: %s", err, out)
		} else {
			log.Infof("logger output: %s", out)
		}
		// sockFile.Close()
	}(fd, taskID)

	// 正常转发数据
	if err := copyFdStream(fd, rFd); err != nil {
		log.Error(err)
	}

	log.Printf("proxy finished(%s)", endpoints)
	syscall.Close(fd)
	return nil
}

func isEpollEventFlagged(events []syscall.EpollEvent, fd int, flag int) bool {
	for _, event := range events {
		if int(event.Fd) != fd {
			continue
		}
		return int(event.Events)&flag > 0
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

	events := make([]syscall.EpollEvent, 10)
	eventsWrite := make([]syscall.EpollEvent, 10)

	// 注册可读
	if err := syscall.EpollCtl(epfd, syscall.EPOLL_CTL_ADD, fd1, &syscall.EpollEvent{Events: syscall.EPOLLIN | syscall.EPOLLRDHUP, Fd: int32(fd1)}); err != nil {
		return err
	}
	if err := syscall.EpollCtl(epfd, syscall.EPOLL_CTL_ADD, fd2, &syscall.EpollEvent{Events: syscall.EPOLLIN | syscall.EPOLLRDHUP, Fd: int32(fd2)}); err != nil {
		return err
	}
	// 注册可写
	if err := syscall.EpollCtl(epWritefd, syscall.EPOLL_CTL_ADD, fd1, &syscall.EpollEvent{Events: syscall.EPOLLOUT, Fd: int32(fd1)}); err != nil {
		return err
	}
	if err := syscall.EpollCtl(epWritefd, syscall.EPOLL_CTL_ADD, fd2, &syscall.EpollEvent{Events: syscall.EPOLLOUT, Fd: int32(fd2)}); err != nil {
		return err
	}

	b := make([]byte, BUF_SIZE)
	for {
		n, err := syscall.EpollWait(epfd, events, -1)
		if err != nil && err != syscall.EINTR {
			return err
		}
		waitEvents := events[:n]

		m, err := syscall.EpollWait(epWritefd, eventsWrite, 0)
		if err != nil && err != syscall.EINTR {
			return err
		}
		writeEvents := eventsWrite[:m]

		closed := isEpollEventFlagged(waitEvents, fd1, syscall.EPOLLRDHUP) ||
			isEpollEventFlagged(waitEvents, fd2, syscall.EPOLLRDHUP)

		fds := []int{fd1, fd2}
		for i := 0; i < 2; i++ {
			r := fds[i]
			w := fds[(i+1)%2]
			if !isEpollEventFlagged(waitEvents, r, syscall.EPOLLIN) {
				continue
			}
			if !isEpollEventFlagged(writeEvents, w, syscall.EPOLLOUT) {
				continue
			}
			nr, _, err := syscall.Recvfrom(r, b, syscall.MSG_DONTWAIT)
			if err != nil {
				return err
			}
			if nr == 0 {
				return nil
			}
			if _, err := syscall.Write(w, b[:nr]); err != nil {
				return err
			}
		}
		if closed {
			return nil
		}
	}
}
