package main

import (
	"fmt"
	"net"
	"syscall"

	log "github.com/sirupsen/logrus"
	flag "github.com/spf13/pflag"
)

const (
	IPPROTO_MPTCP = 262           // MPTCP 协议号
	BUF_SIZE      = 65536         // 读写缓冲区大小
	SO_ORIGINAL_DST = 80          // 获取原始目的地址的 socket 选项
)

var (
	localPort    int  // 本地监听端口
	disableMPTCP bool // 是否禁用 MPTCP
)

func main() {
	// 如果是调试模式，显示调用栈
	if log.GetLevel() == log.DebugLevel {
		log.SetReportCaller(true)
	}

	flag.IntVarP(&localPort, "port", "p", 0, "local bind port (required)")
	flag.BoolVar(&disableMPTCP, "disable-mptcp", false, "Disable MPTCP")
	flag.Parse()

	if localPort == 0 {
		flag.Usage()
		return
	}

	log.Infof("starting proxy in transparent server mode...")

	// 启动代理：从 MPTCP 接收，向 TCP 转发（server 模式）
	if disableMPTCP {
		doProxy(syscall.IPPROTO_IP, syscall.IPPROTO_IP)
	} else {
		doProxy(IPPROTO_MPTCP, syscall.IPPROTO_IP)
	}
}

// 从 TCP 连接中提取原始目标地址（用于透明代理）
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

// 主逻辑：监听来自 client 的连接，并转发至原始目标地址
func doProxy(bindProtocol, connectProtocol int) {
	// 创建监听 socket（绑定 MPTCP 或 TCP）
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, bindProtocol)
	if err != nil {
		log.Fatal(err)
	}
	defer syscall.Close(fd)

	// 设置 socket 重用
	err = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
	if err != nil {
		log.Fatal(err)
	}

	// 配置监听地址（只绑定到 127.0.0.1，用于 TPROXY）
	bindAddr := syscall.SockaddrInet4{
		Port: localPort,
		Addr: [4]byte{127, 0, 0, 1},
	}

	// 启用 IP_TRANSPARENT（必须设置）
	err = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_TRANSPARENT, 1)
	if err != nil {
		log.Error(err)
		return
	}

	// 绑定 + 监听
	err = syscall.Bind(fd, &bindAddr)
	if err != nil {
		log.Fatal(err)
	}
	err = syscall.Listen(fd, 5)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Started to listening on port %d...", localPort)

	for {
		// 接收连接
		fd2, rAddr, err := syscall.Accept(fd)
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("Accepted connection (fd=%d)", fd2)

		// 获取原始目标地址（来自 iptables REDIRECT）
		ip, port, err := getOriginalDestination(fd2)
		if err != nil {
			log.Printf("failed to get original destination %s", err)
			continue
		}
		remoteSockAddr := &syscall.SockaddrInet4{}
		copy(remoteSockAddr.Addr[:], ip.To4())
		remoteSockAddr.Port = port

		// 启动转发
		go handleConnection(fd2, rAddr.(*syscall.SockaddrInet4), remoteSockAddr, connectProtocol)
	}
}

// 建立与目标服务器的连接，转发数据
func handleConnection(fd int, src, dst *syscall.SockaddrInet4, connectProtocol int) error {
	defer syscall.Close(fd)

	// 创建与目标地址连接的 socket
	rFd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, connectProtocol)
	if err != nil {
		log.Error(err)
		return err
	}
	defer syscall.Close(rFd)

	// 设置 TCP_NODELAY 减少延迟
	err = syscall.SetsockoptInt(rFd, syscall.SOL_TCP, syscall.TCP_NODELAY, 1)
	if err != nil {
		log.Error(err)
		return err
	}

	// 发起连接
	err = syscall.Connect(rFd, dst)
	if err != nil {
		log.Error(err)
		return err
	}

	srcAddr := net.IPv4(src.Addr[0], src.Addr[1], src.Addr[2], src.Addr[3])
	dstAddr := net.IPv4(dst.Addr[0], dst.Addr[1], dst.Addr[2], dst.Addr[3])
	endpoints := fmt.Sprintf("src=%s:%d dst=%s:%d", srcAddr.String(), src.Port, dstAddr.String(), dst.Port)
	log.Printf("connected to remote(%s)", endpoints)

	// 开始转发流量
	err = copyFdStream(fd, rFd)
	if err != nil {
		log.Error(err)
	}
	log.Printf("proxy finished(%s)", endpoints)
	return nil
}
