package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/google/gopacket"
)

// 启动抓包和重发
func startCaptureAndRetry(iface, ifaceName string, ws *wsClient, stopAll chan struct{}) chan struct{} {
	if stopAll != nil {
		close(stopAll)
	}
	stopAllNew := make(chan struct{})
	packetChan := make(chan gopacket.Packet, 10)
	go captureDNSWithStop(iface, packetChan, stopAllNew)
	go startRetry(ws, stopAllNew)
	go func() {
		for packet := range packetChan {
			dnsPacket := parseDNSPacket(packet)
			if dnsPacket == nil {
				continue
			}
			jsonData := dnsPacket.toJson(ifaceName, VERSION)
			sendPacket(ws, jsonData)
		}
	}()
	return stopAllNew
}

// 停止抓包和重发
func stopCaptureAndRetry(stopAll chan struct{}) {
	if stopAll != nil {
		close(stopAll)
	}
}

// CLI入口
func runCLI(serverIP, username, password string) {
	if serverIP == "" {
		fmt.Println("请使用 --ip 参数指定服务端IP，例如: --ip=192.168.1.100")
		os.Exit(1)
	}
	if username == "" {
		fmt.Println("请使用 --u 参数指定用户名，例如: --u=zhangsan")
		os.Exit(1)
	}
	if password == "" {
		fmt.Println("请使用 --p 参数指定用户密码，例如: --p=123456")
		os.Exit(1)
	}
	// 自动选择活跃网卡
	useIface, err := findActiveInterface()
	iface := useIface.Name
	ifaceName := username + "@" + iface
	if err != nil {
		fmt.Println("未找到可用网卡:", err)
		os.Exit(1)
	}
	fmt.Println("使用网卡:", useIface.Description, "(", iface, ")")
	// 连接服务器获取认证令牌

	token, err := requestToken(serverIP, username, password, ifaceName)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	// 创建 WebSocket 连接
	clientWS := newWSClient(serverIP, token)
	// 信号监听（CTRL+C退出）
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	var stopAll chan struct{}
	go func() {
		<-quit
		fmt.Println("\n收到退出信号，正在关闭...")
		clientWS.close()
		if stopAll != nil {
			close(stopAll)
		}
		os.Exit(0)
	}()
	// 监听连接是否成功
	connected := make(chan struct{})
	go clientWS.waitForConnection(connected)
	// 等待连接成功
	clientWS.start()
	<-connected
	fmt.Println("等待服务端下发配置...")
	<-clientWS.readyChan
	fmt.Println("收到配置，等待服务端控制指令...")
	clientWS.OnControl(func(action string) {
		switch action {
		case "start":
			fmt.Println("收到控制指令: start，启动抓包和数据传输")
			stopAll = startCaptureAndRetry(iface, ifaceName, clientWS, stopAll)
		case "stop":
			fmt.Println("收到控制指令: stop，暂停抓包和数据传输")
			stopCaptureAndRetry(stopAll)
			stopAll = nil
			// 不再调用 clientWS.close()
		default:
			fmt.Println("未知控制指令:", action)
		}
	})
}
