package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/url"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

type wsClient struct {
	conn           *websocket.Conn
	serverIP       string
	token          string
	hbTime         time.Duration
	reConTime      time.Duration
	rsTime         time.Duration
	stopChan       chan struct{}
	doneChan       chan struct{}
	hbTimeChan     chan time.Duration
	readyChan      chan struct{}
	stopReconnect  chan struct{}
	mu             sync.Mutex
	isRunning      bool
	controlHandler func(action string)
}

// 创建新客户端
func newWSClient(serverHost, token string) *wsClient {
	return &wsClient{
		serverIP:      serverHost,
		token:         token,
		hbTime:        10 * time.Second,
		reConTime:     10 * time.Second,
		stopChan:      make(chan struct{}),
		doneChan:      make(chan struct{}),
		hbTimeChan:    make(chan time.Duration, 1),
		readyChan:     make(chan struct{}),
		stopReconnect: make(chan struct{}),
	}
}

// 注册控制消息回调
func (c *wsClient) OnControl(handler func(action string)) {
	c.controlHandler = handler
}

// 启动客户端（重连、心跳、消息监听）
func (c *wsClient) start() {
	c.mu.Lock()
	if c.isRunning {
		c.mu.Unlock()
		fmt.Println("wsClient 已经启动，忽略重复调用")
		return
	}
	c.isRunning = true
	if c.stopReconnect != nil {
		close(c.stopReconnect)
	}
	c.stopReconnect = make(chan struct{})
	c.mu.Unlock()
	go c.reConnect(c.stopReconnect)
}

// 重连
func (c *wsClient) reConnect(stopReconnect <-chan struct{}) {
	defer func() {
		c.mu.Lock()
		c.isRunning = false
		c.mu.Unlock()
	}()
	for {
		select {
		case <-stopReconnect:
			return
		default:
		}
		if !c.firstConnect(stopReconnect) {
			select {
			case <-stopReconnect:
				return
			case <-time.After(c.reConTime):
			}
			continue
		}
		select {
		case <-c.doneChan:
		case <-stopReconnect:
			return
		}
		c.cleanupConn()
		fmt.Println("准备重连")
		select {
		case <-stopReconnect:
			return
		case <-time.After(c.reConTime):
		}
	}
}

// 建立连接并初始化，成功返回true，失败返回false
func (c *wsClient) firstConnect(stopReconnect <-chan struct{}) bool {
	fmt.Println("尝试连接服务器:", c.serverIP)
	conn, err := c.connect()
	if err != nil {
		fmt.Println("连接失败，", c.reConTime, "秒后重试:", err)
		select {
		case <-stopReconnect:
			return false
		case <-time.After(c.reConTime):
			return false
		}
	}
	c.mu.Lock()
	c.conn = conn
	c.mu.Unlock()
	fmt.Println("连接成功:", c.serverIP)
	go c.read()
	go c.sendHeartbeat()
	c.doneChan = make(chan struct{})
	return true
}

// 断开连接时的清理
func (c *wsClient) cleanupConn() {
	c.mu.Lock()
	if c.conn != nil {
		c.conn.Close()
		c.conn = nil
	}
	c.mu.Unlock()
}

// 发送消息
func (c *wsClient) send(data []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn == nil {
		return fmt.Errorf("连接尚未建立")
	}
	return c.conn.WriteMessage(websocket.TextMessage, data)
}

// 建立连接
func (c *wsClient) connect() (*websocket.Conn, error) {
	u := url.URL{
		Scheme:   "wss",
		Host:     c.serverIP + ":8443",
		Path:     "/probe/ws",
		RawQuery: "token=" + c.token,
	}
	dialer := websocket.Dialer{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	conn, _, err := dialer.Dial(u.String(), nil)
	return conn, err
}

// 接收消息
func (c *wsClient) read() {
	defer close(c.doneChan)
	for {
		_, msg, err := c.conn.ReadMessage()
		if err != nil {
			fmt.Println("接收错误:", err)
			return
		}
		var m map[string]interface{}
		if err := json.Unmarshal(msg, &m); err != nil {
			fmt.Println("非 JSON 消息:", string(msg))
			continue
		}
		switch m["type"] {
		case "config":
			c.solveConfig(m)
		case "control":
			if c.controlHandler != nil {
				if action, ok := m["action"].(string); ok {
					c.controlHandler(action)
				}
			}
		default:
			fmt.Println("未知消息:", m)
		}
	}
}

// 配置处理
func (c *wsClient) solveConfig(m map[string]interface{}) {
	if data, ok := m["data"].(map[string]interface{}); ok {
		if v, ok := data["rsTime"].(float64); ok && v > 0 {
			c.rsTime = time.Duration(v) * time.Second
			fmt.Println("下发配置: 重发间隔 =", c.rsTime)
		}
		if v, ok := data["reConTime"].(float64); ok && v > 0 {
			c.reConTime = time.Duration(v) * time.Second
			fmt.Println("下发配置: 重连间隔 =", c.reConTime)
		}
		if v, ok := data["hbTime"].(float64); ok && v > 0 {
			c.hbTime = time.Duration(v) * time.Second
			c.hbTimeChan <- c.hbTime // 通知心跳调整
			fmt.Println("下发配置: 心跳间隔 =", c.hbTime)
		}
	}
	// 收到配置后，通知 main 可以启动抓包
	select {
	case <-c.readyChan:
	default:
		close(c.readyChan)
	}
}

// 定时心跳
func (c *wsClient) sendHeartbeat() {
	ticker := time.NewTicker(c.hbTime)
	defer ticker.Stop()
	for {
		select {
		case newHb := <-c.hbTimeChan:
			ticker.Stop()
			ticker = time.NewTicker(newHb)
			fmt.Println("心跳更新为:", newHb)
		case <-ticker.C:
			c.mu.Lock()
			if c.conn == nil {
				c.mu.Unlock()
				return
			}
			hbMsg := map[string]interface{}{
				"type": "heartbeat",
				"time": time.Now().Format(time.RFC3339),
			}
			data, err := json.Marshal(hbMsg)
			if err != nil {
				c.mu.Unlock()
				fmt.Println("心跳消息序列化失败:", err)
				continue
			}
			err = c.conn.WriteMessage(websocket.TextMessage, data)
			c.mu.Unlock()
			if err != nil {
				fmt.Println("心跳发送失败:", err)
				return
			}
		case <-c.stopChan:
			return
		}
	}
}

// 获取重发间隔rsTime
func (c *wsClient) getRsTime() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.rsTime
}

// 关闭客户端连接
func (c *wsClient) close() {
	c.mu.Lock()
	if c.conn != nil {
		c.conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
		c.conn.Close()
		c.conn = nil
	}
	c.isRunning = false
	if c.stopReconnect != nil {
		close(c.stopReconnect)
	}
	c.mu.Unlock()
	close(c.stopChan)
}

// 等待连接建立
func (c *wsClient) waitForConnection(connected chan struct{}) {
	for {
		c.mu.Lock()
		conn := c.conn
		c.mu.Unlock()
		if conn != nil {
			close(connected)
			return
		}
	}
}
