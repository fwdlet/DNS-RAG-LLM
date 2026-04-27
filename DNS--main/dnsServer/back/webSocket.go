package back

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/websocket"
)

type clientConn struct {
	conn       *websocket.Conn
	lastActive time.Time
	mu         sync.Mutex
	username   string
	hbTimeout  time.Duration // 每个设备的心跳超时时间
}

var (
	connPool = make(map[string]*clientConn)
	poolMu   sync.RWMutex
	upgrader = websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			// 允许所有跨域请求，实际可限制域名
			return true
		},
	}
)

// 做websocket连接
func HandleWS(w http.ResponseWriter, r *http.Request) {
	token, ok := authenticateRequest(w, r)
	if !ok {
		return
	}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("升级websocket失败:", err)
		return
	}
	defer conn.Close()
	log.Println("客户端连接成功")
	claims, _ := token.Claims.(jwt.MapClaims)
	deviceID, _ := claims["device_id"].(string)
	username, _ := claims["username"].(string)
	role, _ := claims["role"].(string)
	if deviceID == "" || username == "" || role == "" {
		http.Error(w, "token缺少必要字段", http.StatusUnauthorized)
		return
	}
	client := &clientConn{
		conn:       conn,
		lastActive: time.Now(),
		username:   username,
		hbTimeout:  20 * time.Second,
	}
	addClientToPool(deviceID, client)
	defer rmClientFromPool(deviceID)
	msgSolve(client, deviceID)
	log.Println("连接断开")
}

// 检验token是否有效
func authenticateRequest(w http.ResponseWriter, r *http.Request) (*jwt.Token, bool) {
	tokenStr := r.URL.Query().Get("token")
	if tokenStr == "" {
		http.Error(w, "token缺失", http.StatusUnauthorized)
		return nil, false
	}
	token, err := checkToken(tokenStr)
	if err != nil || !token.Valid {
		http.Error(w, "无效token", http.StatusUnauthorized)
		return nil, false
	}
	return token, true
}

// 设备状态判断
func invalidDevice(c *clientConn, deviceID string) bool {
	status, err := checkDeviceStatus(deviceID)
	if err != nil || status != DEVICEAPPROVED {
		log.Println("设备状态异常或未批准:", deviceID, "错误:", err)
		c.conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, "设备已被撤销或拉黑"))
		c.conn.Close()
		return true
	}
	return false
}

// 连接信息放入连接池
func addClientToPool(deviceID string, client *clientConn) {
	poolMu.Lock()
	connPool[deviceID] = client
	poolMu.Unlock()
}

// 连接信息移除连接池
func rmClientFromPool(deviceID string) {
	poolMu.Lock()
	delete(connPool, deviceID)
	poolMu.Unlock()
}

// 消息处理
func msgSolve(c *clientConn, deviceID string) {
	for {
		if invalidDevice(c, deviceID) {
			break
		}
		_, msg, err := c.conn.ReadMessage()
		if err != nil {
			log.Println("读取消息失败:", err)
			break
		}
		var m map[string]interface{}
		if err := json.Unmarshal(msg, &m); err != nil {
			log.Println("消息格式错误:", string(msg))
			continue
		}
		// 安全获取type字段
		rawType, ok := m["type"]
		if !ok {
			log.Println("消息缺少type字段:", string(msg))
			continue
		}
		msgType, ok := rawType.(string)
		if !ok {
			log.Println("type字段不是字符串:", string(msg))
			continue
		}
		msgType = strings.ToLower(msgType)
		switch msgType {
		case "heartbeat":
			c.mu.Lock()
			c.lastActive = time.Now()
			c.mu.Unlock()
		case "packet":
			err := savePacket(m["data"])
			if err != nil {
				log.Println("保存失败:", err)
			}
		default:
			log.Println("未知消息类型:", msgType)
		}
	}
}