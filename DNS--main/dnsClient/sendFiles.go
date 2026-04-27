// path: sender.go
package main

import (
	"encoding/json"
	"fmt"
)

// 主发送函数：失败则缓存
func sendPacket(ws *wsClient, pkt *jsonPacket) {
	wrapped := map[string]interface{}{
		"type": "packet",
		"data": pkt,
	}
	data, err := json.Marshal(wrapped)
	if err != nil {
		fmt.Println("JSON序列化失败:", err)
		return
	}
	err = ws.send(data)
	if err != nil {
		fmt.Println("发送失败，加入内存缓存队列:", err)
		cacheQueue <- data
	}
}
