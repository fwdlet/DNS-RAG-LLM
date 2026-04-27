package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

var cacheQueue = make(chan []byte, 1000)

func startRetry(ws *wsClient, stopAll <-chan struct{}) {
	go startReSend(ws, stopAll)
	go startFlushToDisk() // 不再传 stopAll
}

func startReSend(ws *wsClient, stopAll <-chan struct{}) {
	for {
		select {
		case <-stopAll:
			return
		default:
			resendCacheFiles(ws)
			rsTime := ws.getRsTime()
			select {
			case <-stopAll:
				return
			case <-time.After(rsTime):
			}
		}
	}
}

// 处理所有缓存文件的重发
func resendCacheFiles(ws *wsClient) {
	files, err := filepath.Glob(filepath.Join("cache", "*.json"))
	if err != nil {
		fmt.Println("查找缓存文件失败:", err)
		return
	}
	for _, file := range files {
		if resendCacheFile(ws, file) {
			fmt.Println("重发成功，已删除缓存文件:", file)
		} else {
			fmt.Println("部分消息发送失败，文件保留，稍后重试:", file)
		}
	}
}

// 重发单个缓存文件
func resendCacheFile(ws *wsClient, file string) bool {
	data, err := os.ReadFile(file)
	if err != nil {
		fmt.Println("读取缓存文件失败:", file, err)
		return false
	}
	var packets []map[string]interface{}
	if err := json.Unmarshal(data, &packets); err != nil {
		fmt.Println("解析缓存文件失败:", file, err)
		return false
	}
	successAll := true
	for _, pkt := range packets {
		dataToSend, err := json.Marshal(pkt)
		if err != nil {
			fmt.Println("序列化单个消息失败:", err)
			successAll = false
			continue
		}
		err = ws.send(dataToSend)
		if err != nil {
			fmt.Println("发送失败:", err)
			successAll = false
			break
		}
	}
	if successAll {
		err = os.Remove(file)
		if err != nil {
			fmt.Println("删除缓存文件失败:", file, err)
			return false
		}
		return true
	}
	return false
}

// 每15秒将发送失败的数据写入磁盘
func startFlushToDisk() {
	var buffer []json.RawMessage
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case msg := <-cacheQueue:
			buffer = append(buffer, json.RawMessage(msg))
		case <-ticker.C:
			if len(buffer) == 0 {
				continue
			}
			cacheDir := "cache"
			os.Mkdir(cacheDir, 0755)
			cacheFile := filepath.Join(cacheDir, fmt.Sprintf("%d.json", time.Now().UnixNano()))
			data, err := json.Marshal(buffer)
			if err != nil {
				fmt.Println("JSON编码失败:", err)
				continue
			}
			err = os.WriteFile(cacheFile, data, 0644)
			if err == nil {
				fmt.Println("已写入缓存文件:", cacheFile, "条数:", len(buffer))
			} else {
				fmt.Println("写入文件失败:", err)
			}
			buffer = buffer[:0]
		}
	}
}
