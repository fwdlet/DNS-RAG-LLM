package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// requestToken 向服务器发送连接请求，获取认证令牌
func requestToken(serverURL, username, password, iface string) (string, error) {
	body := map[string]string{"username": username, "password": password, "iface": iface}
	jsonBody, _ := json.Marshal(body)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	for {
		resp, err := client.Post("https://"+serverURL+":8443/probe/login", "application/json", bytes.NewReader(jsonBody))
		if err != nil {
			return "", fmt.Errorf("连接服务器失败: %v", err)
		}
		data, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			if bytes.Contains(data, []byte("设备待管理员批准")) {
				fmt.Println("设备待管理员批准，等待管理员操作...10秒后重试")
				time.Sleep(10 * time.Second)
				continue
			}
			return "", fmt.Errorf("认证失败: %s", string(data))
		}
		var result struct {
			Token string `json:"token"`
		}
		if err := json.Unmarshal(data, &result); err != nil {
			return "", fmt.Errorf("解析响应失败: %v", err)
		}
		fmt.Println("认证成功")
		return result.Token, nil
	}
}
