package main

import (
	"dnsServer/back"
	"fmt"
	"net/http"
	"os"

	"gopkg.in/yaml.v2"
)

type Config struct {
	DBDSN      string `yaml:"db_dsn"`
	ListenAddr string `yaml:"listen_addr"`
	CertFile   string `yaml:"cert_file"`
	KeyFile    string `yaml:"key_file"`
}

var config Config

// 从配置文件加载配置
func loadConfig() {
	f, err := os.Open("config.yaml")
	if err != nil {
		panic("无法打开配置文件: " + err.Error())
	}
	defer f.Close()
	if err := yaml.NewDecoder(f).Decode(&config); err != nil {
		panic("配置文件解析失败: " + err.Error())
	}
}

// 初始化所有组件
func initAll() {
	loadConfig()
	back.InitDB(config.DBDSN)
	back.InitJWTSecret()
	go back.StartHBChecker()
}

func main() {
	initAll()
	back.RegisterRoutes()
	http.Handle("/", http.FileServer(http.Dir("front")))
	localIP := back.GetLocalIP()
	fmt.Printf("文件服务器启动成功: https://%s%s\n", localIP, config.ListenAddr)
	http.ListenAndServeTLS(config.ListenAddr, config.CertFile, config.KeyFile, nil)
}
