package main

import (
	"flag"
	"io"
	"log"
)

const VERSION = "3.0"

func main() {
	log.SetOutput(io.Discard)
	inputIP := flag.String("ip", "", "服务端IP地址")
	inputUser := flag.String("u", "", "用户名")
	inputPW := flag.String("p", "", "用户密码")
	flag.Parse()
	if *inputIP == "" && *inputUser == "" && *inputPW == "" {
		runGUI()
	} else {
		runCLI(*inputIP, *inputUser, *inputPW)
	}
}
