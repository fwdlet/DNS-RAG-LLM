package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

var virtualKeywords = []string{
	"vmware", "bluetooth", "bus", "docker", "interface", "virtual", "veth", "vboxnet", "hyper-v", "Io",
}

// 判断是否为虚拟或非物理网卡
func isVirtualDevice(desc string) bool {
	desc = strings.ToLower(desc)
	for _, kw := range virtualKeywords {
		if strings.Contains(desc, kw) {
			return true
		}
	}
	return false
}

// 扫描网卡并返回第一个有流量的非虚拟设备名称
func findActiveInterface() (pcap.Interface, error) {
	devices, err := getPhysicalInterfaces()
	if err != nil {
		return pcap.Interface{}, fmt.Errorf("%v", err)
	}
	fmt.Println("正在扫描网卡...")
	for _, dev := range devices {
		handle, err := pcap.OpenLive(dev.Name, 65536, false, 500*time.Millisecond)
		if err != nil {
			continue
		}
		defer handle.Close()
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		packetChan := packetSource.Packets()
		timeout := time.After(3 * time.Second)
		select {
		case <-timeout:
		case _, ok := <-packetChan:
			if ok {
				return dev, nil
			}
		}
	}
	return pcap.Interface{}, fmt.Errorf("未检测到任何有流量的物理网卡")
}

// 获取所有物理网卡列表（不含虚拟网卡）
func getPhysicalInterfaces() ([]pcap.Interface, error) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return nil, fmt.Errorf("无法获取设备列表: %v", err)
	}
	var phys []pcap.Interface
	for _, dev := range devices {
		if isVirtualDevice(dev.Description) {
			continue
		}
		phys = append(phys, dev)
	}
	if len(phys) == 0 {
		return nil, fmt.Errorf("未检测到任何物理网卡")
	}
	return phys, nil
}
