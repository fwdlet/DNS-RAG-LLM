package main

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
)

// GUI入口
func runGUI() {
	a := app.New()
	w := a.NewWindow("DNS CLient " + VERSION)
	ipEntry := widget.NewEntry()
	ipEntry.SetPlaceHolder("服务端IP地址")
	userEntry := widget.NewEntry()
	userEntry.SetPlaceHolder("用户名")
	pwEntry := widget.NewPasswordEntry()
	pwEntry.SetPlaceHolder("用户密码")
	ifaceNames := []string{"自动选择"}
	ifaceMap := map[string]string{"自动选择": ""}
	// 获取物理网卡列表
	ifaces, err := getPhysicalInterfaces()
	if err == nil {
		for _, iface := range ifaces {
			desc := iface.Description
			if desc == "" {
				desc = iface.Name
			}
			label := desc + " (" + iface.Name + ")"
			ifaceNames = append(ifaceNames, label)
			ifaceMap[label] = iface.Name
		}
	}
	ifaceSelect := widget.NewSelect(ifaceNames, nil)
	ifaceSelect.SetSelected("自动选择")
	form := widget.NewForm(
		widget.NewFormItem("服务端IP", ipEntry),
		widget.NewFormItem("用户名", userEntry),
		widget.NewFormItem("用户密码", pwEntry),
		widget.NewFormItem("网卡选择", ifaceSelect),
	)
	var statusBox *widget.Entry = widget.NewMultiLineEntry()
	statusBox.SetPlaceHolder("")
	statusBox.Wrapping = fyne.TextWrapWord
	statusBox.SetMinRowsVisible(12)
	statusBox.Disable()
	var clientWS *wsClient
	var stopAll chan struct{}
	// 控制输入区和选择区的启用/禁用
	enableInputs := func(enable bool) {
		ipEntry.Disable()
		userEntry.Disable()
		pwEntry.Disable()
		ifaceSelect.Disable()
		if enable {
			ipEntry.Enable()
			userEntry.Enable()
			pwEntry.Enable()
			ifaceSelect.Enable()
		}
	}
	var stopBtn *widget.Button
	var startBtn *widget.Button
	stopBtn = widget.NewButton("停止", func() {
		if clientWS != nil {
			clientWS.close()
			clientWS = nil
		}
		stopCaptureAndRetry(stopAll)
		stopAll = nil
		statusBox.SetText("已断开连接")
		stopBtn.Disable()
		startBtn.Enable()
		enableInputs(true)
	})
	stopBtn.Disable()
	startBtn = widget.NewButton("启动", func() {
		ip := ipEntry.Text
		user := userEntry.Text
		pw := pwEntry.Text
		ifaceSel := ifaceSelect.Selected
		if ip == "" || user == "" || pw == "" {
			statusBox.SetText("请填写所有信息")
			return
		}
		statusBox.SetText("正在初始化...")
		startBtn.Disable()
		enableInputs(false)
		go func() {
			stopAll = nil
			var iface string
			if ifaceSel == "自动选择" || ifaceSel == "" {
				useIface, err := findActiveInterface()
				if err != nil {
					statusBox.SetText("未找到可用网卡: " + err.Error())
					startBtn.Enable()
					enableInputs(true)
					return
				}
				iface = useIface.Name
			} else {
				iface = ifaceMap[ifaceSel]
			}
			ifaceName := user + "@" + iface
			token, err := requestToken(ip, user, pw, ifaceName)
			if err != nil {
				statusBox.SetText("认证失败: " + err.Error())
				startBtn.Enable()
				enableInputs(true)
				return
			}
			clientWS = newWSClient(ip, token)
			connected := make(chan struct{})
			go clientWS.waitForConnection(connected)
			clientWS.start()
			select {
			case <-connected:
			case <-stopAll:
				return
			}
			statusBox.SetText("等待下发配置...")
			select {
			case <-clientWS.readyChan:
			case <-stopAll:
				return
			}
			statusBox.SetText("收到配置，等待控制指令...")
			stopBtn.Enable()
			// 监听 control 消消息
			clientWS.OnControl(func(action string) {
				switch action {
				case "start":
					statusBox.SetText("收到控制指令: start，启动抓包和数据传输")
					stopAll = startCaptureAndRetry(iface, user+"@"+iface, clientWS, stopAll)
				case "stop":
					statusBox.SetText("收到控制指令: stop，暂停抓包和数据传输")
					stopCaptureAndRetry(stopAll)
					stopAll = nil
					// 不再调用 clientWS.close()
				default:
					statusBox.SetText("未知控制指令: " + action)
				}
			})
		}()
	})
	leftBox := container.NewVBox(
		widget.NewLabel("请输入连接信息："),
		form,
		startBtn,
		stopBtn,
	)
	rightBox := container.NewVBox(
		widget.NewLabel("状态："),
		statusBox,
	)
	split := container.NewHSplit(leftBox, rightBox)
	split.Offset = 0.4
	w.SetContent(split)
	w.Resize(fyne.NewSize(700, 250))
	w.ShowAndRun()
}
