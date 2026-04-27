// 用户配置下发
function pushConfig() {
    const deviceID = document.getElementById("configDeviceID").value;
    const hbTime = parseInt(document.getElementById("configHbTime").value, 10);
    const reConTime = parseInt(document.getElementById("configReConTime").value, 10);
    const rsTime = parseInt(document.getElementById("configRsTime").value, 10);
    const msgSpan = document.getElementById("pushConfigMsg");
    msgSpan.innerText = "";
    if (!deviceID) return msgSpan.innerText = "请选择设备";
    if (!(hbTime > 0 && reConTime > 0 && rsTime > 0))
        return msgSpan.innerText = "配置参数需为正整数";
    postJSON(`/api/user/device/config/push?device_id=${encodeURIComponent(deviceID)}`, {
        hbTime, reConTime, rsTime
    })
        .then((r) => {
            if (!r.ok) throw new Error("配置失败");
            msgSpan.innerText = "配置下发成功";
        })
        .catch((e) => {
            msgSpan.innerText = `配置下发失败: ${e.message}`;
        });
}

function showUserConfigDialog(deviceId) {
    document.getElementById('userConfigDeviceID').value = deviceId;
    document.getElementById('userConfigHbTime').value = 30;
    document.getElementById('userConfigReConTime').value = 60;
    document.getElementById('userConfigRsTime').value = 60;
    document.getElementById('userPushConfigMsg').innerText = '';
    document.getElementById('userConfigDialog').style.display = 'block';
}

function closeUserConfigDialog() {
    document.getElementById('userConfigDialog').style.display = 'none';
}

function userPushConfig() {
    const deviceID = document.getElementById("userConfigDeviceID").value;
    const hbTime = parseInt(document.getElementById("userConfigHbTime").value, 10);
    const reConTime = parseInt(document.getElementById("userConfigReConTime").value, 10);
    const rsTime = parseInt(document.getElementById("userConfigRsTime").value, 10);
    const msgSpan = document.getElementById("userPushConfigMsg");
    msgSpan.innerText = "";
    if (!deviceID) return msgSpan.innerText = "请选择设备";
    if (!(hbTime > 0 && reConTime > 0 && rsTime > 0))
        return msgSpan.innerText = "配置参数需为正整数";
    postJSON(`/api/user/device/config/push?device_id=${encodeURIComponent(deviceID)}`, {
        hbTime, reConTime, rsTime
    })
        .then((r) => {
            if (!r.ok) throw new Error("配置失败");
            msgSpan.innerText = "配置下发成功";
        })
        .catch((e) => {
            msgSpan.innerText = `配置下发失败: ${e.message}`;
        });
}