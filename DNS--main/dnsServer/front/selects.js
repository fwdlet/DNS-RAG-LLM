// 加载设备下拉框
function loadDeviceSelects() {
    const updateSelect = (id, optionsHTML) => {
        const el = document.getElementById(id);
        if (el) el.innerHTML = optionsHTML;
    };
    // 管理员界面：文件查询、日志查询、删除文件，展示所有有上传过包的设备
    if (document.getElementById("adminNav").style.display !== "none") {
        authFetch("/api/admin/device/query")
            .then((r) => r.json())
            .then((list) => {
                const optAll = ['<option value="">全部设备</option>', ...list.map(d => `<option value="${d}">${d}</option>`)].join("");
                const optSel = ['<option value="">请选择设备</option>', ...list.map(d => `<option value="${d}">${d}</option>`)].join("");
                updateSelect("queryDeviceID", optAll);         // 文件查询
                updateSelect("logDeviceID", optAll);           // 日志查询
                updateSelect("deleteFileDeviceID", optSel);    // 删除文件
            });
        // 管理员用户登录日志查询：下拉选择所有用户
        authFetch("/api/admin/user/approved/query")
            .then(r => r.json())
            .then(list => {
                const userOptions = ['<option value="">请选择用户</option>', ...list.map(u => `<option value="${u.username}">${u.username}</option>`)].join("");
                const userSel = document.getElementById("loginLogUsername");
                if (userSel) userSel.innerHTML = userOptions;
            });
    }
    // 用户界面：配置下发下拉框只展示该用户在线的设备
    if (document.getElementById("userNav").style.display !== "none") {
        // 普通用户只查自己的在线设备
        authFetch("/api/user/device/online/query")
            .then(r => r.json())
            .then(list => {
                const configOptions = ['<option value="">请选择设备</option>', ...list.map(d => `<option value="${d.device_id}">${d.device_id}</option>`)].join("");
                updateSelect("configDeviceID", configOptions);
            });
    }
}
