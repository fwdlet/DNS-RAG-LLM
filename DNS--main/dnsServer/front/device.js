// 更新设备列表
function updateDeviceList(elementId, devices, emptyMsg, renderFn) {
    const container = document.getElementById(elementId);
    if (!devices.length) {
        container.innerHTML = emptyMsg;
        return;
    }
    container.innerHTML = devices.map(renderFn).join("");
}

function paginateData(data, page, pageSize = 5) {
    const start = (page - 1) * pageSize;
    return data.slice(start, start + pageSize);
}

function renderPaginationControls(containerId, total, page, callback) {
    const totalPages = Math.ceil(total / 5);
    const container = document.getElementById(containerId + "_pagination");
    if (!container) return;

    container.innerHTML = `
        <div class="pagination-controls">
            <button ${page === 1 ? "disabled" : ""} onclick="${callback}(${page - 1})">上一页</button>
            <span>第 ${page} / ${totalPages} 页</span>
            <button ${page >= totalPages ? "disabled" : ""} onclick="${callback}(${page + 1})">下一页</button>
        </div>
    `;
}

function updateDeviceList(containerId, list, emptyMsg, renderRowFn, page = 1) {
    const container = document.getElementById(containerId);
    if (!container) return;

    const pageList = paginateData(list, page);
    if (pageList.length === 0) {
        container.innerHTML = `<p>${emptyMsg}</p>`;
        return;
    }

    const tableHtml = `
        <table class="device-table">
            <thead>
                <tr>${renderRowFn('header')}</tr>
            </thead>
            <tbody>
                ${pageList.map((d) => `<tr>${renderRowFn('row', d)}</tr>`).join('')}
            </tbody>
        </table>
        <div id="${containerId}_pagination"></div>
    `;

    container.innerHTML = tableHtml;
    renderPaginationControls(containerId, list.length, page, `window.${containerId}_pageCallback`);
}

let pendingDevices = [];
window.pendingDeviceList_pageCallback = function(page) {
    updateDeviceList("pendingDeviceList", pendingDevices, "无待批准设备", renderPendingDeviceRow, page);
};

let approvedDevices = [];
window.registeredDeviceList_pageCallback = function(page) {
    updateDeviceList("registeredDeviceList", approvedDevices, "无已登记设备", renderApprovedDeviceRow, page);
};

let onlineDevices = [];
window.onlineDeviceList_pageCallback = function(page) {
    updateDeviceList("onlineDeviceList", onlineDevices, "无在线设备", renderOnlineDeviceRow, page);
};

function fetchPendingDevice() {
    authFetch("/api/admin/device/pending/query")
        .then((r) => r.json())
        .then((list) => {
            pendingDevices = list;
            window.pendingDeviceList_pageCallback(1);
        });
}

function fetchApprovedDevice() {
    authFetch("/api/admin/device/approved/query")
        .then((r) => r.json())
        .then((list) => {
            approvedDevices = list;
            window.registeredDeviceList_pageCallback(1);
        });
}

function fetchOnlineDevice() {
    authFetch("/api/admin/device/online/query")
        .then((r) => r.json())
        .then((list) => {
            onlineDevices = list;
            window.onlineDeviceList_pageCallback(1);
        });
}

function renderPendingDeviceRow(type, d) {
    if (type === 'header') {
        return `
            <th>设备ID</th><th>注册时间</th><th>用户</th><th>操作</th>
        `;
    }
    return `
        <td><b>${d.device_id}</b></td>
        <td>${d.register_time}</td>
        <td><b>${d.user || "未知"}</b></td>
        <td><button onclick="deviceOp('approve', '${d.device_id}', '${d.user}')">批准</button></td>
    `;
}

function renderApprovedDeviceRow(type, d) {
    if (type === 'header') {
        return `
            <th>设备ID</th><th>用户</th><th>状态</th><th>注册时间</th><th>操作</th>
        `;
    }
    return `
        <td><b>${d.device_id}</b></td>
        <td><b>${d.user || "未知"}</b></td>
        <td><b>${d.status === 1 ? "已批准" : "待批准"}</b></td>
        <td>${d.register_time}</td>
        <td>
            <button onclick="deviceOp('revoke', '${d.device_id}')">撤销</button>
            <button onclick="deviceOp('delete', '${d.device_id}')">删除</button>
        </td>
    `;
}

function renderOnlineDeviceRow(type, d) {
    if (type === 'header') {
        return `<th>设备ID</th><th>最后心跳时间</th><th>操作</th>`;
    }
    return `<td><b>${d.device_id}</b></td><td>${d.last_heartbeat}</td><td><button onclick="controlDevice('${d.device_id}', 'start')">启动</button> <button onclick="controlDevice('${d.device_id}', 'stop')">停止</button></td>`;
}


// 设备操作（批准/撤销/删除）
function deviceOp(action, deviceID, user) {
    const actionMap = {
        approve: { url: "/api/admin/device/approve", confirm: false, msg: "批准成功" },
        revoke: { url: "/api/admin/device/revoke", confirm: "确定要将该设备移入待批准吗？", msg: "已移入待批准" },
        delete: { url: "/api/admin/device/delete", confirm: "确定要删除该设备吗？", msg: "删除成功" },
    };
    const conf = actionMap[action];
    if (!conf)
        return;
    if (conf.confirm && !confirm(conf.confirm))
        return;
    let body = { device_id: deviceID };
    if (action === "approve" && user)
        body.user = user;
    postJSON(conf.url, body)
        .then(() => {
            fetchPendingDevice();
            fetchApprovedDevice();
            fetchOnlineDevice();
            alert(conf.msg);
        })
        .catch(() => {
            alert(`${actionMap[action].msg}失败`);
        });
}

// 用户加载自己设备
function userFetchDevice() {
    authFetch("/api/user/device/query")
        .then(r => r.json())
        .then(list => {
            const el = document.getElementById("userDeviceList");
            if (!el) return;
            if (!list.length) {
                el.innerHTML = "无设备";
                return;
            }
            const tableHtml = `
                <table class="device-table">
                    <thead>
                        <tr><th>设备ID</th><th>状态</th><th>注册时间</th></tr>
                    </thead>
                    <tbody>
                        ${list.map(d => `<tr><td><b>${d.device_id}</b></td><td>${d.status === 1 ? "已批准" : "待批准"}</td><td>${d.register_time}</td></tr>`).join("")}
                    </tbody>
                </table>
            `;
            el.innerHTML = tableHtml;
        });
}

// 用户加载在线设备
function userFetchOnlineDevice() {
    authFetch("/api/user/device/online/query")
        .then(r => r.json())
        .then(list => {
            const el = document.getElementById("userOnlineDeviceList");
            if (!el) return;
            if (!list.length) {
                el.innerHTML = "无在线设备";
                return;
            }
            const tableHtml = `
                <table class="device-table">
                    <thead>
                        <tr>${userRenderOnlineDeviceRow('header')}</tr>
                    </thead>
                    <tbody>
                        ${list.map(d => `<tr>${userRenderOnlineDeviceRow('row', d)}</tr>`).join('')}
                    </tbody>
                </table>
            `;
            el.innerHTML = tableHtml;
        });
}

function userRenderOnlineDeviceRow(type, d) {
    if (type === 'header') {
        return `<th>设备ID</th><th>最后心跳时间</th><th>操作</th>`;
    }
    return `<td><b>${d.device_id}</b></td><td>${d.last_heartbeat}</td><td><button onclick="showUserConfigDialog('${d.device_id}')">下发配置</button> <button onclick="controlDevice('${d.device_id}', 'start')">启动</button> <button onclick="controlDevice('${d.device_id}', 'stop')">停止</button> <button onclick="offlineDevice('${d.device_id}')">下线设备</button></td>`;
}

// 用户下线设备
function offlineDevice(deviceID) {
    if (!confirm("确定下线该设备？")) return;
    authFetch("/api/user/device/offline", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ device_id: deviceID })
    })
        .then(async (res) => {
            if (res.ok) {
                userFetchDevice();
                alert("设备已下线");
            }
            else {
                const msg = await res.text();
                alert("下线失败：" + (msg || "未知错误"));
            }
        })
        .catch((e) => {
            alert("请求失败：" + (e.message || "未知错误"));
        });
}

// 控制设备（启动/停止）
function controlDevice(deviceID, action) {
    authFetch('/api/device/control', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ device_id: deviceID, action })
    })
    .then(r => {
        if (r.ok) {
            alert((action === 'start' ? '启动' : '停止') + '命令已下发');
        } else {
            r.text().then(t => alert('操作失败: ' + t));
        }
    })
    .catch(e => alert('请求失败: ' + e.message));
}