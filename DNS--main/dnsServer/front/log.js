// 设备日志查询
function fetchDeviceLog() {
    const deviceID = document.getElementById("logDeviceID").value;
    const start = document.getElementById("logStartTime").value;
    const end = document.getElementById("logEndTime").value;
    let url = `/api/admin/device/logs/query?`;
    if (deviceID) url += `device_id=${encodeURIComponent(deviceID)}&`;
    if (start) url += `start=${encodeURIComponent(start)}&`;
    if (end) url += `end=${encodeURIComponent(end)}`;
    authFetch(url)
        .then((r) => r.json())
        .then((list) => {
            const div = document.getElementById("deviceLogResult");
            if (!list.length) {
                div.innerHTML = "无日志";
                return;
            }
            div.innerHTML = `
                <table class="device-table">
                    <thead><tr><th>设备ID</th><th>时间</th><th>文件数</th></tr></thead>
                    <tbody>
                        ${list.map(l => `<tr><td><b>${l.device_id}</b></td><td>${l.time}</td><td>${l.file_count}</td></tr>`).join("")}
                    </tbody>
                </table>
            `;
        });
}

// 用户登录日志查询
function fetchUserLog() {
    const username = document.getElementById("loginLogUsername").value.trim();
    if (!username) {
        document.getElementById("userLoginLogList").innerText = "请选择用户";
        return;
    }
    authFetch(`/api/admin/user/log/query?username=${encodeURIComponent(username)}`)
        .then((r) => r.json())
        .then((list) => {
            window._userLoginLogList = list;
            window.userLoginLogList_pageCallback(1);
        });
}

window.userLoginLogList_pageCallback = function(page) {
    const list = window._userLoginLogList || [];
    const el = document.getElementById("userLoginLogList");
    if (!list.length) {
        el.innerHTML = "无登录日志";
        return;
    }
    const pageSize = 5;
    const totalPages = Math.ceil(list.length / pageSize);
    const start = (page - 1) * pageSize;
    const pageList = list.slice(start, start + pageSize);
    el.innerHTML = `
        <table class="device-table">
            <thead><tr><th>用户</th><th>登录时间</th><th>登出时间</th></tr></thead>
            <tbody>
                ${pageList.map(l => `<tr><td><b>${l.username}</b></td><td>${l.login_time}</td><td>${l.logout_time}</td></tr>`).join("")}
            </tbody>
        </table>
        <div id="userLoginLogList_pagination"></div>
        <button onclick="deleteUserLog('${pageList[0]?.username || ''}')">删除该用户所有登录日志</button>
    `;
    // 分页控件
    const pagDiv = document.getElementById("userLoginLogList_pagination");
    if (pagDiv) {
        pagDiv.innerHTML = `
            <div class="pagination-controls">
                <button ${page === 1 ? "disabled" : ""} onclick="window.userLoginLogList_pageCallback(${page - 1})">上一页</button>
                <span>第 ${page} / ${totalPages} 页</span>
                <button ${page >= totalPages ? "disabled" : ""} onclick="window.userLoginLogList_pageCallback(${page + 1})">下一页</button>
            </div>
        `;
    }
};

// 管理员删除用户登录日志
function deleteUserLog(username) {
    if (!confirm(`确定要删除用户 ${username} 的所有登录日志吗？`)) return;
    postJSON("/api/admin/user/log/delete", { username })
        .then((r) => {
            if (r.ok) {
                alert("日志删除成功");
                fetchUserLog();
            } else
                r.text().then(t => alert("日志删除失败：" + t));
        });
}