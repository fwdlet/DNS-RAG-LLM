// 管理员批准用户
function approveUser(username) {
    if (!confirm(`确定批准用户 ${username} 吗？`)) 
        return;
    postJSON("/api/admin/user/approve", { username })
        .then(r => {
            if (r.ok) {
                alert("批准成功");
                fetchPendingUser();
                fetchApprovedUser();
            } else {
                r.text().then(t => alert("批准失败：" + t));
            }
        });
}

// 管理员获取待批准用户列表
function fetchPendingUser() {
    authFetch("/api/admin/user/pending/query")
        .then(r => r.json())
        .then(list => {
            window._pendingUserList = list;
            window.pendingUserList_pageCallback(1);
        });
}

// 分页
window.pendingUserList_pageCallback = function(page) {
    const list = window._pendingUserList || [];
    const el = document.getElementById("pendingUserList");
    if (!list.length) {
        el.innerHTML = "无待审核用户";
        return;
    }
    const pageSize = 5;
    const totalPages = Math.ceil(list.length / pageSize);
    const start = (page - 1) * pageSize;
    const pageList = list.slice(start, start + pageSize);
    el.innerHTML = `
        <table class="device-table">
            <thead><tr><th>用户名</th><th>注册时间</th><th>操作</th></tr></thead>
            <tbody>
                ${pageList.map(u => `<tr><td><b>${u.username}</b></td><td>${u.create_time}</td><td><button onclick="approveUser('${u.username}')">批准</button> <button onclick="deleteUser('${u.username}')">删除</button></td></tr>`).join("")}
            </tbody>
        </table>
        <div id="pendingUserList_pagination"></div>
    `;
    // 分页控件
    const pagDiv = document.getElementById("pendingUserList_pagination");
    if (pagDiv) {
        pagDiv.innerHTML = `
            <div class="pagination-controls">
                <button ${page === 1 ? "disabled" : ""} onclick="window.pendingUserList_pageCallback(${page - 1})">上一页</button>
                <span>第 ${page} / ${totalPages} 页</span>
                <button ${page >= totalPages ? "disabled" : ""} onclick="window.pendingUserList_pageCallback(${page + 1})">下一页</button>
            </div>
        `;
    }
};

// 管理员获取已批准用户列表
function fetchApprovedUser() {
    authFetch("/api/admin/user/approved/query")
        .then(r => r.json())
        .then(list => {
            window._approvedUserList = list;
            window.userList_pageCallback(1);
        });
}

// 分页
window.userList_pageCallback = function(page) {
    const list = window._approvedUserList || [];
    const el = document.getElementById("userList");
    if (!list.length) {
        el.innerHTML = "无用户";
        return;
    }
    const pageSize = 5;
    const totalPages = Math.ceil(list.length / pageSize);
    const start = (page - 1) * pageSize;
    const pageList = list.slice(start, start + pageSize);
    el.innerHTML = `
        <table class="device-table">
            <thead><tr><th>用户名</th><th>注册时间</th><th>权限</th><th>操作</th></tr></thead>
            <tbody>
                ${pageList.map(u => `<tr><td><b>${u.username}</b></td><td>${u.create_time}</td><td>${u.role === "admin" ? "管理员" : "普通用户"}</td><td><button onclick="deleteUser('${u.username}')">删除</button></td></tr>`).join("")}
            </tbody>
        </table>
        <div id="userList_pagination"></div>
    `;
    // 分页控件
    const pagDiv = document.getElementById("userList_pagination");
    if (pagDiv) {
        pagDiv.innerHTML = `
            <div class="pagination-controls">
                <button ${page === 1 ? "disabled" : ""} onclick="window.userList_pageCallback(${page - 1})">上一页</button>
                <span>第 ${page} / ${totalPages} 页</span>
                <button ${page >= totalPages ? "disabled" : ""} onclick="window.userList_pageCallback(${page + 1})">下一页</button>
            </div>
        `;
    }
};

// 管理员删除用户
function deleteUser(username) {
    if (!confirm(`确定要删除用户 ${username} 吗？此操作不可恢复！`)) return;
    postJSON("/api/admin/user/delete", { username })
        .then(r => {
            if (r.ok) {
                alert("删除成功");
                fetchApprovedUser?.();
            } else 
                r.text().then(t => alert("删除失败：" + t));
        });
}

// 管理员查询在线用户
function fetchOnlineUserList() {
  authFetch("/api/admin/user/online/query")
    .then(r => r.json())
    .then(list => {
      const el = document.getElementById("onlineUserList");
      el.innerHTML = list.length
        ? "<ul>" + list.map(u => `<li>用户: <b>${u.username}</b></li>`).join("") + "</ul>"
        : "无在线用户";
    });
}