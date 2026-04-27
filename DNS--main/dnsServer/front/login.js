function showLoginInterface() {
    document.getElementById("mainContainer").style.display = "none";
    document.getElementById("loginContainer").style.display = "flex";
}

function hideLoginInterface() {
    document.getElementById("mainContainer").style.display = "";
    document.getElementById("loginContainer").style.display = "none";
}

function login() {
    const username = document.getElementById("loginUser").value;
    const password = document.getElementById("loginPwd").value;
    document.getElementById("loginMsg").innerText = "正在登录...";
    fetch("/api/platform/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password })
    }).then((r) => {
        if (!r.ok) 
            throw new Error("登录失败");
        return r.json();
    }).then((res) => {
        if (res.status === "pending") {
            document.getElementById("loginMsg").innerText = "账号待管理员审核";
            return;
        }
        sessionToken = res.token;
        document.getElementById("sidebar").style.display = "block";
        hideLoginInterface();
        showSectionByRole(res.role);
    }).catch(() => {
        document.getElementById("loginMsg").innerText = "用户名或密码错误";
    });
}

function logout() {
    document.getElementById("sidebar").style.display = "none";
    // 清除可能的状态
    document.getElementById("loginUser").value = "";
    document.getElementById("loginPwd").value = "";
    document.getElementById("loginMsg").innerText = "";
    // 清除token等
    localStorage.removeItem("sessionToken");
    // 记录登出日志
    postJSON("/api/platform/logout", {}).finally(() => {
        sessionToken = null;
        showLoginInterface();
    });
}