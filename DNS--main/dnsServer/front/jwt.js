let sessionToken = null;

// 重新生成 JWT 密钥
function regenerateJWTSecret() {
    if (!confirm("确定要重新生成JWT密钥吗？操作后所有已登录用户需重新登录。")) return;
    authFetch("/api/admin/jwt/regenerate", { method: "POST" })
        .then(r => {
            const msg = document.getElementById("jwtSecretMsg");
            if (r.ok) {
                msg.innerText = "密钥已成功重新生成";
                // 强制登出当前用户
                setTimeout(() => {
                    logout(); // 调用登出逻辑
                }, 1000); // 等1秒显示提示后退出，可根据需要调整时间
            } else {
                msg.innerText = "密钥生成失败";
            }
            setTimeout(() => (msg.innerText = ""), 3000);
        })
        .catch(() => {
            document.getElementById("jwtSecretMsg").innerText = "密钥生成失败";
        });
}

// 包装fetch，自动加token和处理401
function authFetch(url, options = {}) {
    options.headers = options.headers || {};
    if (sessionToken) 
        options.headers["Authorization"] = "Bearer " + sessionToken;
    return fetch(url, options).then(r => {
        if (r.status === 401) {
            sessionToken = null;
            showLoginInterface();
            throw new Error("未登录");
        }
        return r;
    });
}

// 通用请求方法封装，支持 loading 与 error 提示
function postJSON(url, data) {
    return authFetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(data),
    });
}