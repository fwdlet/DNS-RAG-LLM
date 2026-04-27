// 管理员添加用户
function showAddUser() {
    document.getElementById("addUserDialog").style.display = "block";
}

function closeAddUser() {
    document.getElementById("addUserDialog").style.display = "none";
    document.getElementById("addUserMsg").innerText = "";
    document.getElementById("addUserUsername").value = "";
    document.getElementById("addUserPassword").value = "";
    document.getElementById("addUserRole").value = "user";
}

function submitAdd() {
    const username = document.getElementById("addUserUsername").value.trim();
    const password = document.getElementById("addUserPassword").value;
    const role = document.getElementById("addUserRole").value;
    const msg = document.getElementById("addUserMsg");
    msg.innerText = "";
    if (!username || !password) {
        msg.innerText = "请填写用户名和密码";
        return;
    }
    postJSON("/api/admin/user/add", { username, password, role })
        .then(r => {
            if (r.ok) {
                msg.innerText = "添加成功";
                setTimeout(closeAddUser, 2000)
            } else
                r.text().then(t => msg.innerText = t);
        })
        .catch(() => msg.innerText = "网络错误");
}

// 用户注册
function showRegisterUser() {
    document.getElementById("registerDialog").style.display = "block";
}

function closeRegisterUser() {
    document.getElementById("registerDialog").style.display = "none";
    document.getElementById("registerMsg").innerText = "";
    document.getElementById("registerUsername").value = "";
    document.getElementById("registerPassword").value = "";
}

function submitRegister() {
    const username = document.getElementById("registerUsername").value.trim();
    const password = document.getElementById("registerPassword").value;
    const msg = document.getElementById("registerMsg");
    msg.innerText = "";
    if (!username || !password) {
        msg.innerText = "请填写用户名和密码";
        return;
    }
    postJSON("/api/user/register", { username, password })
        .then(r => {
            if (r.ok) {
                msg.innerText = "注册成功，请等待管理员审核";
                setTimeout(closeRegisterUser, 5000)
            } else
                r.text().then(t => msg.innerText = t);
        })
        .catch(() => msg.innerText = "网络错误");
}