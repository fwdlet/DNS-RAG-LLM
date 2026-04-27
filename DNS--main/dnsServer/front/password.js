// 管理员修改用户密码
function showAdminUpdatePwd() {
    document.getElementById("adminChangeUserPwdDialog").style.display = "block";
}

function closeAdminUpdatePwd() {
    document.getElementById("adminChangeUserPwdDialog").style.display = "none";
    document.getElementById("changeUserPwdMsg").innerText = "";
}

function adminSubmitPwd() {
    const username = document.getElementById("changePwdUsername").value;
    const newPwd = document.getElementById("changePwdNew").value;
    const msg = document.getElementById("changeUserPwdMsg");
    msg.innerText = "";
    if (!username || !newPwd) {
        msg.innerText = "请填写用户名和新密码";
        return;
    }
    postJSON("/api/admin/user/pwd/update", { username, new_password: newPwd })
        .then((r) => {
            if (r.ok) {
                msg.innerText = "修改成功";
                setTimeout(closeAdminUpdatePwd, 2000);
            } else
                r.text().then(t => msg.innerText = t);
        })
        .catch(() => msg.innerText = "网络错误");
}

// 用户更新自己的密码
function showUserUpdatePwd() {
    document.getElementById("userChangePwdDialog").style.display = "block";
}

function closeUserUpdatePwd() {
    document.getElementById("userChangePwdDialog").style.display = "none";
    document.getElementById("userChangePwdMsg").innerText = "";
}

function userSubmitPwd() {
    const newPwd = document.getElementById("userNewPwd").value;
    const msg = document.getElementById("userChangePwdMsg");
    msg.innerText = "";
    if (!newPwd) {
        msg.innerText = "请填写新密码";
        return;
    }
    postJSON("/api/user/pwd/update", { new_password: newPwd })
        .then((r) => {
            if (r.ok) {
                msg.innerText = "修改成功";
                setTimeout(closeUserUpdatePwd, 2000);
            } else
                r.text().then(t => msg.innerText = t);
        })
        .catch(() => msg.innerText = "网络错误");
}