let _adminAutoRefreshTimer = null;

// 根据权限显示不同界面
function showSectionByRole(role) {
    document.getElementById("adminNav").style.display = role === "admin" ? "" : "none";
    document.getElementById("userNav").style.display = role === "user" ? "" : "none";
    // 隐藏所有section
    document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
    if (role === "admin") {
        showSection('deviceSection', document.getElementById('nav-device'));
        fetchPendingDevice();
        fetchApprovedDevice();
        fetchOnlineDevice();
    }
    else {
        showSection('userDeviceSection', document.getElementById('nav-user-device'));
        userFetchDevice();
        userFetchOnlineDevice();
    }
}

// 切换模块显示，并高亮导航按钮
function showSection(sectionId, navItem) {
    document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
    const target = document.getElementById(sectionId);
    if (target) {
        target.classList.add('active');
        target.style.display = "";
    }
    // 隐藏其它section
    document.querySelectorAll('.section').forEach(s => {
        if (s.id !== sectionId) 
            s.style.display = "none";
    });
    document.querySelectorAll('.nav-item').forEach(btn => btn.classList.remove('active'));
    if (navItem) 
        navItem.classList.add('active');
    loadDeviceSelects();
    if (sectionId === "userPacketSection")
        userfetchPacket();
    if (sectionId === "userDeviceSection") {
        userFetchDevice();
        userFetchOnlineDevice();
    }

    // 只在设备管理或用户管理界面定时刷新
    if (_adminAutoRefreshTimer) {
        clearInterval(_adminAutoRefreshTimer);
        _adminAutoRefreshTimer = null;
    }
    if (sectionId === "deviceSection") {
        fetchPendingDevice();
        fetchApprovedDevice();
        fetchOnlineDevice();
        _adminAutoRefreshTimer = setInterval(() => {
            fetchPendingDevice();
            fetchApprovedDevice();
            fetchOnlineDevice();
        }, 20000);
    } else if (sectionId === "adminUserSection") {
        fetchApprovedUser();
        fetchPendingUser();
        fetchOnlineUserList();
        _adminAutoRefreshTimer = setInterval(() => {
            fetchApprovedUser();
            fetchPendingUser();
            fetchOnlineUserList();
        }, 20000);
    }
}