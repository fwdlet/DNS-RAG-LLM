// 初始化：填充下拉框 + 定时刷新在线设备和下拉框
window.addEventListener("DOMContentLoaded", () => {
    loadDeviceSelects();
    setInterval(loadDeviceSelects, 15000); // 每15秒自动刷新下拉框
    userFetchOnlineDevice(); // 页面加载时拉取用户在线设备
});

// 页面加载时始终显示登录界面
window.onload = function () {
    showLoginInterface();
};