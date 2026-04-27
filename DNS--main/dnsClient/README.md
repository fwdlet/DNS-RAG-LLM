### DNS探针端

Windows下：在该文件夹中打开powershell，输入`./dnsProbe --ip=服务器地址 --u=用户名 --p=密码`执行（CLI），或右键以管理员身份运行（GUI）

Linux下：在该文加中打开root权限的终端，输入`sudo ./dnsProbe --ip=服务器地址 --u=用户名 --p=密码` 执行（CLI），或输入`sudo ./dnsProbe`执行（GUI）

**注**：

1. 若有“未检测到网卡”的情况出现，此时网卡可能没有什么流量，多次重启该程序即可
2. Linux端运行GUI时推荐手动选择网卡（ens33、eth0等），自选可能会选错