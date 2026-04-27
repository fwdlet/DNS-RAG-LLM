#### DNS抓包服务端

在dnsServer文件夹中打开命令行，

安装docker：

    sudo apt-get install -y docker.io
    sudo apt-get install -y docker-compose


创建文件路径：

    sudo mkdir -p /etc/docker

将文件夹中daemon.json文件放在/etc/docker下：

    sudo mv daemon.json /etc/docker

然后执行：

    systemctl daemon-reload
    systemctl restart docker

验证docker安装：

    sudo docker run hello-world

出现 **Hello from Docker!** 说明配置成功

关闭 mysql ：

```
systemctl stop mysql
```

首次运行程序或修改`.go`文件后重新编译：

    sudo docker-compose up --build

或

```
sudo docker-compose build
sudo docker-compose up
```

出现

......

Starting mysql8 ... done 

Creating dnsserver_app_1 ... done

......

则表示运行成功，可以在浏览器访问 `https://localhost:8443` 或 `https://本机IP:8443`，此时 Ctrl + C 时是关闭docker容器

关闭后重启docker容器：

```
sudo docker-compose restart
```

 重启后关闭docker容器：

```
sudo docker-compose stop
```

删除docker容器：

```
sudo docker-compose down
```

若同时要清除数据库中内容：

```
sudo docker-compose down -v
```

删除docker容器后需要重新部署：

```
sudo docker-compose up
```
