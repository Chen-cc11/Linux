# 1 shell_typing_game.sh
一个用Bash编写的命令行打字练习小游戏。通过多种练习模式帮助提升打字速度和准确度，包括数字、字母、混合字符和单词练习。
在终端执行后，即可以交互方式进行小游戏。
```bash
chmod +x shell_typing_game.sh
bash shell_typing_game.sh
```
# 2 get_server_info.sh
用于检索Linux服务器的CPU、内存、磁盘和其他基本信息。
```bash
chmod +x get_server_info
bash get_server_info.sh
```

# 3 configure_ssh.sh
Bash脚本，用于在Linux系统上配置SSH密钥认证，**实现本地无密码登录**。脚本会自动生成SSH密钥对，配置授权密钥，并测试SSH连接。  
```bash
chmod +x configure_ssh.sh
bash configure_ssh.sh
```
在执行脚本过程中遇到提示输入私钥和公钥的保存位置时，可以直接按enter，这样会默认分别保存到`configure_ssh.sh`和`~/.ssh/id_rsa.pub` 中