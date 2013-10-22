证书说明：
usercert1.pem：摄像机合法数字证书
usercert2.pem：网络硬盘录像机合法数字证书
attacker.pem:摄像机非法数字证书，扮演攻击者角色进行三元对等身份认证，不能通过认证过程。

脚本运行说明：
演示步骤：演示没有证书的--->演示持有非法证书的--->演示持有合法证书的
脚本运行先后顺序：deletecert.sh--->attacker.sh--->resetcert.sh
deletecert.sh作用：将合法证书名字重命名，导致找不到合法证书
attacker.sh作用：将攻击者的证书名字attacker.pem重命名为usercert1.pem,扮演攻击者行为
resetcert.sh作用：将原来的合法证书名字还原，进行合法证书的认证过程。

