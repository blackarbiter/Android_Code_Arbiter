# Android Code Arbiter

## 介绍

 根据Find Security Bugs：http://find-sec-bugs.github.io/ 改写，去除其中跟Android漏洞无关的漏洞，保留与Android相关的，同时增加其它一些检测项，从而形成了针对Android的源码审计工具。同时将检测结果设置成中文，方便开发者查看问题原因及修改建议。

## 检测项

 - 域名（Hostname）校验不严格
 - Webview证书错误未处理
 - 命令注入/动态加载
 - TrustManager未进行证书校验
 - MD2、MD4、MD5弱信息摘要算法使用
 - SHA-1弱信息摘要算法
 - 错误字符转换
 - DES/DESede使用
 - RSA Nopadding
 - RSA密钥长度问题
 - ECB模式
 - 加密无完整性校验
 - CBC/PKCS5Padding模式
 - 外部文件存储
 - 发送广播消息未设置接收权限
 - 发送粘性广播
 - 动态注册广播接收器未设置权限
 - 创建模式使用不当
 - Webview设置不当
 - Webview加载外部资源
 - 使用System.out/err输出信息
 - 本地拒绝服务
 - 本地潜在SQL注入
 - 硬编码

## 源码打包

进入根目录，运行 mvn clean install，如果没有错误，那么在plugin/target目录中就会发现生成的jar包。




