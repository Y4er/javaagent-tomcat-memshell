# javaagent-tomcat-memshell
Shiro反序列化注入 java agent 类型的内存 shell

# 效果
![shell.gif](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/593424/21f519ec-a731-13c4-eb06-60d03b75fc67.gif)

# 项目说明
1. MyAgent.jar 是测试打包好的agent文件
2. org.chabug.demo.CC10 用来生成 rememberMe Cookie，依赖于 ysoserial

# 使用方法

## 通过反序列化注入
1. 通过命令执行下载或者 base64 写入 MyAgent.jar
2. 修改 org/chabug/demo/CC10.java:137 为 MyAgent.jar 绝对路径
3. 发送 rememberMe Cookie

## 通过执行命令注入
```
java -jar MyAgent.jar agentPath
```

# 参考
1. https://www.cnblogs.com/rebeyond/p/9686213.html
2. https://github.com/rebeyond/memShell
3. https://www.cnblogs.com/rickiyang/p/11368932.html
4. http://y4er.com/post/javaagent-tomcat-memshell/
