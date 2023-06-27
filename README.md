# ComputerNetworkCourseDesign

### 北京邮电大学 计算机网络课程设计 2020

一、教学目的

1.进一步熟悉socket 编程，通过查阅资料来完成服务器与客户端之间的通信。
设计时应该充分考虑应用场景，有容错、高效、用户体验等方面的尝试。

2.培养工程合作能力，采取良好的团队分工协作模式，充分发挥各组员特长，
互相支撑共同协作，更好更高效地完成课题。

二、实验内容

1.设计一个DNS 服务器程序，读入“域名-IP 地址”对照表，当客户端查询域名
对应的IP 地址时，用域名检索该对照表，三种检索结果：

（1）检索结果为ip 地址0.0.0.0，则向客户端返回“域名不存在”的报错消息，
而不是返回IP 地址为0.0.0.0（不良网站拦截功能）

（2）检索结果为普通IP 地址，则向客户返回这个地址（服务器功能）

（3）表中未检到该域名，则向因特网DNS 服务器发出查询，并将结果返给客户
端（中继功能）考虑多个计算机上的客户端会同时查询，需要进行消息ID 的转
换。

2.Windows/Linux 源程序的一致性能

3.LRU 缓冲池
