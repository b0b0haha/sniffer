# Sniffer

这是一个基于python实现的仿wireshark的网络协议分析器

### 1.功能

#### 基本功能

- 网卡选择
- 抓取数据包
- 保存数据
- 清除数据
- 读取数据
- 流量包基本信息显示
- 协议分析
- hexdump内容

#### 流量分析功能

- 流量协议统计（分层）
- 获取http/https请求（该功能存在问题）
- 流入/出流量IP归属地查询和统计
- 流量时间统计

### 2.效果展示

#### 基本界面

#### 流量分析功能



### 3.安装使用

```
git clone https://github.com/Estherbdf/sniffer.git
cd ./sniffer
pip3 install requirements.txt
python3 capture_packet.py
```



### 4.参考

https://blog.csdn.net/wmrem/article/details/80465104?depth_1-utm_source=distribute.pc_relevant.none-task&utm_source=distribute.pc_relevant.none-task







