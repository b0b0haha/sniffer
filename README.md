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

### 5.程序界面和运行效果

- 程序主界面

  ![image-20200322103536550](C:%5CUsers%5Cesther%5CAppData%5CRoaming%5CTypora%5Ctypora-user-images%5Cimage-20200322103536550.png)

- 流量分析部分

  - 对所有抓取到的数据包的日志

    相应结果保存在/log/packet_log_（2020_03_21_23_47_16）-时间戳

    ![image-20200322104214677](C:%5CUsers%5Cesther%5CAppData%5CRoaming%5CTypora%5Ctypora-user-images%5Cimage-20200322104214677.png)

  - 针对各层协议数据包的统计分析

    相应的结果保存在/png

    ![image-20200322103913833](C:%5CUsers%5Cesther%5CAppData%5CRoaming%5CTypora%5Ctypora-user-images%5Cimage-20200322103913833.png)

    ![image-20200322103927285](C:%5CUsers%5Cesther%5CAppData%5CRoaming%5CTypora%5Ctypora-user-images%5Cimage-20200322103927285.png)

    ![image-20200322104025382](C:%5CUsers%5Cesther%5CAppData%5CRoaming%5CTypora%5Ctypora-user-images%5Cimage-20200322104025382.png)

    

  - 获取http/https请求（结果保存在日志中）

    ![image-20200322104108537](C:%5CUsers%5Cesther%5CAppData%5CRoaming%5CTypora%5Ctypora-user-images%5Cimage-20200322104108537.png)

    日志保存在/log/req_result.log

    ![image-20200322104236037](C:%5CUsers%5Cesther%5CAppData%5CRoaming%5CTypora%5Ctypora-user-images%5Cimage-20200322104236037.png)

  - 流入/出流量IP归属地查询（包括可视化界面和日志）

    可视化界面：

    相应结果保存在/html/query_address.html

    ![image-20200322104339309](C:%5CUsers%5Cesther%5CAppData%5CRoaming%5CTypora%5Ctypora-user-images%5Cimage-20200322104339309.png)

    日志：（保存在/log/in_ip_addr.txt和/log/out_ip_addr.txt)

    - in_ip_addr.txt:

    ![image-20200322104442925](C:%5CUsers%5Cesther%5CAppData%5CRoaming%5CTypora%5Ctypora-user-images%5Cimage-20200322104442925.png)

    - out_ip_addr.txt:

      ![image-20200322104647442](C:%5CUsers%5Cesther%5CAppData%5CRoaming%5CTypora%5Ctypora-user-images%5Cimage-20200322104647442.png)

  - 流出/流入流量数据包数量和时间统计

    相应结果保存在/html/ip_packet_statistic.html

    ![image-20200322104820191](C:%5CUsers%5Cesther%5CAppData%5CRoaming%5CTypora%5Ctypora-user-images%5Cimage-20200322104820191.png)

    ![image-20200322104833292](C:%5CUsers%5Cesther%5CAppData%5CRoaming%5CTypora%5Ctypora-user-images%5Cimage-20200322104833292.png)

    ![image-20200322104846744](C:%5CUsers%5Cesther%5CAppData%5CRoaming%5CTypora%5Ctypora-user-images%5Cimage-20200322104846744.png)

    

### 3.安装使用

```
git clone https://github.com/Estherbdf/sniffer.git
cd ./sniffer
pip3 install requirements.txt
python3 capture_packet.py
```









