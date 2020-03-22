#coding = utf-8
import datetime
import threading
import sys
import os
import re
import collections
import tkinter
from tkinter import *
from tkinter import ttk
from tkinter import font, filedialog
from tkinter.constants import *
from tkinter.messagebox import *
from tkinter.scrolledtext import ScrolledText
from tkinter.ttk import Treeview
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether
from scapy.layers import http

plt.rcParams['font.sans-serif']=['SimHei']
import numpy as np
import json
import requests
import geoip2.database
from geoip2.errors import AddressNotFoundError
from pyecharts.charts import *
from pyecharts.globals import *
from pyecharts.commons import *
from pyecharts import options as opts
from selenium import webdriver
from PIL import Image, ImageTk

protocal_choose_list = ['ALL', 'ether', 'ip', 'ip6', 'arp', 'decnet', 'tcp', 'udp', 'tcp or udp', 'icmp']

# 用来终止抓包线程的线程事件
stop_sending = threading.Event()
# 用来给抓到扥数据包编号
packet_id = 1
# 用来存放抓到的数据包
packet_list =[]

# 用来存放每个数据包各层的信息
ether_info={}
ip_info={}
tcp_info={}
#一些标志位
start_flag=False
stop_flag=False
save_flag=False
filter_flag=False
#本机的网卡列表
NIC_list=[]
lock = threading.Lock()
colors1=['pink','lavenderBlush','palevioletred','hotpink','deeppink']
colors2=['violet','purple','mediumorchid','darkviolet','darkorchid ','indigo','blueviolet','mediumpurple','lavender','white']
colors3=['blue','mediumblue','midnightblue','darkblue', 'navy','royalblue', 'cornflowerblue', 'lightsteelblue']
titles = ["network layer statistics", "transport layer statistics", "application layer statistics","http/https request get","ip address statistics","time flow analysis"]

##===========工具函数===========##
def log_format(file_path,orderd_dict_list):
    '''
    :param file_path: 示例：r"\log\nic.txt"
    :param orderd_dict:
    :return:
    '''
    col_width={}
    for row in orderd_dict_list:
        for k,v in row.items():
            if k not in col_width:
                col_width[k]=len(v)
            else:
                if(col_width[k]<len(v)):
                    col_width[k]=len(v)
        for k in row.keys():
            if k not in col_width:
                col_width[k]=len(k)
            else:
                if(col_width[k]<len(k)):
                    col_width[k]=len(k)
    print("col_width", col_width)
    output = sys.stdout
    outputfile = open(file_path, "w")
    sys.stdout = outputfile

    with open(file_path, "w") as file:

        for idx,finfo in enumerate(orderd_dict_list):
            if(idx==0):
                for key in orderd_dict_list[0].keys():
                    print(('{:<' + str(col_width[key]) + '}').format(key), end=' ')
                print()
            fvalue = ""
            for key, value in finfo.items():
                print(('{:<' + str(col_width[key]) + '}').format(value), end=' ')
            print()
    outputfile.close()
    sys.stdout = output

def get_host_ip():
    ip_count=[]
    global packet_list
    for pkt in packet_list:
        if(pkt.haslayer(IP)):
            src=pkt[IP].src
            dst=pkt[IP].dst
            ip_count.append(src)
            ip_count.append(dst)
    host_ip=collections.Counter(ip_count).most_common(1)[0][0]
    return host_ip

def get_public_ip():
    from json import load
    ip = None
    # four methods to get my public ip
    try:
        ip = requests.get('http://ip.42.pl/raw', timeout=3).text()
        return ip
    except:
        ip = None

    try:
        ip = load(requests.get('http://jsonip.com', timeout=3))['ip']
        return ip
    except:
        ip = None

    try:
        ip = load(requests.get('http://httpbin.org/ip', timeout=3))['origin']
        return ip
    except:
        ip = None
    try:
        ip = load(
            requests.get('https://api.ipify.org/?format=json', timeout=3))['ip']
        return ip
    except:
        ip = None
    return ip

def getNIC():
    '''
    获取本机的网卡信息
    :return:
    '''
    global NIC_list
    NIC_list.append("ALL")  # 加入所有的选项
    ##### 输出重定向
    output = sys.stdout
    project_path = os.path.dirname(os.path.abspath(__file__))

    file_path=project_path+r"\log\nic.txt"
    outputfile = open(file_path, "w")
    sys.stdout = outputfile
    show_interfaces()
    outputfile.close()
    sys.stdout = output
    ##### 对输出进行解析，获得网卡列表
    with open(file_path, "r") as file:
        header = file.readline()
        iface_index = header.index("IFACE")
        ip_index = header.index("IP")
        # print("index",iface_index,ip_index)

        lines = file.readlines()
        for line in lines:
            line = line[iface_index:ip_index]
            if line.startswith("["):
                continue
            line = line.strip()
            # print(line)
            NIC_list.append(line)
    os.remove(file_path)
    return NIC_list

def process_Ether(packet):
    src = packet[Ether].src
    dst = packet[Ether].dst
    type = packet[Ether].type
    types = {0x0800: 'IPv4', 0x0806: 'ARP', 0x86dd: 'IPv6', 0x88cc: 'LLDP', 0x891D: 'TTE'}
    if type in types:
        proto = types[type]
    else:
        proto = 'LOOP'  # 协议

    if proto in ether_info:
        ether_info[proto] += 1
    else:
        ether_info[proto] = 1

    return (proto, src, dst)

def process_IP(packet, proto):
    # IP
    if proto == 'IPv4':
        # 建立协议查询字典
        protos = {1: 'ICMP', 2: 'IGMP', 4: 'IP', 6: 'TCP', 8: 'EGP', 9: 'IGP', 17: 'UDP', 41: 'IPv6', 50: 'ESP',
                  89: 'OSPF'}
        src = packet[IP].src
        dst = packet[IP].dst
        proto = packet[IP].proto
        if proto in protos:
            proto = protos[proto]
            if proto in ip_info:
                ip_info[proto] += 1
            else:
                ip_info[proto] = 1
        return (proto, src, dst)

    elif proto == 'IPv6':
        protos = {
            4: "IP",
            6: "TCP",
            17: "UDP",
            41: "IPv6",
            47: "GRE",
            58: "ICMPv6",
            112: "VRRP",
            132: "SCTP",
        }
        src = packet[IPv6].src
        dst = packet[IPv6].dst
        proto = packet[IPv6].nh
        if proto in protos:
            proto = protos[proto]
            if proto in ip_info:
                ip_info[proto] += 1
            else:
                ip_info[proto] = 1
        return (proto, src, dst)

    else:
        return None

def process_Transfer(packet, proto):
    # tcp
    if TCP in packet:

        protos_tcp = {80: 'Http', 443: 'Https', 23: 'Telnet', 21: 'Ftp', 20: 'ftp_data', 22: 'SSH', 25: 'SMTP'}
        sport = packet[TCP].sport
        dport = packet[TCP].dport
        if sport in protos_tcp:
            proto = protos_tcp[sport]
            if proto in tcp_info:
                tcp_info[proto] += 1
            else:
                tcp_info[proto] = 1

        elif dport in protos_tcp:
            proto = protos_tcp[dport]
            if proto in tcp_info:
                tcp_info[proto] += 1
            else:
                tcp_info[proto] = 1

    # udp
    elif UDP in packet:
        if packet[UDP].sport == 53 or packet[UDP].dport == 53:
            proto = 'DNS'
            if proto in tcp_info:
                tcp_info[proto] += 1
            else:
                tcp_info[proto] = 1
    return proto

def process_http(p):
    flag = False
    if p.haslayer(http.HTTPRequest):
        flag = True
        print("*********request******")
        http_name = 'HTTP Request'
        http_header = p[http.HTTPRequest].fields
        if ('Headers' in http_header.keys()):
            headers = http_header['Headers']


    elif p.haslayer(http.HTTPResponse):
        flag = True
        print("*********response******")
        http_name = 'HTTP Response'
        http_header = p[http.HTTPResponse].fields
        if ('Headers' in http_header.keys()):
            headers = http_header['Headers']

    return flag

def capture_packet():
    '''
    抓取数据包并保存
    :return:
    '''
    # 设置过滤条件
    filters = filter_entry.get()
    print("抓包条件：" + filters)
    nic = select_nic_combo.get().strip()
    print("网卡：", nic)
    stop_sending.clear()
    tmp = time.strftime('%Y_%m_%d_%H_%M_%S', time.localtime(time.time()))
    filename = r".\log\packet_log_%s.txt" % (tmp)
    if (nic != 'ALL'):
        # 抓取数据包并将抓到的包存在列表中
        sniff(iface=nic, prn=(lambda x: process_packet(x,filename)), filter=filters,
              stop_filter=(lambda x: stop_sending.is_set()))
    else:
        # 抓取数据包并将抓到的包存在列表中
        sniff(prn=(lambda x: process_packet(x, filename)), filter=filters,
              stop_filter=(lambda x: stop_sending.is_set()))

def process_packet(packet,filename):
    '''
    对抓到的数据包进行处理
    :param packet:
    :return:
    '''
    lock.acquire()
    global packet_list
    # 将抓到的包存在列表中
    packet_list.append(packet)

    # 抓包的时间
    time_array = time.localtime(packet.time)
    packet_time = time.strftime("%Y-%m-%d %H:%M:%S", time_array)
    ether_info_tuple = process_Ether(packet)
    proto = ether_info_tuple[0]
    src = ether_info_tuple[1]
    dst = ether_info_tuple[2]
    ip_info_tuple = process_IP(packet, ether_info_tuple[0])
    if (ip_info_tuple != None):
        proto = ip_info_tuple[0]
        src = ip_info_tuple[1]
        dst = ip_info_tuple[2]
    proto = process_Transfer(packet, proto)
    flag = process_http(packet)
    if (flag == True):
        print("index", len(packet_list))

    length = len(packet)  # 长度
    info = packet.summary()  # 信息
    global packet_id  # 数据包的编号
    packet_list_tree.insert("", 'end', packet_id, text=packet_id,
                            values=(packet_id, packet_time, src, dst, proto, length, info))
    packet_list_tree.update_idletasks()  # 更新列表，不需要修改
    packet_id = packet_id + 1
    # 将数据包的信息记录到日志中
    with open(filename, "a+") as f:
        if (packet_id-1== 1):
            header = 'packet_id' + '\t' + 'packet_time' + '\t' + 'src' + '\t' + 'dst' + '\t' + 'proto' + '\t' + 'length' + '\t' + 'info' + '\n'
            f.write(header)
        record = str(packet_id-1) + '\t' + str(packet_time) + '\t' + str(src) + '\t' + str(dst) + '\t' + str(proto) + '\t' + str(length)+ '\t' + str(info) + '\n'
        f.write(record)
    lock.release()

##===========分析和统计===========##
def get_request_url():
    '''
    记录请求的url
    :return:
    '''
    global packet_list
    req_list = []
    time_list=[]
    for pkt in packet_list:
        if TCP in pkt :
            if pkt[TCP].fields['dport'] == 80 and pkt.haslayer(http.HTTPRequest):
                http_header = pkt[http.HTTPRequest].fields
                #print("http_header", http_header)
                phttp_header={}
                for header ,info in http_header.items():
                    info=bytes.decode(info,encoding='utf-8')
                    phttp_header[header]=info
                print("phttp_header", phttp_header)
                if 'Host' in phttp_header and 'Path' in phttp_header:
                    req_url = 'http://' + phttp_header['Host'] + phttp_header['Path']
                    time_array = time.localtime(pkt.time)
                    mytime = time.strftime("%Y-%m-%d %H:%M:%S", time_array)
                    req_list.append(req_url)
                    time_list.append(mytime)
    # print req_list
    print(str(len(req_list)) + '  request url achieved.')
    project_path = os.path.dirname(os.path.abspath(__file__))
    file_path = project_path + r'\log\req_result.log'
    f = open(file_path, 'w+')
    record ='req_link' + '\t' + 'publish_time' +'\n'
    f.write(record)
    for index, url in enumerate(req_list):
        record = url + '\t' + str(time_list[index])+'\n'
        f.write(record)
    f.close()
    showinfo("提示","获取的requets的信息已经保存至/log/req_result.log")

def analysis_plot(info_dict,type):
    #windows = Tk()
    datas = []
    # 添加标题
    if(type=="ether"):
        title="network layer statistics"
        i = 0
        for proto, num in info_dict.items():
            data = [proto, num, colors1[i]]
            datas.append(data)
            i += 1
        print("datas", datas)
    elif(type=="ip"):
        title="transport layer statistics"
        i = 0
        for proto, num in info_dict.items():
            data = [proto, num, colors2[i]]
            datas.append(data)
            i += 1
        print("datas", datas)
    elif(type=="transport"):
        title="application layer statistics"
        i = 0
        for proto, num in info_dict.items():
            data = [proto, num, colors3[i]]
            datas.append(data)
            i += 1
        print("datas", datas)
    #windows.title(title)

    plt.Figure(figsize=(6, 9),dpi=100)  # 调节图形大小
    labels=[]
    sizes=[]
    colors=[]
    max_size=datas[0][1]
    max_index=0
    for cnt,data in enumerate(datas):
        labels.append(data[0]) # 定义标签
        sizes.append(data[1])
        if(data[1]>max_size):
            max_size=data[1]
            max_index=cnt
        colors.append(data[2]) # 每块颜色定义

    explode = np.zeros(len(datas),int).tolist()# 将某一块分割出来，值越大分割出的间隙越大
    explode[max_index]=0.02
    explode=tuple(explode)
    print("explode",explode)
    print("labels",labels)
    print("sizes",sizes)
    print("colors",colors)

    patches, text1, text2 = plt.pie(sizes,
                                    explode=explode,
                                    labels=labels,
                                    colors=colors,
                                    labeldistance=1.2,  # 图例距圆心半径倍距离
                                    autopct='%3.2f%%',  # 数值保留固定小数位
                                    shadow=False,  # 无阴影设置
                                    startangle=90,  # 逆时针起始角度设置
                                    pctdistance=0.6)  # 数值距圆心半径倍数距离
    # patches饼图的返回值，texts1饼图外label的文本，texts2饼图内部文本
    # x，y轴刻度设置一致，保证饼图为圆形

    plt.axis('equal')
    plt.legend()
    project_path = os.path.dirname(os.path.abspath(__file__))
    file_path=project_path+r'\png\%s_analysis.png'%(type)
    plt.savefig(file_path)
    plt.show()

    img= Image.open(file_path)
    photo = ImageTk.PhotoImage(img)
    windows = Toplevel()
    windows.title(title)
    imageLabel = Label(windows, image=photo)
    imageLabel.pack()
    windows.mainloop()

def draw_count_in_out_ip(in_packet_list,out_packet_list,in_time_flow_dict,out_time_flow_dict):
    '''
    1.饼状图统计ip与数据包数量的关系(只统计前10名的Ip)
    2.折线图统计ip与时间的关系
    :return:
    '''
    ordered_packet_list=collections.OrderedDict()
    tmp_v=list(in_packet_list.values())
    sorted_v =list(set(sorted(tmp_v,reverse=True)))
    count=0
    for v in sorted_v:
        keys=list(filter(lambda k :in_packet_list[k]==v,in_packet_list))
        for k in keys:
            if (count == 15):
                break
            ordered_packet_list[k]=in_packet_list[k]
            count+=1

    attr=ordered_packet_list.keys()
    vl=ordered_packet_list.values()
    data_pair=zip(attr,vl)
    pie_in=Pie()
    pie_in.add(
            "",
            data_pair,
            radius=["15%", "50%"],
            label_opts=opts.LabelOpts(formatter="{b}: {c} frames"),
        )
    #pie_in.set_series_opts(label_opts=opts.LabelOpts(is_show=True))
    pie_in.set_global_opts(title_opts=opts.TitleOpts(title="流入流量统计"))

    ordered_packet_list = collections.OrderedDict()
    tmp_v = list(out_packet_list.values())
    sorted_v = list(set(sorted(tmp_v, reverse=True)))
    count = 0
    for v in sorted_v:
        keys = list(filter(lambda k: out_packet_list[k] == v, out_packet_list))
        for k in keys:
            if (count == 15):
                break
            ordered_packet_list[k] = out_packet_list[k]
            count += 1

    attr = ordered_packet_list.keys()
    vl = ordered_packet_list.values()
    data_pair = zip(attr, vl)
    pie_out=Pie()
    pie_out.add(
        "",
        data_pair,
        radius=["15%", "50%"],
        label_opts=opts.LabelOpts(formatter="{b}: {c} frames"),
    )
    #pie_out.set_series_opts(label_opts=opts.LabelOpts(is_show=True))
    pie_out.set_global_opts(title_opts=opts.TitleOpts(title="流出流量统计"))
    line=Line()
    in_x=in_time_flow_dict.keys()
    in_y=[in_time_flow_dict[k] for k in in_time_flow_dict.keys()]
    out_y=[out_time_flow_dict[k] for k in out_time_flow_dict.keys()]
    line.add_xaxis(in_x)
    line.add_yaxis("流入流量",in_y,is_smooth=True,areastyle_opts=opts.AreaStyleOpts(opacity=0.5))
    line.add_yaxis("流出流量", out_y, is_smooth=True, areastyle_opts=opts.AreaStyleOpts(opacity=0.5))
    line.set_global_opts(
            title_opts=opts.TitleOpts(title="流量时间统计图"),
            xaxis_opts=opts.AxisOpts(
            axistick_opts=opts.AxisTickOpts(is_align_with_label=True),
            is_scale=False,
            boundary_gap=False,
            ))
    line.set_series_opts(areastyle_opts=opts.AreaStyleOpts(opacity=0.5),label_opts=opts.LabelOpts(is_show=False))
    page=Page(layout=Page.DraggablePageLayout)
    page.add(pie_in)
    page.add(pie_out)
    page.add(line)
    project_path = os.path.dirname(os.path.abspath(__file__))
    file_path = project_path + r"\html\ip_packet_statistic.html"
    page.render(file_path)
    driver = webdriver.Chrome()
    driver.get(r"C:\Users\esther\Desktop\sniffer\html\ip_packet_statistic.html")
    time.sleep(10)
    driver.quit()

def analysis_in_out_ip():
    '''
    流入与流出流量统计(包括数量、时间）
    :return:
    '''
    in_packet_list={}
    out_packet_list={}
    in_time_flow_dict=collections.OrderedDict()
    out_time_flow_dict=collections.OrderedDict()
    global packet_list
    host_ip=get_host_ip()
    time_list=[p.time for p in packet_list]
    start=min(time_list)
    end=max(time_list)
    print("start",start)
    print("end",end)
    #初始化字典的键值
    for i in range(0,int(float("%.1f"%(end-start))*10)+1):
        in_time_flow_dict[i / 10.0] = 0
        out_time_flow_dict[i / 10.0] = 0
    for pkt in packet_list:
        if(pkt.haslayer(IP)):
            time=pkt.time
            src = pkt[IP].src
            dst = pkt[IP].dst
            trange = time - start
            if(src==host_ip):
                if (dst in out_packet_list):
                    out_packet_list[dst] += len(corrupt_bytes(pkt))
                else:
                    out_packet_list[dst] = len(corrupt_bytes(pkt))
                if float('%.1f' % trange) in out_time_flow_dict.keys():
                    out_time_flow_dict[float('%.1f' % trange)
                    ] += len(corrupt_bytes(pkt))
                else:
                    out_time_flow_dict[float('%.1f' % trange)] = len(corrupt_bytes(pkt))
                for k in out_time_flow_dict.keys():
                    out_time_flow_dict[k] = float(
                        "%.1f" % (float(out_time_flow_dict[k]) / 1024.0))
            elif(dst==host_ip):
                if (src in in_packet_list):
                    in_packet_list[src] += len(corrupt_bytes(pkt))
                else:
                    in_packet_list[src] = len(corrupt_bytes(pkt))
                if float('%.1f' % trange) in in_time_flow_dict.keys():
                    in_time_flow_dict[float('%.1f' % trange)
                    ] += len(corrupt_bytes(pkt))
                else:
                    in_time_flow_dict[float('%.1f' % trange)] = len(
                        corrupt_bytes(pkt))
                for k in in_time_flow_dict.keys():
                    in_time_flow_dict[k] = float(
                        "%.1f" % (float(in_time_flow_dict[k]) / 1024.0))

    draw_count_in_out_ip(in_packet_list,out_packet_list,in_time_flow_dict,out_time_flow_dict)
    #return in_packet_list,out_packet_list,in_time_flow_dict,out_time_flow_dict

def queryIpAdr():
    '''
    查询IP所属的区域
    :return:
    '''
    reader = geoip2.database.Reader(r'geoip\GeoLite2-City.mmdb')
    global packet_list
    in_ip_addr={}
    out_ip_addr={}
    host_ip=get_host_ip()
    print("origin_host-public-ip", get_public_ip())
    if(get_public_ip()!=None):
        host_public_ip = bytes.decode(get_public_ip())
    else:
        host_public_ip='121.207.83.216'
    print("host-public-ip",host_public_ip)
    host_ip_info=None
    try:
        response = reader.city(host_public_ip)
        info = {}
        info['addr_en'] = response.continent.names["es"]
        info['addr_cn'] = response.continent.names["zh-CN"]
        info['contry'] = response.country.name
        info['contry_iso_code'] = response.country.iso_code
        info['province'] = response.subdivisions.most_specific.name
        info['city'] = response.city.name
        info['trapeze'] = (response.location.longitude,
                           response.location.latitude)
        info['time_zone'] = response.location.time_zone
        info['postal_code'] = response.postal.code
        host_ip_info = info
    except:
        print("解析地址失败")

    for pkt in packet_list:
        if(pkt.haslayer(IP)):
            src=pkt[IP].src
            dst=pkt[IP].dst
            if(src==host_ip):
                #流出流量归属统计
                try:
                    response = reader.city(dst)
                    info = {}
                    info['addr_en'] = response.continent.names["es"]
                    info['addr_cn'] = response.continent.names["zh-CN"]
                    info['contry'] = response.country.name
                    info['contry_iso_code'] = response.country.iso_code
                    info['province'] = response.subdivisions.most_specific.name
                    info['city'] = response.city.name
                    info['trapeze'] = (response.location.longitude,
                                       response.location.latitude)
                    info['time_zone'] = response.location.time_zone
                    info['postal_code'] = response.postal.code
                    if (dst not in out_ip_addr):
                        ip_addr_info = {}
                        ip_addr_info['info'] = info
                        ip_addr_info['count'] = 1
                        out_ip_addr[dst] = ip_addr_info
                    else:
                        out_ip_addr[dst]['count'] += 1
                except:
                    print("解析地址失败！")

            elif(dst==host_ip):
                #流入流量归属统计
                try:
                    response = reader.city(src)
                    info = {}
                    info['addr_en'] = response.continent.names["es"]
                    info['addr_cn'] = response.continent.names["zh-CN"]
                    info['contry'] = response.country.name
                    info['contry_iso_code'] = response.country.iso_code
                    info['province'] = response.subdivisions.most_specific.name
                    info['city'] = response.city.name
                    info['trapeze'] = (response.location.longitude,
                                       response.location.latitude)
                    info['time_zone'] = response.location.time_zone
                    info['postal_code'] = response.postal.code
                    if (src not in in_ip_addr):
                        ip_addr_info = {}
                        ip_addr_info['info'] = info
                        ip_addr_info['count'] = 1
                        in_ip_addr[src] = ip_addr_info
                    else:
                        in_ip_addr[src]['count'] += 1
                except:
                    print("解析地址失败！")

    #绘制地区热力图
    if(host_ip_info!=None):
        draw_addr_map(in_ip_addr, out_ip_addr, host_ip_info)
    else:
        print("无法解析host_ip_info")
    #show_addr_list(in_ip_addr,out_ip_addr)

def draw_addr_map(in_ip_addr,out_ip_addr,host_ip_info):
    '''
    :param out_addr_info:
    :param out_addr_info:
    :return:
    '''
    #保存流量所属地日志
    logger_addr(in_ip_addr, "in")
    logger_addr(out_ip_addr,"out")

    #进行地图绘制
    g=Geo()
    #g.add_schema(maptype="world")
    g.add_schema(maptype="world")
    host_ip=get_host_ip()
    g.add_coordinate(host_ip, host_ip_info['trapeze'][0], host_ip_info['trapeze'][1])
    g.add("", [(host_ip, 1)], type_=GeoType.EFFECT_SCATTER, symbol_size=5, color="red")
    edge_list=[]
    data_pair=[]
    for ip ,info in in_ip_addr.items():
        g.add_coordinate(ip,info['info']['trapeze'][0],info['info']['trapeze'][1])
        #print("ip",ip)
        #print("info",info)
        pair=(ip,info['count'])
        data_pair.append(pair)
        edge=(ip,host_ip)
        edge_list.append(edge)

    print("in_data_pair",data_pair)
    g.add("",data_pair,type_=GeoType.EFFECT_SCATTER,symbol_size=5,color="red")

    data_pair = []
    for ip, info in out_ip_addr.items():
        g.add_coordinate(ip, info['info']['trapeze'][0], info['info']['trapeze'][1])
        #print("ip", ip)
        #print("info", info)
        pair = (ip, info['count'])
        data_pair.append(pair)
        edge = (host_ip,ip)
        edge_list.append(edge)

    print("out_data_pair", data_pair)
    g.add("", data_pair, type_=GeoType.EFFECT_SCATTER, symbol_size=5,color="red")
    g.add(
            "",
            edge_list,
            type_=ChartType.LINES,
            effect_opts=opts.EffectOpts(
                symbol=SymbolType.ARROW, symbol_size=6, color="black"
            ),
            linestyle_opts=opts.LineStyleOpts(curve=0.2),
        )

    g.set_series_opts(label_opts=opts.LabelOpts(is_show=False))
    g.set_global_opts(title_opts=opts.TitleOpts(title='流量归属地理位置统计'))
    project_path = os.path.dirname(os.path.abspath(__file__))
    file_path=project_path+r"\html\query_address.html"
    g.render(file_path)
    #show_addr_list(in_ip_addr,out_ip_addr)
    driver=webdriver.Chrome()
    driver.get(r"C:\Users\esther\Desktop\sniffer\html\query_address.html")
    time.sleep(20)
    driver.quit()

def logger_addr(ip_addr_info,flag):
    project_path = os.path.dirname(os.path.abspath(__file__))
    file_path= project_path + r"\log\%s_ip_addr.txt"%(flag)
    finfos=[]

    for ip,info in ip_addr_info.items():
        # ("序号", "ip", "经纬度", "国家", "城市", "数量")
        finfo = collections.OrderedDict()
        finfo['ip'] = ip
        finfo['trapeze'] = info['info']['trapeze']
        finfo['contry'] = info['info']['contry']
        finfo['city'] = info['info']['city']
        finfo['count']=info['count']
        finfos.append(finfo)

    ordered_finfos=[]
    tmp_v = [ f['count'] for f in finfos]
    sorted_v = list(set(sorted(tmp_v)))
    cnt=1
    for v in sorted_v:
        for index,f in enumerate(finfos):
            if(f['count']==v):
                new_info=collections.OrderedDict()
                new_info['index']=str(cnt)
                for key,value in f.items():
                    new_info[key]=str(value)
                ordered_finfos.append(new_info)
                cnt+=1
    log_format(file_path,ordered_finfos)
    return ordered_finfos

def show_addr_list(in_ip_addr,out_ip_addr):
    '''
    显示并保存进出入流量地址归属的日志
    :param in_ip_addr:
    :param out_ip_addr:
    :return:
    '''
    addr_tk = tkinter.Toplevel()
    addr_tk.title("流出/流入流量IP地址归属")
    main_window = PanedWindow(tk, sashrelief=RAISED, sashwidth=5, orient=HORIZONTAL)
    in_addr_info_frame=Frame()
    in_addr_sub_frame=Frame(in_addr_info_frame)
    in_addr_list_tree= Treeview(in_addr_sub_frame, selectmode='browse')
    in_addr_list_tree.bind('<<TreeviewSelect>>')
    # 数据包列表垂直滚动条
    in_addr_list_vscrollbar = Scrollbar(in_addr_sub_frame, orient="vertical", command=in_addr_list_tree.yview)
    in_addr_list_vscrollbar.pack(side=RIGHT, fill=Y, expand=YES)
    in_addr_list_tree.configure(yscrollcommand=in_addr_list_vscrollbar.set)
    in_addr_sub_frame.pack(side=TOP, fill=BOTH, expand=YES)
    # 数据包列表水平滚动条
    in_addr_list_hscrollbar = Scrollbar(packet_list_frame, orient="horizontal", command=in_addr_list_tree.xview)
    in_addr_list_hscrollbar.pack(side=BOTTOM, fill=X, expand=YES)
    in_addr_list_tree.configure(xscrollcommand=in_addr_list_hscrollbar.set)
    # 数据包列表区列标题
    in_addr_list_tree["columns"] = ("序号", "ip", "经纬度", "国家", "城市", "时间")
    in_addr_list_column_width = [100, 180, 160, 100, 100, 100, 160]
    in_addr_list_tree['show'] = 'headings'
    for column_name, column_width in zip(in_addr_list_tree["columns"], in_addr_list_column_width):
        in_addr_list_tree.column(column_name, width=column_width, anchor='w')
        in_addr_list_tree.heading(column_name, text=column_name)
    in_addr_list_tree.pack(side=LEFT, fill=X, expand=YES)
    in_addr_info_frame.pack(side=TOP, fill=Y, padx=5, pady=5, expand=YES, anchor='n')
    # 将数据包列表区加入到主窗体
    main_window.add(in_addr_info_frame)

    out_addr_info_frame = Frame()
    out_addr_sub_frame = Frame(out_addr_info_frame)
    out_addr_list_tree = Treeview(out_addr_sub_frame, selectmode='browse')
    out_addr_list_tree.bind('<<TreeviewSelect>>')
    # 数据包列表垂直滚动条
    out_addr_list_vscrollbar = Scrollbar(out_addr_sub_frame, orient="vertical", command=out_addr_list_tree.yview)
    out_addr_list_vscrollbar.pack(side=RIGHT, fill=Y, expand=YES)
    out_addr_list_tree.configure(yscrollcommand=out_addr_list_vscrollbar.set)
    out_addr_sub_frame.pack(side=TOP, fill=BOTH, expand=YES)
    # 数据包列表水平滚动条
    out_addr_list_hscrollbar = Scrollbar(packet_list_frame, orient="horizontal", command=out_addr_list_tree.xview)
    out_addr_list_hscrollbar.pack(side=BOTTOM, fill=X, expand=YES)
    out_addr_list_tree.configure(xscrollcommand=out_addr_list_hscrollbar.set)
    # 数据包列表区列标题
    out_addr_list_tree["columns"] = ("序号", "ip", "经纬度", "国家", "城市", "时间")
    out_addr_list_column_width = [100, 180, 160, 100, 100, 100, 160]
    out_addr_list_tree['show'] = 'headings'
    for column_name, column_width in zip(out_addr_list_tree["columns"], out_addr_list_column_width):
        out_addr_list_tree.column(column_name, width=column_width, anchor='w')
        out_addr_list_tree.heading(column_name, text=column_name)
    out_addr_list_tree.pack(side=LEFT, fill=X, expand=YES)
    out_addr_info_frame.pack(side=TOP, fill=Y, padx=5, pady=5, expand=YES, anchor='n')
    # 将数据包列表区加入到主窗体
    main_window.add(out_addr_info_frame)
    main_window.pack(fill=BOTH,expand=1)

    # 流入/流出流量日志保存
    ordered_finfos=logger_addr(in_ip_addr, "in")
    for index,item in enumerate(ordered_finfos):

        in_addr_list_tree.insert("", 'end', index, text=index,
                                 values=item.values())
        in_addr_list_tree.update_idletasks()  # 更新列表，不需要修改
    ordered_finfos=logger_addr(out_ip_addr, "out")

    for index, item in enumerate(ordered_finfos):
        out_addr_list_tree.insert("", 'end', index, text=index,
                                 values=item.values())
        out_addr_list_tree.update_idletasks()  # 更新列表，不需要修改
    addr_tk.mainloop()


##===========事件响应函数===========##
def select_nic(event):
    print("select nic:", select_nic_combo.get())

def on_click_packet(event):
    '''
    数据包列表单击事件响应函数
    1.在协议解析区对数据包进行解析
    2.在hexdump区显示此数据包的十六进制的内容
    :return:
    '''
    global packet_list

    packet_dissect_tree.delete(*packet_dissect_tree.get_children())
    packet_dissect_tree.column('Dissect', width=packet_list_frame.winfo_width())
    item = event.widget.selection()
    index=int(item[0])-1
    packet=packet_list[index]

    infos=(packet.show(dump=True)).split("\n")
    print("packet_info",infos)
    for info in infos:
        if(info.startswith('#')):
            info=info.strip('# ')
            parent=packet_dissect_tree.insert('', 'end', text=info)
        else:
            packet_dissect_tree.insert(parent,'end',text=info)
        col_width = font.Font().measure(info)
        # 根据新插入数据项的长度动态调整协议解析区的宽度
        if packet_dissect_tree.column('Dissect', width=None) < col_width:
            packet_dissect_tree.column('Dissect', width=col_width)
    #增加对http的处理
    if packet.haslayer(http.HTTPRequest):
        parent = packet_dissect_tree.insert('', 'end', text='[ HTTP ]')
        print("*********request******")
        http_name = 'HTTP Request'
        http_header = packet[http.HTTPRequest].fields
        for header ,info in http_header.items():
            text= header +' = '+info
            packet_dissect_tree.insert(parent, 'end', text=text)
            col_width = font.Font().measure(info)
            # 根据新插入数据项的长度动态调整协议解析区的宽度
            if packet_dissect_tree.column('Dissect', width=None) < col_width:
                packet_dissect_tree.column('Dissect', width=col_width)

    elif packet.haslayer(http.HTTPResponse):
        parent = packet_dissect_tree.insert('', 'end', text='[ HTTP ]')
        print("*********response******")
        http_name = 'HTTP Response'
        http_header = packet[http.HTTPResponse].fields
        for header, info in http_header.items():
            text = header + ' = ' + info
            packet_dissect_tree.insert(parent, 'end', text=text)
            col_width = font.Font().measure(info)
            # 根据新插入数据项的长度动态调整协议解析区的宽度
            if packet_dissect_tree.column('Dissect', width=None) < col_width:
                packet_dissect_tree.column('Dissect', width=col_width)

    #在hexdump区显示此数据包的16进制的内容
    hexdump_scrolledtext['state'] = 'normal'
    hexdump_scrolledtext.delete(1.0, END)
    hexdump_scrolledtext.insert(END, hexdump(packet, dump=True))
    hexdump_scrolledtext['state'] = 'disabled'


def save():
    '''
    将获取得到的文件进行保存
    :return:
    '''
    global save_flag
    filename = tkinter.filedialog.asksaveasfilename(title='保存文件', filetypes=[('所有文件', '.*'),
                                                                             ('数据包', '.pcap')], initialfile='.pcap')
    if filename.find('.pcap') == -1:
        # 默认文件格式为 pcap
        filename = filename + '.pcap'

    wrpcap(filename, packet_list)
    if(len(filename)>5):
        print("已保存当前文件")
        # 设置标志位
        save_flag = True

def start():
    """
    开新线程，进行抓包
    :return:
    """
    # 暂停，停止，保存的标志位
    global stop_flag,save_flag,start_flag

    # 设置开始按钮为不可用，暂停按钮可操作
    select_nic_combo['state'] = 'disabled'
    filter_button['state'] = 'disabled'
    stop_button['state'] = 'normal'
    start_button['state'] = 'disabled'
    analysis_button['state']='disabled'
    select_analysis_combo['state']='disabled'


    stop_sending.clear()
    # 开启新线程进行抓包
    t = threading.Thread(target=capture_packet)
    t.setDaemon(True)
    t.start()
    stop_flag = False
    save_flag = False
    start_flag = True

def stop(event):
    """
    终止线程，停止抓包
    :return:
    """
    # 终止线程，停止抓包
    stop_sending.set()
    # 设置开始按钮为可用，暂停按钮为不可用,保存为可用
    select_nic_combo['state'] = 'readonly'
    filter_button['state'] = 'normal'
    stop_button['state'] = 'disabled'
    start_button['state'] = 'normal'
    clear_button['state'] = 'normal'
    save_button['state'] = 'normal'
    analysis_button['state'] = 'normal'
    select_analysis_combo['state']='normal'

    filter_entry['state'] = 'normal'
    global stop_flag, save_flag
    stop_flag = True
    save_flag = False
    # 不能用加号+，连接不同格式字符
    print("停止抓包,共抓到", packet_id, "个数据包")

def quit():
    '''
    退出程序
    :return:
    '''
    global stop_sending
    if (stop_flag is True) :
        if (save_flag is False):
            result= tkinter.messagebox.askyesnocancel("保存提醒", "是否保存抓到的数据包")
            if(result is False):
                print("直接退出不保存")
                tk.destroy()
            elif(result is True):
                print("先保存数据包，再退出")
                filename = tkinter.filedialog.asksaveasfilename(title='保存文件',filetypes=[('所有文件', '.*'), ('数据包', '.pcap')],initialfile='.pcap')
                if filename.find('.pcap') == -1:
                    # 默认文件格式为 pcap
                    filename = filename + '.pcap'
                wrpcap(filename, packet_list)
                tk.destroy()
            else:
                print("取消退出")
        else:
            print("已经保存，直接退出")
            tk.destroy()
    else:
        if(start_flag==True):
            result = tkinter.messagebox.askyesnocancel("警告", "程序仍在运行，是否退出程序？")
            # 程序仍在运行，直接退出程序
            if (result is True):
                # 终止抓包的线程
                stop_sending.set()
                if (save_flag is False):
                    result = tkinter.messagebox.askyesnocancel("保存提醒", "是否保存抓到的数据包")
                    if (result is False):
                        print("直接退出不保存")
                        tk.destroy()
                    elif (result is True):
                        print("先保存数据包，再退出")
                        filename = tkinter.filedialog.asksaveasfilename(title='保存文件',
                                                                        filetypes=[('所有文件', '.*'), ('数据包', '.pcap')],
                                                                        initialfile='.pcap')
                        if filename.find('.pcap') == -1:
                            # 默认文件格式为 pcap
                            filename = filename + '.pcap'
                        wrpcap(filename, packet_list)
                        tk.destroy()
                    else:
                        print("取消退出")
                else:
                    print("已经保存，直接退出")
                    tk.destroy()
            # 不退出程序
            else:
                print("取消退出")
        else:
            print("直接退出程序！")
            tk.destroy()

def clear_data():
    global packet_id,packet_list
    ether_info.clear()
    ip_info.clear()
    tcp_info.clear()
    packet_list.clear()
    packet_id = 1

def clear():
    '''
    清空列表中的数据
    :return:
    '''
    analysis_button['state'] = 'disabled'
    select_analysis_combo['state'] = 'disabled'
    # 判断是否需要进行保存
    global save_flag
    if (save_flag is False):
        result = tkinter.messagebox.askyesnocancel("保存提醒", "是否保存抓到的数据包")
        if (result is False):
            print("直接清空不保存")
            clear_data()
            # 清空已经抓到的数据包列表
            items = packet_list_tree.get_children()
            for item in items:
                packet_list_tree.delete(item)
            packet_list_tree.clipboard_clear()
            clear_button['state'] = 'disabled'

        elif (result is True):
            print("先保存数据包，再清空")
            filename = tkinter.filedialog.asksaveasfilename(title='保存文件', filetypes=[('所有文件', '.*'), ('数据包', '.pcap')],
                                                            initialfile='.pcap')
            if filename.find('.pcap') == -1:
                # 默认文件格式为 pcap
                filename = filename + '.pcap'
            wrpcap(filename, packet_list)
            if(len(filename)>5):
                save_flag = True
                clear_data()
                # 清空已经抓到的数据包列表
                items = packet_list_tree.get_children()
                for item in items:
                    packet_list_tree.delete(item)
                packet_list_tree.clipboard_clear()
                clear_button['state'] = 'disabled'
            else:
                print("取消清空")

        else:
            print("取消清空")
    else:
        print("已经保存，直接清空")
        # 进行清空操作
        clear_data()
        # 清空已经抓到的数据包列表
        items = packet_list_tree.get_children()
        for item in items:
            packet_list_tree.delete(item)
        packet_list_tree.clipboard_clear()

        clear_button['state'] = 'disabled'

def filter_packet():
    # 设置过滤后需要更新过滤的值
    filter_flag = True

    # 根据用户输入生成BPF过滤规则
    protocal= protocal_combo.get()
    src_adr=src_adr_entry.get()
    src_port=src_port_entry.get()
    dst_adr=dst_adr_entry.get()
    dst_port=dst_port_entry.get()
    #print(len(protocal),len(src_adr),len(src_port),len(dst_adr),len(dst_port))
    # 抓包前过滤
    filter_rule = " "
    # TODO 需要判断设定的规则是否正确
    if (protocal != "ALL"):
        filter_rule += protocal + ' '
    if (src_adr.strip() != ''):
        filter_rule += 'src ' + src_adr + ' '
    if (src_port.strip() != ""):
        filter_rule += 'port ' + src_port + ' '
    if (dst_adr.strip() != ""):
        filter_rule += 'dst ' + dst_adr + ' '
    if (dst_port.strip() != ""):
        filter_rule += 'port ' + dst_port
    print("filter_rule", filter_rule)
    filter_entry.delete(0, END)
    filter_entry.insert(0, filter_rule)

def analysis():
    
    types=['ether','ip','transport']
    title=select_analysis_combo.get()
    index=select_analysis_combo.current()
    if(index==0):
        analysis_plot(ether_info, types[index])
    elif(index==1):
        analysis_plot(ip_info, types[index])
    elif(index==2):
        analysis_plot(tcp_info, types[index])
    elif(index==3):
        #request请求分析
        get_request_url()
    elif(index==4):
        #地域分析
        queryIpAdr()
    elif(index==5):
        #流量时间分析
        analysis_in_out_ip()

##===========绘制界面===========##

# 状态栏类
class StatusBar(Frame):
    def __init__(self, master):
        Frame.__init__(self, master)
        self.label = Label(self, bd=1, relief=SUNKEN, anchor=W)
        self.label.pack(fill=X)
    def set(self, fmt, *args):
        self.label.config(text=fmt % args)
        self.label.update_idletasks()
    def clear(self):
        self.label.config(text="")
        self.label.update_idletasks()
tk = tkinter.Tk()
tk.title("Sniffer")
# tk.resizable(0, 0)
# 带水平分割条的主窗体
main_panedwindow = PanedWindow(tk, sashrelief=RAISED, sashwidth=5, orient=VERTICAL)

# 顶部的按钮及过滤器区
toolbar = Frame(tk)
select_nic_label=Label(toolbar,width=10,text="选择网卡")
select_nic_combo=ttk.Combobox(toolbar,width=50,values=getNIC(), state="readonly")
select_nic_combo.current(0)
select_nic_combo.bind("<<ComboboxSelected>>",select_nic)
start_button = Button(toolbar, width=8, text="开始", command=start)
#pause_button = Button(toolbar, width=8, text="暂停", command=pause_capture)
stop_button = Button(toolbar, width=8, text="停止")
stop_button.bind("<Button-1>",stop)
clear_button = Button(toolbar, width=8, text="清空数据", command=clear)
save_button = Button(toolbar, width=8, text="保存数据", command=save)

analysis_button = Button(toolbar,width=8,text="流量分析",command=analysis)
select_analysis_combo=ttk.Combobox(toolbar,width=35,values=titles, state="readonly")
select_analysis_combo['state']='disabled'
select_analysis_combo.current(0)
quit_button = Button(toolbar, width=8, text="退出", command=quit)

start_button['state'] = 'normal'
#pause_button['state'] = 'disabled'
#stop_button['state'] = 'disabled'
clear_button['state']='disabled'
save_button['state'] = 'disabled'
analysis_button['state']='disabled'
quit_button['state'] = 'normal'

select_nic_label.pack(side=LEFT,padx=10,pady=10)
select_nic_combo.pack(side=LEFT,after=select_nic_label,pady=10)
start_button.pack(side=LEFT, after=select_nic_combo,padx=10,pady=10)
#pause_button.pack(side=LEFT, after=start_button, padx=10, pady=10)
stop_button.pack(side=LEFT, after=start_button, padx=10, pady=10)
clear_button.pack(side=LEFT, after=stop_button, padx=10, pady=10)
save_button.pack(side=LEFT, after=clear_button, padx=10, pady=10)
analysis_button.pack(side=LEFT, after=save_button, padx=10, pady=10)
select_analysis_combo.pack(side=LEFT, after=analysis_button, padx=10, pady=10)
quit_button.pack(side=LEFT, after=select_analysis_combo, padx=10, pady=10)

toolbar.pack(side=TOP, fill=X)


# 数据包过滤区
filter_frame = Frame()
protocal_label = Label(filter_frame, width=10, text="协议类型：")
protocal_combo=ttk.Combobox(filter_frame,width=15,values=protocal_choose_list)
#protocal_combo.current(1)
src_adr_label = Label(filter_frame, width=10, text="源地址：")
src_adr_entry = Entry(filter_frame)
src_post_label = Label(filter_frame, width=10, text="源端口：")
src_port_entry = Entry(filter_frame)
dst_adr_label = Label(filter_frame, width=10, text="目的地址：")
dst_adr_entry = Entry(filter_frame)
dst_port_label = Label(filter_frame, width=10, text="目的端口：")
dst_port_entry = Entry(filter_frame)
filter_button= Button(filter_frame, width=8, text="设置过滤", command=filter_packet)


protocal_label.pack(side=LEFT,padx=10,pady=10)
protocal_combo.pack(side=LEFT,after=protocal_label,pady=10)
src_adr_label.pack(side=LEFT,after=protocal_combo,pady=10)
src_adr_entry.pack(side=LEFT,after=src_adr_label,pady=10)
src_post_label.pack(side=LEFT,after=src_adr_entry,pady=10)
src_port_entry.pack(side=LEFT,after=src_post_label,pady=10)
dst_adr_label.pack(side=LEFT,after=src_port_entry,pady=10)
dst_adr_entry.pack (side=LEFT,after=dst_adr_label,pady=10)
dst_port_label.pack(side=LEFT,after=dst_adr_entry,pady=10)
dst_port_entry.pack(side=LEFT,after=dst_port_label,pady=10)
filter_button.pack(side=LEFT,after=dst_port_entry,padx=10,pady=10)

#main_panedwindow.add(filter_frame)

#过滤规则显示区域
filter_rule_frame = Frame()
filter_label = Label(filter_rule_frame, width=10, text="BPF过滤规则：")
filter_entry = Entry(filter_rule_frame)
filter_label.pack(side=LEFT,padx=20, pady=10)
filter_entry.pack(side=LEFT, after=filter_label, padx=20, pady=10, fill=X, expand=YES)
main_panedwindow.add(filter_rule_frame)

# 数据包列表区
packet_list_frame = Frame()
packet_list_sub_frame = Frame(packet_list_frame)
packet_list_tree = Treeview(packet_list_sub_frame, selectmode='browse')
packet_list_tree.bind('<<TreeviewSelect>>', on_click_packet)
# 数据包列表垂直滚动条
packet_list_vscrollbar = Scrollbar(packet_list_sub_frame, orient="vertical", command=packet_list_tree.yview)
packet_list_vscrollbar.pack(side=RIGHT, fill=Y, expand=YES)
packet_list_tree.configure(yscrollcommand=packet_list_vscrollbar.set)
packet_list_sub_frame.pack(side=TOP, fill=BOTH, expand=YES)
# 数据包列表水平滚动条
packet_list_hscrollbar = Scrollbar(packet_list_frame, orient="horizontal", command=packet_list_tree.xview)
packet_list_hscrollbar.pack(side=BOTTOM, fill=X, expand=YES)
packet_list_tree.configure(xscrollcommand=packet_list_hscrollbar.set)
# 数据包列表区列标题
packet_list_tree["columns"] = ("序号", "时间", "源地址", "目的地址", "协议", "长度", "信息")
packet_list_column_width = [100, 180, 160, 160, 100, 100, 800]
packet_list_tree['show'] = 'headings'
for column_name, column_width in zip(packet_list_tree["columns"], packet_list_column_width):
    packet_list_tree.column(column_name, width=column_width, anchor='w')
    packet_list_tree.heading(column_name, text=column_name)
packet_list_tree.pack(side=LEFT, fill=X, expand=YES)
packet_list_frame.pack(side=TOP, fill=X, padx=5, pady=5, expand=YES, anchor='n')
# 将数据包列表区加入到主窗体
main_panedwindow.add(packet_list_frame)

# 协议解析区
packet_dissect_frame = Frame()
packet_dissect_sub_frame = Frame(packet_dissect_frame)
packet_dissect_tree = Treeview(packet_dissect_sub_frame, selectmode='browse')
packet_dissect_tree["columns"] = ("Dissect",)
packet_dissect_tree.column('Dissect', anchor='w')
packet_dissect_tree.heading('#0', text='Packet Dissection', anchor='w')
packet_dissect_tree.pack(side=LEFT, fill=BOTH, expand=YES)
# 协议解析区垂直滚动条
packet_dissect_vscrollbar = Scrollbar(packet_dissect_sub_frame, orient="vertical", command=packet_dissect_tree.yview)
packet_dissect_vscrollbar.pack(side=RIGHT, fill=Y)
packet_dissect_tree.configure(yscrollcommand=packet_dissect_vscrollbar.set)
packet_dissect_sub_frame.pack(side=TOP, fill=X, expand=YES)
# 协议解析区水平滚动条
packet_dissect_hscrollbar = Scrollbar(packet_dissect_frame, orient="horizontal", command=packet_dissect_tree.xview)
packet_dissect_hscrollbar.pack(side=BOTTOM, fill=X)
packet_dissect_tree.configure(xscrollcommand=packet_dissect_hscrollbar.set)
packet_dissect_frame.pack(side=LEFT, fill=X, padx=5, pady=5, expand=YES)
# 将协议解析区加入到主窗体
main_panedwindow.add(packet_dissect_frame)

# hexdump区
hexdump_scrolledtext = ScrolledText(height=10)
hexdump_scrolledtext['state'] = 'disabled'
# 将hexdump区区加入到主窗体
main_panedwindow.add(hexdump_scrolledtext)

main_panedwindow.pack(fill=BOTH, expand=1)

# 状态栏
status_bar = StatusBar(tk)
status_bar.pack(side=BOTTOM, fill=X)
#just_a_test()  # 展示一个数据包，不是抓来的
project_path = os.path.dirname(os.path.abspath(__file__))
file_path=project_path+r'\icon\networking_32px_1208137_easyicon.net.ico'
tk.iconbitmap(file_path)
tk.mainloop()
