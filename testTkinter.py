# coding=utf-8
import datetime
import threading
import sys
import os
import re
import tkinter
import psutil
from tkinter import *
from tkinter import ttk
from tkinter import font, filedialog
from tkinter.constants import *
from tkinter.messagebox import askyesno
from tkinter.scrolledtext import ScrolledText
from tkinter.ttk import Treeview
from scapy.all import *
from scapy.layers.inet import *
from scapy.layers.l2 import *
protocal_choose_list = ['ALL', 'ether', 'ip', 'ip6', 'arp', 'decnet', 'tcp', 'udp', 'tcp or udp', 'icmp']

#用于终止抓包线程的事件
stop_sending = threading.Event()

#数据包的Id
packet_num=1
#数据包列表
packet_list=[]
#一些标志位
start_flag=False
stop_flag=False
save_flag=False
filter_flag=False
#本机的网卡列表
NIC_list=[]
# 过滤规则
filter_rule=""

#=============一些跟工具相关的类==============#

def getNIC():
    '''
    获取本机的网卡信息
    :return:
    '''
    global NIC_list
    NIC_list.append("ALL") #加入所有的选项
    ##### 输出重定向
    output=sys.stdout
    outputfile=open("tmp.txt","w")
    sys.stdout=outputfile
    show_interfaces()
    outputfile.close()
    sys.stdout = output
    ##### 对输出进行解析，获得网卡列表
    with open("tmp.txt","r") as file:
        header=file.readline()
        iface_index = header.index("IFACE")
        ip_index=header.index("IP")
        #print("index",iface_index,ip_index)

        lines=file.readlines()
        for line in lines:
            line = line[iface_index:ip_index]
            if line.startswith("["):
                continue
            line=line.strip()
            #print(line)
            NIC_list.append(line)
    os.remove("tmp.txt")
    return NIC_list

# 处理抓到的数据包
def process_packet(packet):
    global packet_list
    # 将抓到的包存在列表中
    packet_list.append(packet)
    # 抓包的时间
    time_array = time.localtime(packet.time)
    packet_time = time.strftime("%Y-%m-%d %H:%M:%S", time_array)
    src = packet[Ether].src
    dst = packet[Ether].dst
    type = packet[Ether].type
    types = {0x0800: 'IPv4', 0x0806: 'ARP', 0x86dd: 'IPv6', 0x88cc: 'LLDP', 0x891D: 'TTE'}
    if type in types:
        proto = types[type]
    else:
        proto = 'LOOP'  # 协议
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
    # tcp
    if TCP in packet:
        protos_tcp = {80: 'Http', 443: 'Https', 23: 'Telnet', 21: 'Ftp', 20: 'ftp_data', 22: 'SSH', 25: 'SMTP'}
        sport = packet[TCP].sport
        dport = packet[TCP].dport
        if sport in protos_tcp:
            proto = protos_tcp[sport]
        elif dport in protos_tcp:
            proto = protos_tcp[dport]
    elif UDP in packet:
        if packet[UDP].sport == 53 or packet[UDP].dport == 53:
            proto = 'DNS'
    length = len(packet)  # 长度
    info = packet.summary()  # 信息
    global packet_num  # 数据包的编号
    packet_list_tree.insert("", 'end', packet_num, text=packet_num,
                            values=(packet_num, packet_time, src, dst, proto, length, info))
    packet_list_tree.update_idletasks()  # 更新列表，不需要修改
    packet_num = packet_num + 1
    
        

def capture_packet():
    '''
    抓取数据包并进行处理
    :return:
    '''
    # step1 设置过滤条件（在抓包前进行过滤），每次抓包前都需要判断是否设置了过滤条件
    nic = select_nic_combo.get()  # 选取的网卡

    global filter_rule,stop_sending
    filter_rule=fitler_entry.get()

    # step2 设置停止抓包的条件
    if (nic != "ALL"):
        sniff(count=20,iface=nic, prn=(lambda x: process_packet(x)), filter=filter_rule,
              stop_filter=(lambda x: stop_sending.is_set()))
    else:
        sniff(count=20,prn=(lambda x: process_packet(x)), filter=filter_rule,
              stop_filter=(lambda x: stop_sending.is_set()))

def select_nic(event):
    print("select nic:",select_nic_combo.get())

def start_capture():
    global stop_sending
    # step 1 更改一些交互的按钮的状态
    select_nic_combo['state']='disabled'
    filter_button['state']='disabled'
    stop_button['state']='normal'
    start_button['state']='disabled'
    # step 2 设置一些标志位
    global stop_flag,save_flag
    stop_flag=False
    save_flag=False
    start_flag=True
    # step 3 启动抓包线程
    stop_sending.clear()
    capture_thread = threading.Thread(target=capture_packet())
    capture_thread.setDaemon(True)
    capture_thread.start()


def stop_capture(event):
    global stop_sending
    # step 1 终止线程，停止抓包
    stop_sending.set()
    print("press stop button")

    # step 2 设置一些标志位
    global stop_flag, save_flag
    stop_flag=True
    save_flag=False
    print("停止抓包，一共抓到",packet_num,"个数据包")

    # step 2 更改一些交互按钮的状态
    select_nic_combo['state'] = 'readonly'
    filter_button['state'] = 'normal'
    stop_button['state'] = 'disabled'
    start_button['state'] = 'normal'
    clear_button['state'] = 'normal'
    save_button['state'] = 'normal'
    analysis_button['state'] = 'normal'

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



def clear():
    '''
    清空列表中的数据
    :return:
    '''
    # 判断是否需要进行保存
    global save_flag,packet_list,packet_num
    if (save_flag is False):
        result = tkinter.messagebox.askyesnocancel("保存提醒", "是否保存抓到的数据包")
        if (result is False):
            print("直接清空不保存")
            packet_list.clear()
            # 清空已经抓到的数据包列表
            items = packet_list_tree.get_children()
            for item in items:
                packet_list_tree.delete(item)
            packet_list_tree.clipboard_clear()
            global packet_num
            packet_num = 1
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
                packet_list.clear()
                # 清空已经抓到的数据包列表
                items = packet_list_tree.get_children()
                for item in items:
                    packet_list_tree.delete(item)
                packet_list_tree.clipboard_clear()

                packet_num = 1
                clear_button['state'] = 'disabled'
            else:
                print("取消清空")

        else:
            print("取消清空")
    else:
        print("已经保存，直接清空")
        # 进行清空操作
        packet_list.clear()
        # 清空已经抓到的数据包列表
        items = packet_list_tree.get_children()
        for item in items:
            packet_list_tree.delete(item)
        packet_list_tree.clipboard_clear()
        packet_num = 1
        clear_button['state'] = 'disabled'


def on_click_packet(event):
    '''
    数据包列表单击事件响应函数
    1.在协议解析区对数据包进行解析
    2.在hexdump区显示此数据包的十六进制的内容
    :return:
    '''
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

    #在hexdump区显示此数据包的16进制的内容
    hexdump_scrolledtext['state'] = 'normal'
    hexdump_scrolledtext.delete(1.0, END)
    hexdump_scrolledtext.insert(END, hexdump(packet, dump=True))
    hexdump_scrolledtext['state'] = 'disabled'


def analysis():
    # TODO 对抓取得到的数据包进行分析（域名统计，流量分析)
    pass


def filter_packet():
    # 设置过滤后需要更新过滤的值
    filter_flag = True

    # 根据用户输入生成BPF过滤规则
    protocal= protocal_combo.get()
    src_adr=src_adr_entry.get()
    src_port=src_port_entry.get()
    dst_adr=dst_adr_entry.get()
    dst_port=dst_port_entry.get()
    print(len(protocal),len(src_adr),len(src_port),len(dst_adr),len(dst_port))
    # 抓包前过滤
    filter_rule = " "
    # TODO 需要判断设定的规则是否正确？
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
    fitler_entry.delete(0, END)
    fitler_entry.insert(0, filter_rule)



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

#=================GUI绘制=================#

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
start_button = Button(toolbar, width=8, text="开始", command=start_capture)
#pause_button = Button(toolbar, width=8, text="暂停", command=pause_capture)
stop_button = Button(toolbar, width=8, text="停止")
stop_button.bind("<Button-1>",stop_capture)
clear_button = Button(toolbar, width=8, text="清空数据", command=clear)
save_button = Button(toolbar, width=8, text="保存数据", command=save)
quit_button = Button(toolbar, width=8, text="退出", command=quit)
analysis_button = Button(toolbar,width=8,text="流量分析",command=analysis)

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
quit_button.pack(side=LEFT, after=analysis_button, padx=10, pady=10)

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

main_panedwindow.add(filter_frame)

#过滤规则显示区域
filter_rule_frame = Frame()
filter_label = Label(filter_rule_frame, width=10, text="BPF过滤规则：")
fitler_entry = Entry(filter_rule_frame)
filter_label.pack(side=LEFT,padx=20, pady=10)
fitler_entry.pack(side=LEFT, after=filter_label, padx=20, pady=10, fill=X, expand=YES)
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
tk.iconbitmap('networking_32px_1208137_easyicon.net.ico')
tk.mainloop()



