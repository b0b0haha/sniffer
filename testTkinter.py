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
# 协议选项列表
protocal_choose_list=['ether','ip','ip6','arp','decnet','tcp','udp','tcp or udp','icmp']

#用于终止抓包线程的事件
stop_event = threading.Event()

#数据包的Id
packet_id=1
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
            line = line[7:55]
            if line.startswith("["):
                continue
            line=line.strip()
            #print(line)
            NIC_list.append(line)
    os.remove("tmp.txt")
    return NIC_list

def timestamp2time(timestamp):
    '''
    时间格式的转换
    :param timestamp:
    :return:
    '''
    tmp_time= time.localtime(timestamp)
    mytime= time.strftime("%Y-%m-%d %H:%M:%S",tmp_time)
    return mytime

def select_nic(event):
    print("select nic:",select_nic_combo.get())

def process_packet(packet):
    pass

def capture_packet():
    '''
    抓取数据包并进行处理
    :return:
    '''
    # step1 设置过滤条件（在抓包前进行过滤），每次抓包前都需要判断是否设置了过滤条件
    nic = select_nic_combo.get()  # 选取的网卡
    global filter_rule

    # step2 设置停止抓包的条件
    stop_event.clear()
    sniff(iface=nic, prn=(lambda x: process_packet(x)), filter=filter_rule,
          stop_filter=(lambda x: stop_event.is_set()))


def start_capture():
    # step 1 更改一些交互的按钮的状态
    select_nic_combo['state']='disabled'
    filter_button['state']='disabled'
    stop_button['state']='normal'
    start_button['state']='disabled'
    # step 2 设置一些标志位
    global stop_flag,save_flag
    stop_flag=False
    save_flag=False


def stop_capture():
    # step 1 更改一些交互按钮的状态
    select_nic_combo['state'] = 'readonly'
    filter_button['state'] = 'normal'
    stop_button['state'] = 'disabled'
    start_button['state'] = 'normal'
    clear_button['state']='normal'
    save_button['state']='normal'
    analysis_button['state']='normal'

    # step 2 设置一些标志位
    global stop_flag, save_flag
    stop_flag=True
    save_flag=False
    # step 3 终止线程，停止抓包
    stop_event.set()
    print("停止抓包，一共抓到",packet_id,"个数据包")

def save_captured_data_to_file():
    '''
    将获取得到的文件进行保存
    :return:
    '''

    filename = tkinter.filedialog.asksaveasfilename(title='保存文件', filetypes=[('所有文件', '.*'),
                                                                             ('数据包', '.pcap')], initialfile='.pcap')
    if filename.find('.pcap') == -1:
        # 默认文件格式为 pcap
        filename = filename + '.pcap'

    wrpcap(filename, packet_list)
    if(len(filename)>5):
        print("已保存当前文件")
        # 设置标志位
        global save_flag
        save_flag = True


def quit_program():
    '''
    退出程序
    :return:
    '''
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
        result = tkinter.messagebox.askyesnocancel("警告", "程序仍在运行，是否退出程序？")
        # 程序仍在运行，直接退出程序
        if(result is True):
            # 终止抓包的线程
            stop_event.set()
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

def clear_data():
    '''
    清空列表中的数据
    :return:
    '''
    # 判断是否需要进行保存？
    global save_flag,packet_list,packet_id
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
            global packet_id
            packet_id = 1
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

                packet_id = 1
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
        packet_id = 1
        clear_button['state'] = 'disabled'



def on_click_packet_list_tree(event):
    '''
    数据包列表单击事件响应函数，在数据包列表中单击数据包时
    1.在协议解析区对数据包进行解析
    2.在hexdump区显示此数据包的十六进制的内容
    :return:
    '''


def analysis_result():
    # TODO 对抓取得到的数据包进行分析（域名统计，流量分析)
    pass




def filter_packet():
    # 设置过滤后需要更新过滤的值
    global filter_flag
    filter_flag = True
    # 根据用户输入生成BPF过滤规则
    protocal= protocal_combo.get()
    src_adr=src_adr_entry.get()
    src_port=src_port_entry.get()

    # 判断当前处于哪种状态？抓包前 vs 抓包后





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
stop_button = Button(toolbar, width=8, text="停止", command=stop_capture)
clear_button = Button(toolbar, width=8, text="清空数据", command=clear_data)
save_button = Button(toolbar, width=8, text="保存数据", command=save_captured_data_to_file)
quit_button = Button(toolbar, width=8, text="退出", command=quit_program)
analysis_button = Button(toolbar,width=8,text="流量分析",command=analysis_result)

start_button['state'] = 'normal'
#pause_button['state'] = 'disabled'
stop_button['state'] = 'disabled'
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

# 数据包列表区
packet_list_frame = Frame()
packet_list_sub_frame = Frame(packet_list_frame)
packet_list_tree = Treeview(packet_list_sub_frame, selectmode='browse')
packet_list_tree.bind('<<TreeviewSelect>>', on_click_packet_list_tree)
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



