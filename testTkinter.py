# coding=utf-8
import datetime
import threading
import tkinter
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

def start_capture():
    pass
def pause_capture():
    pass
def stop_capture():
    pass
def save_captured_data_to_file():
    pass
def quit_program():
    pass
def on_click_packet_list_tree():
    pass
def analysis_result():
    pass
def filter_packet():
    pass
def clear_data():
    pass

def getNIC():
    return ['eth0','eth1','eth2']

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
select_nic_combo=ttk.Combobox(toolbar,width=15,values=getNIC())
select_nic_combo.current(1)
start_button = Button(toolbar, width=8, text="开始", command=start_capture)
pause_button = Button(toolbar, width=8, text="暂停", command=pause_capture)
stop_button = Button(toolbar, width=8, text="停止", command=stop_capture)
clear_button = Button(toolbar, width=8, text="清空数据", command=clear_data)
save_button = Button(toolbar, width=8, text="保存数据", command=save_captured_data_to_file)
quit_button = Button(toolbar, width=8, text="退出", command=quit_program)
analysis_button = Button(toolbar,width=8,text="流量分析",command=analysis_result)

start_button['state'] = 'normal'
pause_button['state'] = 'disabled'
stop_button['state'] = 'disabled'
clear_button['state']='disabled'
save_button['state'] = 'disabled'
analysis_button['state']='disabled'
quit_button['state'] = 'normal'

select_nic_label.pack(side=LEFT,padx=10,pady=10)
select_nic_combo.pack(side=LEFT,after=select_nic_label,pady=10)
start_button.pack(side=LEFT, after=select_nic_combo,padx=10,pady=10)
pause_button.pack(side=LEFT, after=start_button, padx=10, pady=10)
stop_button.pack(side=LEFT, after=pause_button, padx=10, pady=10)
save_button.pack(side=LEFT, after=stop_button, padx=10, pady=10)
analysis_button.pack(side=LEFT, after=save_button, padx=10, pady=10)
quit_button.pack(side=LEFT, after=analysis_button, padx=10, pady=10)

toolbar.pack(side=TOP, fill=X)


# 数据包过滤区
filter_frame = Frame()
protocal_label = Label(filter_frame, width=10, text="协议类型：")
protocal_combo=ttk.Combobox(filter_frame,width=15,values=['ARP only','IP only','TCP only',"UDP only","TCP or UDP"])
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



