import socket
import threading
import time
import sys
import os
from datetime import datetime
import tkinter as tk
from tkinter import (scrolledtext, Entry, Button, END, Label, messagebox,
                     filedialog, ttk)
import webbrowser

# 常量定义
BUFFER_SIZE = 1024  # 数据缓冲区大小
CHAT_MSG_FLAG = b"CHAT_MSG"  # 聊天消息标识
FILE_MSG_FLAG = b"FILE_MSG"  # 文件消息标识


class P2P_Chat_GUI:
    def __init__(self, root):
        self.root = root
        self.root.title("LANChatRoom v1.0")
        self.root.geometry("500x600")
        self.root.resizable(True, True)
        
        self.running = True
        self.username = None
        self.port = None
        self.broadcast_socket = None  # 用于聊天和文件头广播
        self.file_listen_socket = None  # 专门用于文件数据接收的socket
        self.file_transfer_thread = None  # 文件传输线程
        self.is_transferring = False  # 是否正在传输文件

        # 获取用户名和端口
        user_info = self.get_user_info()
        if not user_info:
            sys.exit(1)
        self.username, self.port = user_info

        # 初始化网络组件
        try:
            self.init_network()
        except Exception as e:
            messagebox.showerror("网络初始化失败", f"无法初始化网络连接：{str(e)}")
            sys.exit(1)

        # 创建GUI组件
        self.create_widgets()

        # 启动监听线程（聊天消息+文件头）
        self.chat_listen_thread = threading.Thread(target=self.listen_chat_and_file_header, daemon=True)
        self.chat_listen_thread.start()

        # 发送上线通知
        self.send_chat_message(f"{self.username} 加入了聊天室（端口: {self.port}）", is_system=True)


    def get_user_info(self):
        """获取用户名和端口的设置对话框"""
        dialog = tk.Toplevel(self.root)
        dialog.title("设置")
        dialog.geometry("380x220")
        dialog.resizable(False, False)
        dialog.transient(self.root)
        dialog.grab_set()

        # 用户名输入
        Label(dialog, text="输入用户名：").pack(pady=(20, 5), anchor="w", padx=30)
        username_entry = Entry(dialog, width=35)
        username_entry.pack(pady=(0, 15), padx=30)
        username_entry.focus()

        # 端口输入
        Label(dialog, text="输入通信端口（1-65535）：").pack(pady=(5, 5), anchor="w", padx=30)
        port_frame = tk.Frame(dialog)
        port_frame.pack(pady=(0, 15), padx=30, fill=tk.X)
        port_entry = Entry(port_frame, width=12)
        port_entry.pack(side=tk.LEFT)
        port_entry.insert(0, "10086")  # 默认端口
        Label(port_frame, text="  建议使用10000以上端口避免冲突").pack(side=tk.LEFT, padx=5, fill=tk.X)

        result = [None, None]

        def on_ok():
            # 验证用户名
            username = username_entry.get().strip()
            if not username:
                messagebox.showwarning("输入错误", "用户名不能为空！")
                return

            # 验证端口
            try:
                port = int(port_entry.get().strip())
                if not (1 <= port <= 65535):
                    raise ValueError("端口必须在1-65535之间")
            except ValueError as e:
                messagebox.showwarning("输入错误", f"无效端口：{str(e)}")
                return

            result[0] = username
            result[1] = port
            dialog.destroy()

        def on_cancel():
            dialog.destroy()

        # 按钮区域
        button_frame = tk.Frame(dialog)
        button_frame.pack(pady=5)
        Button(button_frame, text="确定", command=on_ok, width=10).pack(side=tk.LEFT, padx=15)
        Button(button_frame, text="取消", command=on_cancel, width=10).pack(side=tk.LEFT, padx=15)

        self.root.wait_window(dialog)
        return (result[0], result[1]) if result[0] and result[1] else None


    def init_network(self):
        """初始化网络组件：修复Windows下的socket参数错误"""
        # 1. 聊天消息和文件头的广播socket（UDP）
        self.broadcast_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Windows系统需要先绑定端口才能设置广播选项
        self.broadcast_socket.bind(('', self.port))
        self.broadcast_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

        # 2. 文件数据接收socket（TCP，可靠传输）
        self.file_listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.file_listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.file_listen_socket.bind(('', self.port))
        self.file_listen_socket.listen(5)


    def create_widgets(self):
        """创建所有GUI组件"""
        # 1. 顶部信息栏
        top_frame = tk.Frame(self.root, bg="#f0f0f0")
        top_frame.pack(fill=tk.X, padx=10, pady=5)
        info_label = Label(
            top_frame, 
            text=f"当前用户：{self.username} | 通信端口：{self.port} | 状态：在线",
            bg="#f0f0f0",
            font=("Arial", 10)
        )
        info_label.pack(anchor="w", padx=10, pady=3)

        # 2. 聊天记录区域
        chat_frame = tk.Frame(self.root)
        chat_frame.pack(padx=10, pady=5, fill=tk.BOTH, expand=True)
        Label(chat_frame, text="聊天记录", font=("Arial", 10, "bold")).pack(anchor="w")
        self.chat_area = scrolledtext.ScrolledText(
            chat_frame, 
            wrap=tk.WORD, 
            state=tk.DISABLED,
            font=("Arial", 10)
        )
        self.chat_area.pack(padx=5, pady=5, fill=tk.BOTH, expand=True)

        # 3. 文件传输进度区域（默认隐藏）
        self.transfer_frame = tk.Frame(self.root, bg="#f8f8f8")
        self.transfer_label = Label(self.transfer_frame, text="文件传输：无", bg="#f8f8f8")
        self.transfer_label.pack(side=tk.LEFT, padx=10, pady=5)
        self.progress_bar = ttk.Progressbar(self.transfer_frame, orient=tk.HORIZONTAL, length=400, mode='determinate')
        self.progress_bar.pack(side=tk.LEFT, padx=10, pady=5, fill=tk.X, expand=True)

        # 4. 操作区域（聊天输入+文件发送+退出）
        action_frame = tk.Frame(self.root)
        action_frame.pack(padx=10, pady=5, fill=tk.X)

        # 聊天输入框
        self.msg_entry = Entry(action_frame, font=("Arial", 10))
        self.msg_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        self.msg_entry.bind("<Return>", lambda e: self.send_chat_message())

        # 发送按钮
        send_btn = Button(action_frame, text="发送消息", command=self.send_chat_message, width=12)
        send_btn.pack(side=tk.LEFT, padx=(0, 5))

        # 文件发送按钮
        file_btn = Button(action_frame, text="发送文件", command=self.select_and_send_file, width=12)
        file_btn.pack(side=tk.LEFT, padx=(0, 5))

        # 退出按钮
        exit_btn = Button(action_frame, text="退出", command=self.on_exit, width=10, bg="#ffcccc")
        exit_btn.pack(side=tk.LEFT)

        # 5. 底部链接区域
        bottom_frame = tk.Frame(self.root)
        bottom_frame.pack(fill=tk.X, padx=10, pady=5)

        github_link = Label(bottom_frame, text="GitHub仓库", fg="black", cursor="hand2")
        github_link.pack(side=tk.LEFT, padx=5)
        github_link.bind("<Button-1>", lambda e: webbrowser.open_new("https://github.com/jianzongX/LAN_ChatRoom"))

        license_link = Label(bottom_frame, text="开源协议", fg="black", cursor="hand2")
        license_link.pack(side=tk.LEFT, padx=5)
        license_link.bind("<Button-1>", lambda e: webbrowser.open_new("https://github.com/jianzongX/LAN_ChatRoom?tab=Apache-2.0-1-ov-file"))

        dev_link = Label(bottom_frame, text="开发者(jianzongX)", fg="black", cursor="hand2")
        dev_link.pack(side=tk.RIGHT, padx=5)
        dev_link.bind("<Button-1>", lambda e: webbrowser.open_new("https://github.com/jianzongX"))


    def listen_chat_and_file_header(self):
        """监听：1. 聊天消息 2. 文件传输请求（文件头）"""
        while self.running:
            try:
                # 接收聊天消息或文件头（UDP）
                data, addr = self.broadcast_socket.recvfrom(BUFFER_SIZE)
                if not data:
                    continue

                # 区分消息类型（前8字节是标识）
                msg_flag = data[:8]
                msg_content = data[8:].decode('utf-8', errors='ignore')

                # 处理聊天消息
                if msg_flag == CHAT_MSG_FLAG:
                    self.handle_chat_message(msg_content, addr)

                # 处理文件传输请求（接收文件头）
                elif msg_flag == FILE_MSG_FLAG:
                    self.handle_file_header(msg_content, addr)

            except Exception as e:
                if self.running:
                    self.add_chat_log(f"[警告] 监听错误：{str(e)}")
                break


    def handle_chat_message(self, msg_content, addr):
        """处理接收到的聊天消息"""
        # 过滤自己发送的消息
        if not msg_content.startswith(f"{self.username}:"):
            # 检查是否为系统消息
            if msg_content.startswith("系统消息:"):
                # 系统消息使用灰色显示，不显示时间，移除前缀
                # 过滤掉自己发送的系统消息，避免重复显示
                if f"{self.username} 加入了聊天室" in msg_content or f"{self.username} 离开了聊天室" in msg_content:
                    return
                system_msg = msg_content.replace("系统消息:", "").strip()
                self.add_chat_log(system_msg, is_system=True)
            else:
                # 普通消息，不显示时间戳
                # 检查是否为文件发送通知
                if "正在发送文件：" in msg_content and "（" in msg_content and "）" in msg_content:
                    self.add_chat_log(msg_content, is_file_info=True)
                else:
                    self.add_chat_log(msg_content)
            
            # 收到消息后将窗口置顶
            self.root.lift()
            self.root.attributes('-topmost', True)
            self.root.after(3000, lambda: self.root.attributes('-topmost', False)) # 3秒后取消置顶


    def handle_file_header(self, file_header, addr):
        """处理文件头：解析文件名和大小，准备接收文件"""
        try:
            # 文件头格式："发送者|文件名|文件大小"
            sender, filename, file_size = file_header.split("|", 2)
            
            # 过滤自己发送的文件请求
            if sender == self.username:
                return
            
            file_size = int(file_size)
            filename = self.sanitize_filename(filename)  # 过滤非法字符

            # 提示用户是否接收
            resp = messagebox.askyesno(
                "接收文件",
                f"{sender} 向你发送文件：\n文件名：{filename}\n文件大小：{self.format_file_size(file_size)}\n是否接收？"
            )
            if not resp:
                self.add_chat_log(f"[信息] 已拒绝接收 {sender} 的文件：{filename}", is_file_info=True)
                return

            # 显示传输进度条
            self.show_transfer_progress(f"正在接收：{filename}（来自{sender}）")
            self.progress_bar['value'] = 0
            self.progress_bar['maximum'] = file_size

            # 启动TCP连接接收文件（单独线程，避免阻塞UI）
            threading.Thread(
                target=self.receive_file,
                args=(addr[0], self.port, filename, file_size),
                daemon=True
            ).start()

        except Exception as e:
            self.add_chat_log(f"[警告] 解析文件请求失败：{str(e)}")
            self.hide_transfer_progress()


    def receive_file(self, sender_ip, port, filename, file_size):
        """接收文件（TCP）"""
        received_size = 0
        save_path = os.path.join(os.getcwd(), filename)  # 保存到当前目录

        try:
            # 建立TCP连接到发送方
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as file_sock:
                file_sock.settimeout(10)
                file_sock.connect((sender_ip, port))

                # 接收文件数据
                with open(save_path, 'wb') as f:
                    while received_size < file_size and self.running:
                        data = file_sock.recv(BUFFER_SIZE)
                        if not data:
                            break
                        f.write(data)
                        received_size += len(data)

                        # 更新进度条（UI操作需在主线程，用after方法）
                        progress = (received_size / file_size) * 100
                        self.root.after(0, lambda: self.progress_bar.config(value=received_size))
                        self.root.after(0, lambda: self.transfer_label.config(text=f"接收进度：{progress:.1f}%"))

            # 验证文件完整性
            if received_size == file_size:
                self.add_chat_log(f"[成功] 文件接收完成！已保存到：\n{save_path}", is_file_info=True)
            else:
                os.remove(save_path)  # 删除不完整文件
                self.add_chat_log(f"[失败] 文件接收中断（仅接收{self.format_file_size(received_size)}/{self.format_file_size(file_size)}）", is_file_info=True)

        except Exception as e:
            self.add_chat_log(f"[警告] 文件接收失败：{str(e)}", is_file_info=True)
            if os.path.exists(save_path):
                os.remove(save_path)

        finally:
            # 隐藏进度条
            self.root.after(0, self.hide_transfer_progress())


    def select_and_send_file(self):
        """选择本地文件并发送（先广播文件头，再用TCP发送文件）"""
        if self.is_transferring:
            messagebox.showwarning("传输中", "当前已有文件正在传输，请等待完成后再发送！")
            return

        # 选择文件
        file_path = filedialog.askopenfilename(
            title="选择要发送的文件",
            filetypes=[("所有文件", "*.*"), ("文档", "*.txt;*.docx;*.pdf"), ("图片", "*.jpg;*.png;*.gif")]
        )
        if not file_path or not os.path.exists(file_path):
            return

        # 获取文件信息
        filename = os.path.basename(file_path)
        file_size = os.path.getsize(file_path)
        if file_size == 0:
            messagebox.showwarning("无效文件", "不能发送空文件！")
            return

        # 广播文件头（通知所有在线用户）
        file_header = f"{self.username}|{filename}|{file_size}"
        try:
            # 发送文件头（UDP广播）
            self.broadcast_socket.sendto(
                CHAT_MSG_FLAG + f"{self.username} 正在发送文件：{filename}（{self.format_file_size(file_size)}）".encode('utf-8'),
                ('255.255.255.255', self.port)
            )
            self.broadcast_socket.sendto(
                FILE_MSG_FLAG + file_header.encode('utf-8'),
                ('255.255.255.255', self.port)
            )
            self.add_chat_log(f"[信息] 已发起文件发送：{filename}（{self.format_file_size(file_size)}），等待接收方响应...", is_file_info=True)

            # 启动TCP服务器等待接收方连接（多线程，支持同时发给多个用户）
            self.is_transferring = True
            self.show_transfer_progress(f"正在发送：{filename}（等待接收方...）")
            self.progress_bar['value'] = 0

            # 启动文件发送监听线程（处理多个接收方连接）
            self.file_transfer_thread = threading.Thread(
                target=self.listen_file_connections,
                args=(file_path, filename, file_size),
                daemon=True
            )
            self.file_transfer_thread.start()

        except Exception as e:
            self.add_chat_log(f"[警告] 发起文件发送失败：{str(e)}", is_file_info=True)
            self.is_transferring = False
            self.hide_transfer_progress()


    def listen_file_connections(self, file_path, filename, file_size):
        """监听接收方的文件连接请求，发送文件给每个连接"""
        client_count = 0
        try:
            while self.running and client_count < 5:  # 最多同时发给5个用户
                # 等待接收方连接（超时30秒，没有连接则退出）
                self.file_listen_socket.settimeout(30)
                client_sock, client_addr = self.file_listen_socket.accept()
                client_count += 1
                self.add_chat_log(f"[连接] 已连接接收方：{client_addr[0]}（{filename}）", is_file_info=True)

                # 单独线程给这个接收方发送文件
                threading.Thread(
                    target=self.send_file_to_client,
                    args=(client_sock, file_path, filename, file_size, client_addr),
                    daemon=True
                ).start()

        except socket.timeout:
            if client_count == 0:
                self.add_chat_log(f"[超时] 文件发送超时：30秒内无接收方响应", is_file_info=True)
        except Exception as e:
            self.add_chat_log(f"[警告] 文件连接监听错误：{str(e)}", is_file_info=True)
        finally:
            self.is_transferring = False
            self.hide_transfer_progress()
            self.add_chat_log(f"[信息] 文件发送任务结束（共发送给{client_count}个接收方）", is_file_info=True)


    def send_file_to_client(self, client_sock, file_path, filename, file_size, client_addr):
        """给单个接收方发送文件数据"""
        sent_size = 0
        try:
            with open(file_path, 'rb') as f:
                while self.running and sent_size < file_size:
                    # 读取文件数据
                    data = f.read(BUFFER_SIZE)
                    if not data:
                        break
                    # 发送数据
                    client_sock.sendall(data)
                    sent_size += len(data)

                    # 更新进度条（显示当前发送进度）
                    progress = (sent_size / file_size) * 100
                    self.root.after(0, lambda: self.transfer_label.config(
                        text=f"发送给{client_addr[0]}：{filename}（{progress:.1f}%）"
                    ))
                    self.root.after(0, lambda: self.progress_bar.config(value=sent_size, maximum=file_size))

            # 验证发送结果
            if sent_size == file_size:
                self.add_chat_log(f"[成功] 已成功发送文件给：{client_addr[0]}（{filename}）", is_file_info=True)
            else:
                self.add_chat_log(f"[失败] 发送给{client_addr[0]}失败：仅发送{self.format_file_size(sent_size)}/{self.format_file_size(file_size)}", is_file_info=True)

        except Exception as e:
            self.add_chat_log(f"[警告] 发送给{client_addr[0]}错误：{str(e)}", is_file_info=True)
        finally:
            client_sock.close()


    # ---------------------- 辅助函数 ----------------------
    def send_chat_message(self, system_msg=None, is_system=False):
        """发送聊天消息（支持系统消息）"""
        # 如果是用户输入的消息
        if system_msg is None:
            msg = self.msg_entry.get().strip()
            if not msg:
                return
            full_msg = f"{self.username}: {msg}"
            self.msg_entry.delete(0, END)
        else:
            # 如果是系统消息，添加前缀（仅在网络传输时）
            if is_system:
                full_msg = f"系统消息: {system_msg}"
            else:
                full_msg = system_msg

        # 广播消息（UDP）
        try:
            self.broadcast_socket.sendto(
                CHAT_MSG_FLAG + full_msg.encode('utf-8'),
                ('255.255.255.255', self.port)
            )
            # 自己的消息也显示到聊天记录，不显示时间戳
            if system_msg is None:
                self.add_chat_log(f"我：{msg}", is_self=True)
            elif is_system:
                # 系统消息在本地显示时不带前缀
                self.add_chat_log(system_msg, is_system=True)
        except Exception as e:
            self.add_chat_log(f"[警告] 消息发送失败：{str(e)}")


    def add_chat_log(self, content, is_system=False, is_self=False, is_file_info=False):
        """添加内容到聊天记录区（线程安全）"""
        def _update():
            self.chat_area.config(state=tk.NORMAL)
            
            # 配置标签样式
            self.chat_area.tag_configure("system", foreground="gray", justify="center", font=("Arial", 8))
            self.chat_area.tag_configure("self", justify="right")
            self.chat_area.tag_configure("file_info", foreground="#ADD8E6", justify="center", font=("Arial", 8)) # 浅蓝色，居中，小字体
            
            if is_system:
                # 系统消息使用灰色显示，居中，小字体
                self.chat_area.insert(END, content + "\n", "system")
            elif is_self:
                # 自己发送的消息靠右显示
                self.chat_area.insert(END, content + "\n", "self")
            elif is_file_info:
                # 文件信息消息使用浅蓝色显示，居中，小字体
                self.chat_area.insert(END, content + "\n", "file_info")
            else:
                # 普通消息
                self.chat_area.insert(END, content + "\n")
                
            self.chat_area.see(END)  # 滚动到底部
            self.chat_area.config(state=tk.DISABLED)
        self.root.after(0, _update)


    def show_transfer_progress(self, text):
        """显示文件传输进度条"""
        def _show():
            self.transfer_frame.pack(fill=tk.X, padx=10, pady=5)
            self.transfer_label.config(text=text)
            self.progress_bar['value'] = 0
        self.root.after(0, _show)


    def hide_transfer_progress(self):
        """隐藏文件传输进度条"""
        def _hide():
            self.transfer_frame.pack_forget()
            self.transfer_label.config(text="文件传输：无")
            self.progress_bar['value'] = 0
        self.root.after(0, _hide)


    def format_file_size(self, size_bytes):
        """格式化文件大小（B→KB→MB→GB）"""
        units = ['B', 'KB', 'MB', 'GB']
        unit_idx = 0
        size = size_bytes
        while size >= 1024 and unit_idx < 3:
            size /= 1024
            unit_idx += 1
        return f"{size:.1f}{units[unit_idx]}"


    def sanitize_filename(self, filename):
        """过滤文件名中的非法字符（避免保存时出错）"""
        illegal_chars = ['\\', '/', ':', '*', '?', '"', '<', '>', '|']
        for c in illegal_chars:
            filename = filename.replace(c, '_')
        return filename


    def on_exit(self):
        """退出聊天室清理资源"""
        self.running = False
        self.is_transferring = False

        # 发送下线通知
        try:
            self.send_chat_message(f"{self.username} 离开了聊天室", is_system=True)
            time.sleep(0.5)  # 等待消息发送完成
        except:
            pass

        # 关闭socket
        for sock in [self.broadcast_socket, self.file_listen_socket]:
            try:
                if sock:
                    sock.close()
            except:
                pass

        # 关闭窗口
        self.root.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    app = P2P_Chat_GUI(root)
    # 处理窗口关闭事件（确保资源清理）
    root.protocol("WM_DELETE_WINDOW", app.on_exit)
    root.mainloop()
