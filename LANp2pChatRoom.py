import socket
import threading
import time
import sys
from datetime import datetime

class P2P_Chat:
    def __init__(self, port=10086, buffer_size=1024):
        self.port = port
        self.buffer_size = buffer_size
        self.username = input("请输入你的用户名: ")
        self.running = True
        self.broadcast_socket = self.create_broadcast_socket()
        self.listen_socket = self.create_listen_socket()
        print(f"\n{self.username}，欢迎来到P2P局域网聊天室！")
        print("输入消息并按回车发送，输入 'exit' 退出聊天室\n")

    def create_broadcast_socket(self):
        """创建用于发送广播的socket"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        return sock

    def create_listen_socket(self):
        """创建用于监听消息的socket"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # 绑定到所有网络接口的指定端口
        sock.bind(('', self.port))
        return sock

    def listen(self):
        """监听并接收消息的线程函数"""
        while self.running:
            try:
                data, addr = self.listen_socket.recvfrom(self.buffer_size)
                message = data.decode('utf-8')
                # 不显示自己发送的消息
                if not message.startswith(self.username + ':'):
                    timestamp = datetime.now().strftime('%H:%M:%S')
                    print(f"\n[{timestamp}] {message}")
                    print("输入消息: ", end='', flush=True)
            except Exception as e:
                if self.running:
                    print(f"接收消息出错: {e}")
                break

    def send_broadcast(self, message):
        """发送广播消息"""
        try:
            # 广播到局域网内的所有设备
            self.broadcast_socket.sendto(
                message.encode('utf-8'), 
                ('255.255.255.255', self.port)
            )
        except Exception as e:
            print(f"发送消息出错: {e}")

    def start(self):
        """启动聊天室"""
        # 启动监听线程
        listen_thread = threading.Thread(target=self.listen, daemon=True)
        listen_thread.start()

        # 发送上线通知
        self.send_broadcast(f"系统消息: {self.username} 加入了聊天室")

        # 主循环处理输入
        try:
            while self.running:
                message = input("输入消息: ")
                if message.lower() == 'exit':
                    self.running = False
                    self.send_broadcast(f"系统消息: {self.username} 离开了聊天室")
                    break
                if message.strip():  # 不发送空消息
                    full_message = f"{self.username}: {message}"
                    self.send_broadcast(full_message)
        except KeyboardInterrupt:
            self.running = False
            self.send_broadcast(f"系统消息: {self.username} 离开了聊天室")

        # 清理资源
        self.broadcast_socket.close()
        self.listen_socket.close()
        print("\n聊天室已关闭，再见！")

if __name__ == "__main__":
    chat = P2P_Chat()
    chat.start()
