import socket
import threading
import os
import base64
from http.server import BaseHTTPRequestHandler, HTTPServer
from http import HTTPStatus
import argparse
from urllib.parse import unquote
import signal
import sys


# 定义HTTP请求处理类
class HttpRequestHandler(BaseHTTPRequestHandler):
    web_dir = "data"  # 设置静态文件目录

    def do_GET(self):
        """Serve a GET request."""
        print("GET request received")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(
            b"""<html>
                    <head><title>Hello!</title></head>
                    <body><h1>Hello, World!</h1></body>
                </html>
            """
        )

        # self.send_response(200)
        # print("...")
        return
        # 解析请求的路径
        path = unquote(self.path)

        # 构建文件的完整路径
        filepath = os.path.join(self.web_dir, path.lstrip("/"))

        # 检查文件是否存在
        if not os.path.exists(filepath):
            self.send_error(404, "File not found")
            return

        # 检查是否是目录
        if os.path.isdir(filepath):
            # 如果是目录，则尝试查找index.html文件
            indexpath = os.path.join(filepath, "index.html")
            if os.path.exists(indexpath):
                filepath = indexpath
            else:
                self.send_error(403, "Directory listing not supported")
                return

        # 读取文件内容并发送
        try:
            with open(filepath, "rb") as file:
                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write(file.read())
        except IOError:
            self.send_error(500, "Internal Server Error")

    def do_HEAD(self):
        # 添加处理HEAD请求的逻辑
        pass

    def do_POST(self):
        # 添加处理POST请求的逻辑
        pass

    # def handle_authentication(self):
    #     # 添加处理验证的逻辑
    #     pass

    # def send_response(self, code, message=None):
    #     # 覆盖原始send_response来处理连接持久性
    #     pass


# 处理每个客户端连接
def handle_client(connection, address):
    try:
        HttpRequestHandler(
            request=connection,
            client_address=address,
            server="YourHTTPServer",  # 这里应该是您的服务器实例或描述
        )
    finally:
        connection.shutdown(socket.SHUT_WR)
        connection.close()


# 信号处理函数
def signal_handler(signum, frame):
    print("Interrupt received, shutting down the server")
    # 这里可以添加任何清理代码
    sys.exit(0)


# 运行服务器
def run_server(host, port):
    server_address = (host, port)
    
    # httpd = HTTPServer(server_address, HttpRequestHandler)
    # print(f"HTTP Server running on {host}:{port}")
    # httpd.serve_forever()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind(server_address)
        server_socket.listen(5)
        server_socket.settimeout(1)  # 设置超时时间

        print(f"HTTP Server running on {host}:{port}")

        while True:
            try:
                connection, address = server_socket.accept()
                thread = threading.Thread(
                    target=handle_client, args=(connection, address)
                )
                thread.start()
            except socket.timeout:
                pass


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="HTTP Server")
    parser.add_argument(
        "-i", "--host", type=str, default="localhost", help="Host address"
    )
    parser.add_argument("-p", "--port", type=int, default=8080, help="Port number")

    args = parser.parse_args()

    # 设置信号处理器
    signal.signal(signal.SIGINT, signal_handler)
    run_server(args.host, args.port)
