import socket
import threading
import os
import argparse
from urllib.parse import unquote
import signal
import sys
from enum import IntEnum
import time
import mimetypes


class HTTPStatus(IntEnum):
    def __new__(cls, value, phrase, description=""):
        obj = int.__new__(cls, value)
        obj._value_ = value

        obj.phrase = phrase
        obj.description = description
        return obj

    # informational
    CONTINUE = 100, "Continue", "Request received, please continue"
    SWITCHING_PROTOCOLS = (
        101,
        "Switching Protocols",
        "Switching to new protocol; obey Upgrade header",
    )
    PROCESSING = 102, "Processing"
    EARLY_HINTS = 103, "Early Hints"

    # success
    OK = 200, "OK", "Request fulfilled, document follows"
    PARTIAL_CONTENT = 206, "Partial Content", "Partial content follows"

    # redirection
    MOVED_PERMANENTLY = (
        301,
        "Moved Permanently",
        "Object moved permanently -- see URI list",
    )

    # client error
    BAD_REQUEST = (400, "Bad Request", "Bad request syntax or unsupported method")
    UNAUTHORIZED = (401, "Unauthorized", "No permission -- see authorization schemes")
    FORBIDDEN = (403, "Forbidden", "Request forbidden -- authorization will not help")
    NOT_FOUND = (404, "Not Found", "Nothing matches the given URI")
    METHOD_NOT_ALLOWED = (
        405,
        "Method Not Allowed",
        "Specified method is invalid for this resource",
    )
    REQUESTED_RANGE_NOT_SATISFIABLE = (
        416,
        "Requested Range Not Satisfiable",
        "Cannot satisfy request range",
    )

    # server errors
    NOT_IMPLEMENTED = (501, "Not Implemented", "Server does not support this operation")
    BAD_GATEWAY = (502, "Bad Gateway", "Invalid responses from another server/proxy")
    SERVICE_UNAVAILABLE = (
        503,
        "Service Unavailable",
        "The server cannot process the request due to a high load",
    )


class BaseHTTPRequestHandler:
    def __init__(self, client_socket: socket, client_address):
        self.client_socket = client_socket
        self.client_address = client_address

        self.request_method = None
        self.request_path = None
        self.request_httpVersion = None
        self.request_headers = {}
        self.request_body = None

        self.response_headers = []

    def handle_request(self):
        raw_request = self.client_socket.recv(1024).decode()

        request_line, rest = raw_request.split("\r\n", 1)
        raw_headers, raw_body = rest.split("\r\n\r\n", 1)
        self.parse_request_line(request_line)
        self.parse_headers(raw_headers)
        self.request_body = raw_body

        method_name = "do_" + self.request_method
        if not hasattr(self, method_name):
            self.send_error(HTTPStatus.NOT_IMPLEMENTED)
            return
        method = getattr(self, method_name)
        method()

    def parse_request_line(self, request_line):
        method, path, version = request_line.split(" ")
        self.request_method = method
        self.request_path = path
        self.request_httpVersion = version

    def parse_headers(self, raw_headers):
        for line in raw_headers.split("\r\n"):
            key, value = line.split(":", 1)
            self.request_headers[key.lower()] = value.strip()

    def send_response(self, code, message=None):
        response_line = f"HTTP/1.1 {code} {message}\r\n"
        self.response_headers.append(response_line.encode("latin-1", "strict"))
        self.send_header("Server", "CS305-2023Fall-PROJ-MiniHttpServer HTTP/1.1")
        self.send_header("Date", self.date_time_string())

    def send_error(self, code, message=None):
        self.send_response(code, message)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.client_socket.sendall(
            b"""<html>
                    <head><title>Error {code}</title></head>
                    <body><h1>Error {code}</h1></body>
                </html>
            """
        )

    def send_header(self, key, value):
        header_line = f"{key}: {value}\r\n"
        self.response_headers.append(header_line.encode("latin-1", "strict"))

    def end_headers(self):
        self.response_headers.append(b"\r\n")
        self.client_socket.sendall(b"".join(self.response_headers))

    def send_body(self, body):
        self.client_socket.sendall(body)

    def log_request(self, code="-", size="-"):
        if isinstance(code, HTTPStatus):
            code = code.value
        self.log_message('"%s" %s %s', self.request_line, str(code), str(size))

    def log_error(self, format, *args):
        self.log_message(format, *args)

    def log_message(self, format, *args):
        print(
            f"{self.client_address} - - [{self.log_date_time_string()}] {format % args}"
        )

    def date_time_string(self, timestamp=None):
        """Return the current date and time formatted for a message header."""
        if timestamp is None:
            timestamp = time.time()
        time_tuple = time.localtime(timestamp)
        date_str = time.strftime("%a, %d %b %Y %H:%M:%S", time_tuple)
        return date_str

    def log_date_time_string(self):
        """Return the current time formatted for logging."""
        now = time.time()
        year, month, day, hh, mm, ss, x, y, z = time.localtime(now)
        s = "%02d/%3s/%04d %02d:%02d:%02d" % (
            day,
            self.monthname[month],
            year,
            hh,
            mm,
            ss,
        )
        return s

    weekdayname = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]

    monthname = [
        None,
        "Jan",
        "Feb",
        "Mar",
        "Apr",
        "May",
        "Jun",
        "Jul",
        "Aug",
        "Sep",
        "Oct",
        "Nov",
        "Dec",
    ]


# 定义HTTP请求处理类
class HttpRequestHandler(BaseHTTPRequestHandler):
    web_dir = "data"  # 设置静态文件目录

    def do_GET(self):
        """Serve a GET request."""
        print("GET request received")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.send_body(
            b"""<html>
                    <head><title>Hello!</title></head>
                    <body><h1>Hello, World!</h1></body>
                </html>
            """
        )

        return
        # 解析请求的路径
        path = unquote(self.request_path)

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

    def handle_authentication(self):
        # 添加处理验证的逻辑
        pass


class FileSystem():
    def __init__(self, root):
        self.root = root

    def get_file(self, path):
        filepath = os.path.join(self.root, path.lstrip("/"))
        if not os.path.exists(filepath):
            raise FileNotFoundError
        with open(filepath, "rb") as file:
            return file.read()
    
    def save_file(self, path, content):
        filepath = os.path.join(self.root, path.lstrip("/"))
        with open(filepath, "wb") as file:
            file.write(content)
    
    def delete_file(self, path):
        filepath = os.path.join(self.root, path.lstrip("/"))
        if not os.path.exists(filepath):
            raise FileNotFoundError
        os.remove(filepath)
        
    def list_directory(self, path):
        dirpath = os.path.join(self.root, path.lstrip("/"))
        if not os.path.exists(dirpath):
            raise FileNotFoundError
        if not os.path.isdir(dirpath):
            raise NotADirectoryError
        return os.listdir(dirpath)


# 处理每个客户端连接
def handle_client(connection, address):
    try:
        httpRequestHandler = HttpRequestHandler(
            client_socket=connection,
            client_address=address,
        )
        httpRequestHandler.handle_request()
    finally:
        connection.shutdown(socket.SHUT_WR)
        connection.close()


# 运行服务器
def run_server(host, port):
    server_address = (host, port)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind(server_address)
        server_socket.listen()
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


# 信号处理函数
def signal_handler(signum, frame):
    print("Interrupt received, shutting down the server")
    # 这里可以添加任何清理代码
    sys.exit(0)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="HTTP Server")
    parser.add_argument(
        "-i",
        "--host",
        type=str,
        default="localhost",
        help="Host address",
    )
    parser.add_argument("-p", "--port", type=int, default=8080, help="Port number")

    args = parser.parse_args()

    # 设置信号处理器
    signal.signal(signal.SIGINT, signal_handler)
    run_server(args.host, args.port)
