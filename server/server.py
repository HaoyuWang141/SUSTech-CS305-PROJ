import socket
import threading
import os
import argparse
from urllib.parse import unquote
import signal
import sys
from enum import IntEnum, Enum
import time
import mimetypes
from typing import NamedTuple

ROOT = "data/"  # 文件根目录


class UserInfo(NamedTuple):
    username: str
    password: str
    tocken: str
    tocken_expire_time: int


class Users(Enum):
    USER1 = UserInfo("user1", "password1", "tocken1", 100000000)
    USER2 = UserInfo("user2", "password2", "tocken2", 100000000)
    USER3 = UserInfo("user3", "password3", "tocken3", 100000000)

    @property
    def username(self):
        return self.value.username

    @property
    def password(self):
        return self.value.password

    @property
    def tocken(self):
        return self.value.tocken

    @property
    def tocken_expire_time(self):
        return self.value.tocken_expire_time


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
    INTERNAL_SERVER_ERROR = (
        500,
        "Internal Server Error",
        "Server got itself in trouble",
    )
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

        self.user = Users.USER1

        self.request_line = None
        self.request_method = None
        self.request_url = None
        self.request_path = None
        self.request_params = {}
        self.request_httpVersion = None
        self.request_headers = {}
        self.request_body = None

        self.response_headers = []

    def handle_request(self):
        SIZE = 2048
        raw_request = self.client_socket.recv(SIZE).decode()

        request_line, rest = raw_request.split("\r\n", 1)
        raw_headers, raw_body = rest.split("\r\n\r\n", 1)

        self.request_line = request_line
        try:
            self.parse_request_line(request_line)
        except ValueError as e:
            self.send_error(HTTPStatus.BAD_REQUEST, str(e))
            return
        self.parse_headers(raw_headers)
        self.request_body = raw_body

        if "content-length" in self.request_headers:
            content_length = int(self.request_headers["content-length"])
            if len(raw_body) < content_length:
                to_read = content_length - len(raw_body)
                self.request_body += self.client_socket.recv(
                    to_read if to_read < SIZE else SIZE
                ).decode()

        # TODO: 处理验证
        # 接收完了请求，开始处理
        # 权限认证

        method_name = "do_" + self.request_method
        if not hasattr(self, method_name):
            self.send_error(HTTPStatus.NOT_IMPLEMENTED)
            return
        method = getattr(self, method_name)
        method()

    def parse_request_line(self, request_line):
        method, url, version = request_line.split(" ")
        self.request_url = url
        self.request_method = method
        self.request_httpVersion = version
        path, query = url.split("?") if "?" in url else (url, None)
        if not path.startswith("/"):
            raise ValueError(f"Malformed path: {path}")
        self.request_path = path
        for param in query.split("&") if query else []:
            if "=" not in param:
                raise ValueError(f"Malformed parameter: {param}")
            key, value = param.split("=")
            self.request_params[key] = value

    def parse_headers(self, raw_headers):
        for line in raw_headers.split("\r\n"):
            key, value = line.split(":", 1)
            self.request_headers[key.lower()] = value.strip()

    def send_response(self, code, message=None):
        self.log_request(code)
        response_line = f"HTTP/1.1 {code} {message}\r\n"
        self.response_headers.append(response_line.encode("latin-1", "strict"))
        self.send_header("Server", "CS305-2023Fall-PROJ-MiniHttpServer HTTP/1.1")
        self.send_header("Date", self.date_time_string())

    def send_error(self, code, message=None):
        self.log_error("code %d, message %s", code, message)
        self.send_response(code, message)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.client_socket.sendall(
            f"""<html>
                    <head><title>Error {code}</title></head>
                    <body>
                        <h1>Error {code}</h1>
                        <p>{message}</p> 
                    </body>
                </html>
            """.encode()
        )

    def send_header(self, key, value):
        header_line = f"{key}: {value}\r\n"
        self.response_headers.append(header_line.encode("latin-1", "strict"))

    def end_headers(self):
        self.response_headers.append(b"\r\n")
        self.client_socket.sendall(b"".join(self.response_headers))

    def send_body(self, body):
        self.client_socket.sendall(body)

    def log_request(self, code="-"):
        if isinstance(code, HTTPStatus):
            code = code.value
        print(
            f'\033[94mLOG {self.client_address} [{self.log_date_time_string()}] "{self.request_line}" {str(code)}\033[0m'
        )

    def log_error(self, format, *args):
        print(
            f"\033[91mERR {self.client_address} [{self.log_date_time_string()}] {format % args}\033[0m"
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
    def __init__(self, client_socket, client_address):
        super().__init__(client_socket, client_address)
        self.fileSystem = FileSystem(ROOT)

    def do_GET(self):
        """Serve a GET request."""
        if self.request_url.startswith("/favicon.ico"):
            size, mimetype, content = self.fileSystem.get_file("/asserts/favicon.ico")
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-type", mimetype)
            self.send_header("Content-Length", size)
            self.end_headers()
            self.send_body(content)
            return
        if not self.request_url.startswith(f"/{self.user.username}"):
            self.send_error(HTTPStatus.BAD_REQUEST)
            return
        if self.request_url.startswith("/upload") or self.request_url.startswith(
            "/delete"
        ):
            self.send_error(HTTPStatus.METHOD_NOT_ALLOWED)
            return
        if self.request_params:
            self.send_error(HTTPStatus.BAD_REQUEST)
            return

        filepath = self.request_url

        # 检查文件是否存在
        if not self.fileSystem.exists(filepath):
            self.send_error(HTTPStatus.NOT_FOUND, "File or directory not found")
            return

        # 检查是否是目录
        if self.fileSystem.is_dir(filepath):
            # 如果是目录，则列出目录内容
            try:
                dir_list = self.fileSystem.list_directory(filepath)
                if not self.fileSystem.is_same_path(filepath, f"/{self.user.username}"):
                    dir_list = ["../"] + dir_list
                dir_list = [
                    f'<li><a href="{os.path.join(self.request_path, item)}">{item}</a></li>'
                    for item in dir_list
                ]
                dir_list = [
                    f'<li><a href="\{self.user.username}">/</a></li>'
                ] + dir_list
                dir_list = "\n".join(dir_list)
                dir_list = f"""
                    <html>
                        <head><title>Index of {self.request_path}</title></head>
                        <body>
                            <h1>Index of {self.request_path}</h1>
                            <ul>
                                {dir_list}
                            </ul>
                        </body>
                    </html>
                """.encode(
                    "utf-8"
                )
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-type", "text/html")
                self.send_header("Content-Length", str(len(dir_list)))
                self.end_headers()
                self.send_body(dir_list)
            except Exception:
                self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR)
        elif self.fileSystem.is_file(filepath):
            # 如果是文件，则读取文件内容并发送
            try:
                size, mimetype, content = self.fileSystem.get_file(filepath)
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-type", mimetype)
                self.send_header("Content-Length", str(size))
                self.end_headers()
                self.send_body(content)
            except IOError:
                self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR)
        else:
            self.send_error(HTTPStatus.NOT_FOUND)

    def do_HEAD(self):
        """Serve a HEAD request"""
        if not self.request_url.startswith(f"/{self.user.username}"):
            self.send_error(HTTPStatus.BAD_REQUEST)
            return
        if self.request_url.startswith("/upload") or self.request_url.startswith(
            "/delete"
        ):
            self.send_error(HTTPStatus.METHOD_NOT_ALLOWED)
            return
        if self.request_params:
            self.send_error(HTTPStatus.BAD_REQUEST)
            return

        filepath = self.request_url

        # 检查文件是否存在
        if not self.fileSystem.exists(filepath):
            self.send_error(HTTPStatus.NOT_FOUND, "File or directory not found")
            return

        # 检查是否是目录
        if self.fileSystem.is_dir(filepath):
            # 如果是目录，则列出目录内容
            try:
                dir_list = self.fileSystem.list_directory(filepath)
                if not self.fileSystem.is_same_path(filepath, f"/{self.user.username}"):
                    dir_list = ["../"] + dir_list
                dir_list = [
                    f'<li><a href="{os.path.join(self.request_path, item)}">{item}</a></li>'
                    for item in dir_list
                ]
                dir_list = [
                    f'<li><a href="\{self.user.username}">/</a></li>'
                ] + dir_list
                dir_list = "\n".join(dir_list)
                dir_list = f"""
                    <html>
                        <head><title>Index of {self.request_path}</title></head>
                        <body>
                            <h1>Index of {self.request_path}</h1>
                            <ul>
                                {dir_list}
                            </ul>
                        </body>
                    </html>
                """.encode(
                    "utf-8"
                )
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-type", "text/html")
                self.send_header("Content-Length", str(len(dir_list)))
                self.end_headers()
            except Exception:
                self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR)
        elif self.fileSystem.is_file(filepath):
            # 如果是文件，则读取文件内容并发送
            try:
                size, mimetype, content = self.fileSystem.get_file(filepath)
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-type", mimetype)
                self.send_header("Content-Length", str(size))
                self.end_headers()
            except IOError:
                self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR)
        else:
            self.send_error(HTTPStatus.NOT_FOUND)

    def do_POST(self):
        """Serve a POST request"""
        if self.request_url.startswith(f"/{self.user.username}"):
            self.send_error(HTTPStatus.METHOD_NOT_ALLOWED)
            return
        if "path" not in self.request_params:
            self.send_error(HTTPStatus.BAD_REQUEST)
            return
        if not self.fileSystem.is_dir(f"/{self.user.username}"):
            self.send_error(
                HTTPStatus.SERVICE_INTERNAL_ERROR,
                f"root directory for user {self.user.username} not found",
            )
            return

        if self.request_url == "/upload":
            try:
                boundary = self.extract_boundary(self.request_headers["content-type"])
                for filename, content in self.parse_multipart(
                    self.request_body, boundary
                ):
                    filepath = os.path.join(
                        self.request_params["path"], filename.lstrip("/")
                    )
                    self.fileSystem.save_file(filepath, content)
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-type", "text/html")
                self.send_header("Content-Length", str(0))
                self.end_headers()
            except ValueError as e:
                self.send_error(HTTPStatus.BAD_REQUEST)
            except Exception:
                self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR)

        elif self.request_url == "/delete":
            try:
                self.fileSystem.delete_dir_or_file(self.request_params["path"])
                os.makedirs(f"data/{self.user.username}", exist_ok=True)
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-type", "text/html")
                self.send_header("Content-Length", str(0))
                self.end_headers()
            except FileNotFoundError:
                self.send_error(HTTPStatus.NOT_FOUND, "File or directory not exists")
            except Exception:
                self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR)

    def extract_boundary(self, content_type):
        # 检查是否为multipart/form-data
        if "multipart/form-data" not in content_type:
            raise ValueError("Invalid content-type: %s" % content_type)

        # 分割头部以获取各个部分
        parts = content_type.split(";")
        # 遍历部分以查找boundary
        for part in parts:
            if "boundary=" in part:
                # 去除可能的空格，然后分割以获取boundary值
                boundary = part.strip().split("=")[1]
                return boundary
        raise ValueError("Invalid content-type: missing boundary")

    def parse_multipart(self, body, boundary):
        # 将边界标识符添加到前后，以正确分割数据
        boundary = "--" + boundary

        # 分割原始请求体
        parts = body.split(boundary)

        for part in parts:
            if "Content-Disposition" in part:
                # 分割头部和数据
                headers, content = part.split("\r\n\r\n", 1)
                headers = headers.strip()
                content = content.rstrip("\r\n")

                # 提取Content-Disposition头部
                disposition = [
                    h
                    for h in headers.split("\r\n")
                    if h.startswith("Content-Disposition")
                ][0]

                # 提取文件名（如果存在）
                if "filename=" in disposition:
                    filename = disposition.split("filename=")[1].strip('"')
                else:
                    filename = None

                yield filename, content

    def handle_authentication(self):
        # 添加处理验证的逻辑
        pass


class FileSystem:
    def __init__(self, root):
        self.root = root

    def is_file(self, path):
        filepath = os.path.join(self.root, path.lstrip("/"))
        return os.path.isfile(filepath)

    def is_dir(self, path):
        dirpath = os.path.join(self.root, path.lstrip("/"))
        return os.path.isdir(dirpath)

    def exists(self, path):
        filepath = os.path.join(self.root, path.lstrip("/"))
        return os.path.exists(filepath)

    def is_same_path(self, path1, path2):
        filepath1 = os.path.join(self.root, path1.lstrip("/"))
        filepath2 = os.path.join(self.root, path2.lstrip("/"))
        return os.path.samefile(filepath1, filepath2)

    def get_file(self, path):
        filepath = os.path.join(self.root, path.lstrip("/"))
        if not os.path.exists(filepath):
            raise FileNotFoundError
        size = os.path.getsize(filepath)
        mimetype = mimetypes.guess_type(filepath)[0]
        with open(filepath, "rb") as file:
            content = file.read()
        return size, mimetype, content

    def save_file(self, path, content):
        filepath = os.path.join(self.root, path.lstrip("/"))
        directory = os.path.dirname(filepath)
        if not os.path.exists(directory):
            os.makedirs(directory, exist_ok=True)
        with open(filepath, "wb") as file:
            file.write(content.encode())

    def delete_dir_or_file(self, path):
        path = os.path.join(self.root, path.lstrip("/"))
        if not os.path.exists(path):
            raise FileNotFoundError
        if os.path.isdir(path):
            # 遍历目录
            for root, dirs, files in os.walk(path, topdown=False):
                # 删除所有文件
                for file in files:
                    os.remove(os.path.join(root, file))
                # 删除所有子目录
                for dir in dirs:
                    os.rmdir(os.path.join(root, dir))

            # 删除目录本身
            os.rmdir(path)
        else:
            os.remove(path)

    def delete_directory(self, path):
        dirpath = os.path.join(self.root, path.lstrip("/"))
        if not os.path.exists(dirpath):
            raise FileNotFoundError
        if not os.path.isdir(dirpath):
            raise NotADirectoryError
        os.rmdir(dirpath)
        os.makedirs(dirpath, exist_ok=True)

    def delete_file(self, path):
        filepath = os.path.join(self.root, path.lstrip("/"))
        if not os.path.exists(filepath):
            raise FileNotFoundError
        if not os.path.isfile(filepath):
            raise IsADirectoryError
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
        # TODO: 处理长连接 - 一个tcp连接可以处理多个http请求
        httpRequestHandler.handle_request()
    finally:
        connection.shutdown(socket.SHUT_WR)
        connection.close()
        threads.remove(threading.current_thread())


# 运行服务器
threads = []


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
                threads.append(thread)
            except socket.timeout:
                pass


# 信号处理函数
def signal_handler(signum, frame):
    print("Interrupt received, shutting down the server")
    # 这里可以添加任何清理代码
    for thread in threads:
        thread.join()
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
