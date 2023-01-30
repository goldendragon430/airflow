import socket
import sys
import http.client
from typing import List


def run_socket(host: str, port: int, buffers: List[str]):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect_ex((host, port))
    if result == 0:
        sock.settimeout(1.0)
        for buffer in buffers:
            sock.send(f'{buffer}'.encode())
        res = sock.recv(1024)
    else:
        res = None
    sock.close()
    return res


def check_data(text: str, data: str):
    return "+ -- --=[Site vulnerable to Cross-Site Tracing!" if text.lower() in data.decode("utf-8", "ignore").lower() else "+ -- --=[Site not vulnerable to Cross-Site Tracing!"


def main(argv):
    argc = len(argv)

    if argc <= 2:
        print("usage: must supply <host> <port>")
        sys.exit(0)

    else:
        host, port = argv[1], int(argv[2])

        if port == 443:
            print("Using HTTPS")
            headers = {
                'User-Agent': 'XSS Tracer v1.3 by 1N3 @ https://crowdshield.com',
                'Content-Type': 'application/x-www-form-urlencoded'
            }

            conn = http.client.HTTPSConnection(host)
            conn.request("GET", "/", "", headers)
            response = conn.getresponse()
            data = response.read()

            print(f'Response: {response.status}, {response.reason}')
            print(f'Data: {data.decode("utf-8", "ignore").lower()}')
        else:
            buffers = ["TRACE / HTTP/1.1\n",
                       "Test: <script>alert(1);</script>\n",
                       f'Host: {host}\n\n']
            data = run_socket(host, port, buffers)
            res = check_data("alert", data)
            print(res)

            buffers = ["GET / HTTP/1.1\n", "Host: http://crowdshield.com\n\n"]
            data = run_socket(host, port, buffers)
            res = check_data("crowdshield", data)
            print(res)

            # TEST FOR CLICKJACKING AND CFS
            buffers = ["GET / HTTP/1.1\n", f'Host: {host}\n\n']
            data = run_socket(host, port, buffers)
            res = check_data("X-Frame-Options", data)
            print(res)


main(sys.argv)
