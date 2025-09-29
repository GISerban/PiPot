# Used resources:
# https://devsjc.github.io/blog/20240627-the-complete-guide-to-pyproject-toml/
# https://github.com/collinsmc23/ssh_honeypy/blob/main/main.py
# https://securehoney.net/blog/how-to-build-an-ssh-honeypot-in-python-and-docker-part-1.html

# Suppressing deprecation warnings from paramiko dependency
import warnings
from cryptography.utils import CryptographyDeprecationWarning

warnings.simplefilter("ignore", category=CryptographyDeprecationWarning)
from time import sleep
import paramiko
from paramiko.common import (
    AUTH_SUCCESSFUL,
    AUTH_PARTIALLY_SUCCESSFUL,
    AUTH_FAILED,
    OPEN_SUCCEEDED,
    OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED,
)
import logging
import threading
from logging.handlers import RotatingFileHandler
import socket
import argparse
import os
import json
import urllib.request
import urllib.error
from typing import Optional

# Constants
BYTE_STRING_ASCII_CONTROL_C = b"\x03"
BYTE_STRING_ASCII_CONTROL_D = b"\x04"
BYTE_STRING_ASCII_BACKSPACE = b"\x7f"
BYTE_STRING_ASCII_ESCAPE = b"\x1b"
BYTE_STRING_ASCII_UP_ARROW = b"[A"
BYTE_STRING_ASCII_TAB = b"\t"
BYTE_STRING_ASCII_ENTER = b"\r"
MAX_FILE_SIZE_BYTES = 2000
MAX_CONCURRENT_CONNECTIONS = 100
SSH_BANNER = "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1"
SSH_USERNAME = "user"
SSH_STANDARD_BANNER = f"Welcome to Ubuntu 20.04.2 LTS (GNU/Linux 5.4.0-80-generic x86_64) ({SSH_USERNAME})!\r\n"
SSH_HOSTNAME = "honeypot"
SSH_SESSION_PREFIX = f"{SSH_USERNAME}@{SSH_HOSTNAME}:~$ "
SSH_CURRENT_DIRECTORY_FILE1 = f"{SSH_HOSTNAME}.conf"
SSH_CURRENT_DIRECTORY_LIST_FILES = SSH_CURRENT_DIRECTORY_FILE1
# Ssh host key (generated with ssh-keygen -t rsa -b 2048 -f server.key)
HOST_KEY = paramiko.RSAKey(filename="./server.key")
# Logging format
LOGGING_FORMAT = logging.Formatter("%(asctime)s - %(message)s")

# General logger
credentials_logger = logging.getLogger("GeneralLogger")
credentials_logger.setLevel(logging.INFO)
# maximum logging file size is about to be exceeded => rotating file handler will open a new one
credentials_logger_handler = RotatingFileHandler(
    "/data/credentials.log", maxBytes=MAX_FILE_SIZE_BYTES, backupCount=5
)
credentials_logger_handler.setFormatter(LOGGING_FORMAT)
credentials_logger.addHandler(credentials_logger_handler)

command_logger = logging.getLogger("CommandLogger")
command_logger.setLevel(logging.INFO)
command_logger_handler = RotatingFileHandler(
    "/data/commands.log", maxBytes=MAX_FILE_SIZE_BYTES, backupCount=5
)
command_logger_handler.setFormatter(LOGGING_FORMAT)
command_logger.addHandler(command_logger_handler)


class SshHoneypotServer(paramiko.ServerInterface):
    def __init__(self, client_ip, input_username=None, input_password=None):
        self.event = threading.Event()
        self.client_ip = client_ip
        self.input_username = input_username
        self.input_password = input_password

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return OPEN_SUCCEEDED
        return OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def get_allowed_auths(self, username: str) -> str:
        return "password"

    def check_auth_password(self, username, password):
        credentials_logger.info(
            f"Trying to authenticate {username} with password {password} from {self.client_ip}"
        )
        return AUTH_SUCCESSFUL

    def check_channel_shell_request(self, channel) -> bool:
        self.event.set()
        return True

    def check_channel_pty_request(
        self, channel, term, width, height, pixelwidth, pixelheight, modes
    ) -> bool:
        return True

    def check_channel_exec_request(self, channel, command) -> bool:
        command = str(command)
        return True


def emulated_shell(channel, client_ip_address):
    command_buffer = b""
    command_history = []
    command_history_index = -1

    channel.send(str.encode(SSH_SESSION_PREFIX))
    while True:
        char = channel.recv(1)
        # ctrl + c
        if char == BYTE_STRING_ASCII_CONTROL_C:
            command_logger.info("Ctrl + C pressed")
            channel.send(b"\r\n")
            channel.send(str.encode(SSH_SESSION_PREFIX))
            command_buffer = b""
        # ctrl + d
        elif char == BYTE_STRING_ASCII_CONTROL_D:
            command_logger.info("Ctrl + D pressed")
            channel.send(b"\r\n")
            channel.send("Goodbye!\r\n")
            channel.close()
            break
        # backspace
        elif char == BYTE_STRING_ASCII_BACKSPACE:
            command_logger.info("Backspace pressed")
            if len(command_buffer) > 0:
                command_buffer = command_buffer[:-1]
                channel.send(b'\x08 \x08')
        # escape
        elif char == BYTE_STRING_ASCII_ESCAPE:
            next_characters = channel.recv(2)
            if next_characters == BYTE_STRING_ASCII_UP_ARROW:
                if command_history and command_history_index < len(command_history) - 1:
                    channel.send(b'\r' + b' ' * (len(SSH_SESSION_PREFIX) + len(command_buffer)) + b'\r')
                    command_history_index += 1
                    history_command = command_history[-(command_history_index + 1)]
                    channel.send(str.encode(SSH_SESSION_PREFIX + history_command))
                    command_buffer = str.encode(history_command)
        elif char == BYTE_STRING_ASCII_TAB:
            # TODO: Implement tab completion
            command_logger.info("Tab pressed")
            channel.send(b"\r\nNot implemented yet...\r\n")
            channel.send(str.encode(SSH_SESSION_PREFIX))
        # enter
        elif char == BYTE_STRING_ASCII_ENTER:
            channel.send(b"\r\n")
            command_string = command_buffer.strip().decode("utf-8")

            if command_string:
                # command_history.insert(0, command_string)
                command_history.append(command_string)
                command_history_index = -1
                command_logger.info(f"Command received from {client_ip_address}: {command_string}")

                response = b""
                match command_string:
                    case "exit":
                        channel.close()
                        return
                    # case "pwd":
                    #     response += str.encode(f"/home/{SSH_USERNAME}")
                    case "whoami":
                        response += str.encode(SSH_USERNAME)
                    # case "ls":
                    #     response += str.encode(SSH_CURRENT_DIRECTORY_LIST_FILES)
                    # case "cat honeypot.conf":
                    #     response += b"caught your ass"
                    case _:
                        response += str.encode(stream_llm_response(command_string))

                channel.send(response + b"\r\n")

            channel.send(str.encode(SSH_SESSION_PREFIX))
            command_buffer = b""
        else:
            command_buffer += char
            channel.send(char)


def handle_client(client, address, username, password):
    client_ip_address = address[0]
    print(f"Connection from {client_ip_address}")

    try:
        # Initialize transport channel -> encrypt session, authenticate
        transport = paramiko.Transport(client)
        transport.local_version = SSH_BANNER
        print("Starting transport")
        server = SshHoneypotServer(client_ip_address, username, password)
        print("Created server")
        transport.add_server_key(HOST_KEY)
        transport.start_server(server=server)

        # Establish encrypted tunnel for bidirectional communication
        channel = transport.accept(MAX_CONCURRENT_CONNECTIONS)

        if channel is None:
            print("No channel was opened.")
            return
        try:
            SSH_USERNAME = username
            SSH_STANDARD_BANNER = f"Welcome to Ubuntu 20.04.2 LTS (GNU/Linux 5.4.0-80-generic x86_64) ({SSH_USERNAME})!\r\n"
            channel.send(str.encode(SSH_STANDARD_BANNER + '\n'))
            emulated_shell(channel, client_ip_address)
        except Exception as error:
            print(error)
    except Exception as error:
        print(error)
    # close transport connection
    finally:
        try:
            transport.close()
        except Exception:
            pass
        client.close()


def start_honeypot(address, port, username, password):
    # Open TCP socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((address, port))

    server_socket.listen(MAX_CONCURRENT_CONNECTIONS)
    print(f"Server is listening on port {port}.")

    while True:
        try:
            client, address = server_socket.accept()
            print(f"Connection from {address}")
            threading.Thread(
                target=handle_client, args=(client, address, username, password)
            ).start()
        except Exception as error:
            print(f"Error accepting connection: {error}")
            continue


def main():
    # resp = stream_llm_response("ls -la")
    # print("LLM response:", resp)
    parser = argparse.ArgumentParser(description="SSH Honeypot")
    parser.add_argument("-a", "--address", type=str, default="0.0.0.0")
    parser.add_argument("-p", "--port", type=int, default=2222)
    parser.add_argument("-u", "--username", type=str, default="root")
    parser.add_argument("-pw", "--password", type=str, default="root")
    arguments = parser.parse_args()
    start_honeypot(
        arguments.address, arguments.port, arguments.username, arguments.password
    )


def stream_llm_response(prompt: str, model: str = "ssh-llama", timeout: int = 30) -> str:
    """
    Send `prompt` to the LLM backend and block until the full streamed response is received.
    Returns the concatenated 'response' fields from each NDJSON line.
    """
    import os
    import json

    backend = os.environ.get("LLM_BACKEND", "http://100.105.46.22:11434/api/generate").rstrip("/")
    if "/api/" in backend:
        url = backend
    else:
        url = f"{backend}/api/generate"

    payload = {"model": model, "prompt": prompt}

    try:
        import requests
    except Exception:
        requests = None

    try:
        resp = requests.post(url, json=payload, timeout=timeout, stream=True, headers={"Accept": "application/x-ndjson, application/json"})
    except Exception as e:
        return f"Error: {e}"

    if not resp.ok:
        # try to read body for error details
        try:
            text = resp.text
        except Exception:
            text = ""
        return f"HTTPError {resp.status_code}: {text}"

    aggregated = ""
    try:
        for line in resp.iter_lines(decode_unicode=True):
            if not line:
                continue
            try:
                obj = json.loads(line)
            except Exception:
                # ignore non-json lines
                continue
            chunk = obj.get("response")
            done = obj.get("done", False)
            if chunk:
                aggregated += str(chunk)
            if done:
                break
    except Exception as e:
        return f"Error while streaming: {e}"
    finally:
        try:
            resp.close()
        except Exception:
            pass

    return aggregated

if __name__ == "__main__":
    main()
    # resp = stream_llm_response("ls")
    # print("LLM response:", resp)