import base64
import json
import os
import secrets
import string
import threading
import paramiko
from io import BytesIO
import sys

import RSAEncryption as rsa
import bittensor as bt

class FakeSSHServer(paramiko.ServerInterface):
    def __init__(self, expected_password, allowed_key):
        self.event = threading.Event()
        self.expected_password = expected_password
        self.allowed_keys = set()
        if allowed_key:
            self.allowed_keys.add(paramiko.RSAKey(data=allowed_key.encode("utf-8")))
        self.running = True

    def check_auth_password(self, username, password):
        if password == self.expected_password:
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        if key in self.allowed_keys:
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password,publickey"

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def add_ssh_key(self, new_key):
        try:
            rsa_key = paramiko.RSAKey(data=new_key.encode("utf-8"))
            self.allowed_keys.add(rsa_key)
            return True
        except Exception as e:
            bt.logging.info(f"Error adding SSH key: {e}")
            return False

    def terminate(self):
        self.running = False

fake_ssh_server = None

def get_docker():
    global fake_ssh_server
    if fake_ssh_server:
        return fake_ssh_server, [fake_ssh_server]
    return None, []

def kill_container():
    global fake_ssh_server
    if fake_ssh_server:
        fake_ssh_server.terminate()
        fake_ssh_server = None
        bt.logging.info("SSH server was terminated successfully.")
        return True
    bt.logging.info("No running SSH server found.")
    return False


def check_container():
    global fake_ssh_server
    return fake_ssh_server is not None


def run_container(cpu_usage, ram_usage, hard_disk_usage, gpu_usage, public_key, docker_requirement: dict):
    global fake_ssh_server
    try:
        if fake_ssh_server:
            bt.logging.info("SSH server is already running.")
            return {"status": False, "info": "SSH server already running."}

        password = password_generator(10)
        ssh_key = docker_requirement.get("ssh_key")
        ssh_port = docker_requirement.get("ssh_port")

        bt.logging.info("Container was created successfully.")
        info = {"username": "root", "password": password, "port": ssh_port}
        info_str = json.dumps(info)
        public_key = public_key.encode("utf-8")
        encrypted_info = rsa.encrypt_data(public_key, info_str)
        encrypted_info = base64.b64encode(encrypted_info).decode("utf-8")

        def start_fake_ssh_server(server_instance, port):
            import socket

            def run_server():
                host = "0.0.0.0"
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind((host, port))
                sock.listen(5)

                bt.logging.info(f"SSH server listening on port {port}")
                while server_instance.running:
                    try:
                        client, addr = sock.accept()
                        bt.logging.info(f"Connection from {addr}")
                        transport = paramiko.Transport(client)
                        transport.add_server_key(paramiko.RSAKey.generate(2048))
                        transport.start_server(server=server_instance)
                        channel = transport.accept(20)
                        if channel is None:
                            continue
                        server_instance.event.wait(10)
                        if not server_instance.event.is_set():
                            channel.close()
                    except Exception as e:
                        bt.logging.info(f"Error in SSH server: {e}")
                    finally:
                        client.close()

                sock.close()

            thread = threading.Thread(target=run_server, daemon=True)
            thread.start()

        fake_ssh_server = FakeSSHServer(expected_password=password, allowed_key=ssh_key)

        start_fake_ssh_server(fake_ssh_server, ssh_port)

        file_path = 'allocation_key'
        allocation_key = base64.b64encode(public_key).decode("utf-8")
        with open(file_path, 'w') as file:
            file.write(allocation_key)

        return {
            "status": True,
            "info": encrypted_info,
        }
    except Exception as e:
        bt.logging.info(f"Error running SSH server: {e}")
        return {"status": False}


def password_generator(length):
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def restart_container():
    global fake_ssh_server
    try:
        if fake_ssh_server:
            if fake_ssh_server.running:
                return {"status": True}
            else:
                bt.logging.info("SSH server is not running.")
                return {"status": False}
        else:
            bt.logging.info("No running SSH server to restart.")
            return {"status": False}
    except Exception as e:
        bt.logging.info(f"Error restarting SSH server: {e}")
        return {"status": False}


def pause_container():
    global fake_ssh_server
    if fake_ssh_server and fake_ssh_server.running:
        fake_ssh_server.running = False
        bt.logging.info("SSH server is now paused.")
        return {"status": True}
    bt.logging.info("No running SSH server to pause.")
    return {"status": False}


def unpause_container():
    global fake_ssh_server
    if fake_ssh_server and not fake_ssh_server.running:
        fake_ssh_server.running = True
        bt.logging.info("SSH server has resumed.")
        return {"status": True}
    bt.logging.info("No paused SSH server to resume.")
    return {"status": False}


def exchange_key_container(new_ssh_key: str):
    global fake_ssh_server
    if fake_ssh_server and fake_ssh_server.running:
        success = fake_ssh_server.add_ssh_key(new_ssh_key)
        if success:
            bt.logging.info("New SSH key added successfully.")
            return {"status": True}
        bt.logging.info("Failed to add new SSH key.")
        return {"status": False}
    bt.logging.info("No running SSH server to update keys.")
    return {"status": False}