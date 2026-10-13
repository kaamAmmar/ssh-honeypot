import argparse
import json
import logging
import os
import socket
import threading
from datetime import datetime, timezone

import paramiko

KEY_FILE = "host_key"
BANNER = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.17"
LOG_FILE = "attempts.jsonl"

MAX_CONNECTIONS = 10
SESSION_TIMEOUT = 30
MAX_FIELD = 100

logging.getLogger("paramiko").setLevel(logging.CRITICAL)

log_lock = threading.Lock()
slots = threading.BoundedSemaphore(MAX_CONNECTIONS)


def load_host_key():
    if os.path.exists(KEY_FILE):
        return paramiko.RSAKey(filename=KEY_FILE)
    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(KEY_FILE)
    return key


def clean(text):
    return str(text)[:MAX_FIELD]


def log_attempt(ip, user, password):
    entry = {
        "time": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "ip": ip,
        "user": clean(user),
        "password": clean(password),
    }
    with log_lock:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")


class FakeServer(paramiko.ServerInterface):
    def __init__(self, ip):
        self.ip = ip

    def get_allowed_auths(self, username):
        return "password"

    def check_auth_password(self, username, password):
        print(f"tentative : user={clean(username)!r} "
              f"password={clean(password)!r}")
        log_attempt(self.ip, username, password)
        return paramiko.AUTH_FAILED


def handle_client(client, addr, host_key):
    transport = None
    try:
        transport = paramiko.Transport(client)
        transport.local_version = BANNER
        transport.add_server_key(host_key)
        transport.start_server(server=FakeServer(addr[0]))
        transport.join(SESSION_TIMEOUT)
    except Exception as e:
        print(f"negociation echouee : {clean(e)!r}")
    finally:
        if transport is not None:
            transport.close()
        client.close()
        slots.release()


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=2222)
    args = parser.parse_args()
    if args.host in ("0.0.0.0", "", "::"):
        raise SystemExit("refuse : ecoute interdite sur toutes les interfaces")
    return args


def main():
    args = parse_args()
    host_key = load_host_key()
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((args.host, args.port))
    server.listen(5)
    print(f"listening on {args.host}:{args.port}")
    try:
        while True:
            client, addr = server.accept()
            if not slots.acquire(blocking=False):
                client.close()
                print(f"refuse (trop de connexions) : {addr[0]}")
                continue
            print(f"connexion de {addr[0]}:{addr[1]}")
            threading.Thread(
                target=handle_client, args=(client, addr, host_key), daemon=True
            ).start()
    except KeyboardInterrupt:
        print("\narret du honeypot")
    finally:
        server.close()


if __name__ == "__main__":
    main()
