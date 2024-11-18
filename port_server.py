import argparse
import socket
import ssl
import asyncio
import logging
import bcrypt
import json
from concurrent.futures import ThreadPoolExecutor
from logging.handlers import RotatingFileHandler
from functools import partial

logging.basicConfig(
    level=logging.INFO,
    handlers=[RotatingFileHandler("server.log", maxBytes=5 * 1024 * 1024, backupCount=2)],
    format="%(asctime)s - %(levelname)s - %(message)s"
)

COMMANDS = {
    "echo": lambda data: data,
    "upper": lambda data: data.upper(),
    "lower": lambda data: data.lower(),
    "reverse": lambda data: data[::-1],
    "math": lambda data: str(eval(data))  # Dangerous without sanitization
}

class SecureServer:
    def __init__(self, port, certfile, keyfile, max_workers=10, passphrase_hash=None):
        self.port = port
        self.certfile = certfile
        self.keyfile = keyfile
        self.ssl_context = self.create_ssl_context()
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self.passphrase_hash = passphrase_hash

    def create_ssl_context(self):
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(self.certfile, self.keyfile)
        return context

    async def handle_client(self, ssl_socket, client_address):
        logging.info(f"Connected to {client_address}")
        try:
            await ssl_socket.sendall(b"Enter passphrase: ")
            passphrase = await asyncio.wait_for(ssl_socket.recv(1024), timeout=10)
            
            if not bcrypt.checkpw(passphrase.strip(), self.passphrase_hash):
                await ssl_socket.sendall(b"Invalid passphrase!")
                logging.warning(f"Invalid passphrase from {client_address}")
                return

            await ssl_socket.sendall(b"Passphrase accepted. Welcome!")
            session_commands = []

            while True:
                await ssl_socket.sendall(b"Enter command: ")
                data = await asyncio.wait_for(ssl_socket.recv(1024), timeout=10)
                if not data:
                    break

                command_data = data.decode().strip()
                if command_data.lower() == "quit":
                    break
                elif command_data.lower() == "history":
                    response = "\n".join(session_commands).encode()
                else:
                    session_commands.append(command_data)
                    response = self.process_command(command_data).encode()

                await ssl_socket.sendall(response)
        except asyncio.TimeoutError:
            logging.warning(f"Client {client_address} timed out.")
        except Exception as e:
            logging.error(f"Error handling client {client_address}: {e}")
        finally:
            ssl_socket.close()
            logging.info(f"Connection closed for {client_address}")

    def process_command(self, data):
        try:
            command, *args = data.split()
            if command in COMMANDS:
                return COMMANDS[command](" ".join(args))
            return "Unknown command"
        except Exception as e:
            return f"Error processing command: {e}"

    async def start_server(self):
        server_socket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind(("::", self.port))  # IPv6 Support
        server_socket.listen()

        logging.info(f"Server listening on port {self.port}...")

        loop = asyncio.get_event_loop()
        try:
            while True:
                client_socket, client_address = await loop.run_in_executor(self.executor, server_socket.accept)
                ssl_socket = self.ssl_context.wrap_socket(client_socket, server_side=True)
                asyncio.create_task(self.handle_client(ssl_socket, client_address))
        except KeyboardInterrupt:
            logging.info("Server shutdown initiated...")
        finally:
            server_socket.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Secure TCP Server")
    parser.add_argument("--port", required=True, type=int, help="Port number to listen on")
    parser.add_argument("--certfile", required=True, help="Path to SSL certificate file")
    parser.add_argument("--keyfile", required=True, help="Path to SSL private key file")
    parser.add_argument("--passphrase", required=True, help="Server passphrase")
    args = parser.parse_args()

    hashed_passphrase = bcrypt.hashpw(args.passphrase.encode(), bcrypt.gensalt())

    server = SecureServer(args.port, args.certfile, args.keyfile, passphrase_hash=hashed_passphrase)
    try:
        asyncio.run(server.start_server())
    except KeyboardInterrupt:
        logging.info("Server stopped.")
