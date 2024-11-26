import argparse
import socket
import ssl
import asyncio
import logging
import bcrypt
import json
from concurrent.futures import ThreadPoolExecutor
from logging.handlers import RotatingFileHandler
from sympy import sympify, SympifyError

# Configure logging
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
    "math": lambda data: str(sympify(data)),  # Safe math evaluation using sympy
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
            await self.send_message(ssl_socket, "Enter passphrase: ")
            passphrase = await self.receive_message(ssl_socket)
            if not bcrypt.checkpw(passphrase.encode(), self.passphrase_hash):
                await self.send_message(ssl_socket, "Invalid passphrase!")
                logging.warning(f"Invalid passphrase from {client_address}")
                return

            await self.send_message(ssl_socket, "Passphrase accepted. Welcome!")
            session_commands = []

            while True:
                await self.send_message(ssl_socket, "Enter command: ")
                command_data = await self.receive_message(ssl_socket)
                if not command_data:
                    break

                if command_data.lower() == "quit":
                    await self.send_message(ssl_socket, "Goodbye!")
                    break
                elif command_data.lower() == "history":
                    response = "\n".join(session_commands)
                else:
                    session_commands.append(command_data)
                    response = self.process_command(command_data)

                await self.send_message(ssl_socket, response)
        except asyncio.TimeoutError:
            logging.warning(f"Client {client_address} timed out.")
        except Exception as e:
            logging.error(f"Error handling client {client_address}: {e}")
        finally:
            ssl_socket.close()
            logging.info(f"Connection closed for {client_address}")

    async def send_message(self, ssl_socket, message):
        ssl_socket.sendall(message.encode() + b"\n")

    async def receive_message(self, ssl_socket, buffer_size=1024):
        data = ssl_socket.recv(buffer_size).decode().strip()
        return data

    def process_command(self, data):
        try:
            command, *args = data.split()
            if command in COMMANDS:
                return json.dumps({"result": COMMANDS[command](" ".join(args))})
            return json.dumps({"error": "Unknown command"})
        except SympifyError:
            return json.dumps({"error": "Invalid mathematical expression"})
        except Exception as e:
            return json.dumps({"error": f"Error processing command: {e}"})

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
        except Exception as e:
            logging.error(f"Server encountered an error: {e}")
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
