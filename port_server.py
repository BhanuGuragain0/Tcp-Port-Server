import argparse
import socket
import ssl
import asyncio
import logging
import bcrypt
import json
import time
from concurrent.futures import ThreadPoolExecutor
from logging.handlers import RotatingFileHandler
from sympy import sympify, SympifyError
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    handlers=[RotatingFileHandler("server.log", maxBytes=5 * 1024 * 1024, backupCount=2)],
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# Supported commands
COMMANDS = {
    "echo": lambda data: data,
    "upper": lambda data: data.upper(),
    "lower": lambda data: data.lower(),
    "reverse": lambda data: data[::-1],
    "math": lambda data: str(sympify(data)),  # Safe math evaluation using sympy
    "time": lambda _: time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
    "stats": lambda session: f"Commands executed: {len(session['commands'])}",
    "encrypt": lambda data: SecureServer.encrypt_data(data),
    "decrypt": lambda data: SecureServer.decrypt_data(data),
    "help": lambda _: "\n".join([f"{cmd}: {func.__doc__}" for cmd, func in COMMANDS.items()]),
    "clear": lambda _: "",  # Clear session history
}

class SecureServer:
    """
    A secure TCP server that handles client connections using SSL and provides various commands.
    """

    def __init__(self, port, certfile, keyfile, max_workers=10, passphrase_hash=None):
        """
        Initialize the server.

        Args:
            port (int): Port number to listen on.
            certfile (str): Path to SSL certificate file.
            keyfile (str): Path to SSL private key file.
            max_workers (int): Maximum number of worker threads.
            passphrase_hash (bytes): Hashed passphrase for client authentication.
        """
        self.port = port
        self.certfile = certfile
        self.keyfile = keyfile
        self.ssl_context = self.create_ssl_context()
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self.passphrase_hash = passphrase_hash
        self.sessions = {}  # Track client sessions

    def create_ssl_context(self):
        """
        Create and configure the SSL context.

        Returns:
            ssl.SSLContext: Configured SSL context.
        """
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(self.certfile, self.keyfile)
        return context

    @staticmethod
    def encrypt_data(data):
        """
        Encrypt data using AES.

        Args:
            data (str): Data to encrypt.

        Returns:
            str: Encrypted data in hex format.
        """
        key = get_random_bytes(16)  # 128-bit key
        cipher = AES.new(key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(data.encode(), AES.block_size))
        return json.dumps({"key": key.hex(), "iv": cipher.iv.hex(), "ciphertext": ct_bytes.hex()})

    @staticmethod
    def decrypt_data(data):
        """
        Decrypt data using AES.

        Args:
            data (str): Encrypted data in hex format.

        Returns:
            str: Decrypted data.
        """
        try:
            data = json.loads(data)
            key = bytes.fromhex(data["key"])
            iv = bytes.fromhex(data["iv"])
            ciphertext = bytes.fromhex(data["ciphertext"])
            cipher = AES.new(key, AES.MODE_CBC, iv)
            pt = unpad(cipher.decrypt(ciphertext), AES.block_size)
            return pt.decode()
        except Exception as e:
            return f"Decryption failed: {e}"

    async def handle_client(self, ssl_socket, client_address):
        """
        Handle a client connection.

        Args:
            ssl_socket (ssl.SSLSocket): SSL-wrapped socket for the client.
            client_address (tuple): Client address (host, port).
        """
        logging.info(f"Connected to {client_address}")
        session = {"commands": [], "start_time": time.time()}
        self.sessions[client_address] = session

        try:
            await self.send_message(ssl_socket, "Enter passphrase: ")
            passphrase = await self.receive_message(ssl_socket)
            if not bcrypt.checkpw(passphrase.encode(), self.passphrase_hash):
                await self.send_message(ssl_socket, "Invalid passphrase!")
                logging.warning(f"Invalid passphrase from {client_address}")
                return

            await self.send_message(ssl_socket, "Passphrase accepted. Welcome!")

            while True:
                await self.send_message(ssl_socket, "Enter command: ")
                command_data = await self.receive_message(ssl_socket)
                if not command_data:
                    break

                if command_data.lower() == "quit":
                    await self.send_message(ssl_socket, "Goodbye!")
                    break
                elif command_data.lower() == "history":
                    response = "\n".join(session["commands"])
                else:
                    session["commands"].append(command_data)
                    response = self.process_command(command_data, session)

                await self.send_message(ssl_socket, response)
        except asyncio.TimeoutError:
            logging.warning(f"Client {client_address} timed out.")
        except Exception as e:
            logging.error(f"Error handling client {client_address}: {e}")
        finally:
            ssl_socket.close()
            del self.sessions[client_address]
            logging.info(f"Connection closed for {client_address}")

    async def send_message(self, ssl_socket, message):
        """
        Send a message to the client.

        Args:
            ssl_socket (ssl.SSLSocket): SSL-wrapped socket for the client.
            message (str): Message to send.
        """
        ssl_socket.sendall(message.encode() + b"\n")

    async def receive_message(self, ssl_socket, buffer_size=1024):
        """
        Receive a message from the client.

        Args:
            ssl_socket (ssl.SSLSocket): SSL-wrapped socket for the client.
            buffer_size (int): Buffer size for receiving data.

        Returns:
            str: Received message.
        """
        data = ssl_socket.recv(buffer_size).decode().strip()
        return data

    def process_command(self, data, session):
        """
        Process a client command.

        Args:
            data (str): Command and arguments.
            session (dict): Client session data.

        Returns:
            str: JSON-encoded response.
        """
        try:
            command, *args = data.split()
            if command in COMMANDS:
                return json.dumps({"result": COMMANDS[command](" ".join(args) if command != "stats" else session)})
            return json.dumps({"error": "Unknown command"})
        except SympifyError:
            return json.dumps({"error": "Invalid mathematical expression"})
        except Exception as e:
            return json.dumps({"error": f"Error processing command: {e}"})

    async def start_server(self):
        """
        Start the server and listen for client connections.
        """
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
