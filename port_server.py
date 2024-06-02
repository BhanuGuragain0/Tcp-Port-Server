import argparse
import socket
import ssl
import asyncio
import logging
import configparser
from concurrent.futures import ThreadPoolExecutor

logging.basicConfig(level=logging.INFO)

COMMANDS = {
    "echo": lambda data: data,
    "upper": lambda data: data.upper(),
    "lower": lambda data: data.lower(),
    "reverse": lambda data: data[::-1]
}

def process_command(data):
    command, *args = data.decode().split()
    if command in COMMANDS:
        response = COMMANDS[command](b' '.join(args))
    else:
        logging.warning(f'Unknown command: {command}')
        response = b'Unknown command'
    return response

def create_ssl_context(certfile, keyfile):
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile, keyfile)
    return context

async def handle_client(ssl_socket, client_address):
    local_address, local_port = ssl_socket.getsockname()
    foreign_address, foreign_port = ssl_socket.getpeername()
    logging.info(f'Connected to {client_address} from {foreign_address}:{foreign_port}, using local address {local_address}:{local_port}')
    try:
        await ssl_socket.sendall(b'Enter passphrase: ')
        passphrase = await asyncio.wait_for(ssl_socket.recv(1024), timeout=10)
        if passphrase.strip() != b'mypassword':
            await ssl_socket.sendall(b'Invalid passphrase!')
            logging.warning(f'Invalid passphrase from {client_address}')
            return
        await ssl_socket.sendall(b'Passphrase accepted. You are authenticated.')
        while True:
            data = await asyncio.wait_for(ssl_socket.recv(1024), timeout=10)
            if not data:
                break
            elif data.decode().lower() == 'quit':
                break
            else:
                logging.info(f'Received data from {client_address}: {data.decode()}')
                response = process_command(data)
                await ssl_socket.sendall(response)
    except asyncio.TimeoutError:
        logging.error(f'Client {client_address} timed out.')
    except ssl.SSLError as e:
        logging.error(f'SSL error with client {client_address}: {e}')
    except asyncio.CancelledError:
        logging.info(f'Client handler task was cancelled for {client_address}')
    except Exception as e:
        logging.error(f'Error handling client {client_address}: {e}')
    finally:
        ssl_socket.close()

async def start_port_server(port, certfile, keyfile, max_workers=10):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(('0.0.0.0', port))
    server_socket.listen()

    ssl_context = create_ssl_context(certfile, keyfile)

    logging.info(f'Port server listening on port {port}...')

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        loop = asyncio.get_event_loop()
        tasks = []

        try:
            while True:
                client_socket, client_address = await loop.run_in_executor(executor, server_socket.accept)
                ssl_socket = ssl_context.wrap_socket(client_socket, server_side=True)
                task = asyncio.create_task(handle_client(ssl_socket, client_address))
                tasks.append(task)
        except asyncio.CancelledError:
            logging.info("Server has been cancelled.")
        except KeyboardInterrupt:
            logging.info("Shutting down server...")
        except Exception as e:
            logging.error(f'Error accepting connection: {e}')
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            server_socket.close()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Secure TCP Server')
    parser.add_argument('--port', help='Port number to listen on', required=True, type=int)
    parser.add_argument('--certfile', help='Path to the certificate file', required=True)
    parser.add_argument('--keyfile', help='Path to the private key file', required=True)
    parser.add_argument('--config', help='Path to configuration file (optional)', default='server.ini')
    parser.add_argument('--max-workers', help='Maximum number of worker threads for handling connections', type=int, default=10)
    args = parser.parse_args()

    config = configparser.ConfigParser()
    config.read(args.config)

    if not (0 <= args.port <= 65535):
        print("Invalid port number provided. Please use a port between 0 and 65535.")
        exit(1)

    try:
        asyncio.run(start_port_server(args.port, args.certfile, args.keyfile, max_workers=args.max_workers))
    except KeyboardInterrupt:
        logging.info("Server was manually stopped.")
