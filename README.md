# Secure TCP Port Server Python

This repository contains an enhanced version of a secure TCP server implemented in Python. The server provides a secure communication channel over SSL/TLS encryption and supports asynchronous handling of client connections using asyncio.

## Features

- **SSL/TLS Encryption**: Ensures secure communication between the server and clients.
- **Asynchronous Handling**: Handles multiple client connections concurrently without blocking.
- **Custom Commands**: Supports custom commands for data manipulation.
- **Error Handling and Logging**: Provides informative logging and error handling for various scenarios.
- **Configuration File Support**: Allows users to configure server settings via a configuration file.
- **Maximum Worker Threads**: Configurable option for controlling the maximum number of worker threads for handling connections.



1. **Running the Server**:

`python port_server.py --port <PORT> --certfile CERTFILE --keyfile <KEYFILE> --config <CONFIG_FILE> --max-workers <MAX_WORKERS>`
or
`python port_server.py --port <PORT> --certfile CERTFILE --keyfile <KEYFILE> --config <CONFIG_FILE>`


for checking kali linux --- `netstat -tuln`

In order to set up a secure connection (TLS/SSL), you need to have a valid SSL certificate and its corresponding private key. These files are typically provided by a Certificate Authority (CA) or can be self-signed for testing purposes.

If you don't have these files yet, you'll need to generate them or obtain them from a trusted source. Here's a brief overview of how you can generate self-signed SSL certificate and key pair using OpenSSL:

`openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365`

markdown


- Replace `PORT` with the desired port number to listen on.
- Replace `CERTFILE` with the path to the SSL/TLS certificate file.
- Replace `KEYFILE` with the path to the private key file.
- Optionally, specify a configuration file (`CONFIG_FILE`) for additional settings.
- Optionally, specify the maximum number of worker threads (`MAX_WORKERS`) for handling connections.

2. **Connect to the Server**:

Once the server is running, clients can connect to it using a secure TCP client. Ensure that clients use SSL/TLS encryption for secure communication.

## Configuration

The server configuration can be customized via the `server.ini` configuration file. Modify the settings in the configuration file as needed.

## Custom Commands

The server supports the following custom commands for data manipulation:

- `echo`: Echoes the input data back to the client.
- `upper`: Converts the input data to uppercase.
- `lower`: Converts the input data to lowercase.
- `reverse`: Reverses the input data.

To use a command, send the command followed by the data to the server.

## Contributing

Contributions to this project are welcome! If you have suggestions for improvements or new features, feel free to open an issue or submit a pull request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
