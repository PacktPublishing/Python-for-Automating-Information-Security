import argparse
import socket
import subprocess
import sys
import threading

# define some global variables
command = False
execute = ""
output_destination = ""
verbose = False


def run_command(cmd: str) -> str:
    """
    Run the specified command in the host OS.
    :param cmd: command to run
    :return: output from command
    """
    cmd = cmd.strip()
    try:
        # run command and return received output
        output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, shell=True)
    except Exception as e:
        print(e)
        print('Failed to execute command: {}'.format(cmd))
        return 'Failed to execute command: {}\r\n'.format(cmd).encode()
    return output


def handle_client_connection(client_socket: socket.socket, client_address):
    """
    Handle requests from a connected client.
    :param client_socket: connected client object
    :param client_address: address of connected client
    :return: None
    """
    global output_destination
    global execute
    global command

    print('Connected to client at {}.'.format(client_address))
    # check if we are supposed to write client input to a file
    if output_destination:
        file_input = ""
        print('Writing input from client at {} to {}.'.format(client_address, output_destination))
        # keep reading data until none is left
        with open(output_destination, 'w') as of:
            while True:
                data = client_socket.recv(1024)
                if not data or data.decode() == '\r\n' or data.decode() == '\n':
                    break
                # write data to file
                of.write(data.decode())
        client_socket.sendall('Successfully saved file to {}.\r\n'.format(output_destination).encode())
    # check if we are supposed to execute a command
    if execute:
        output = run_command(execute)
        client_socket.sendall(output)
    # check if a command shell was requested
    if command:
        while True:
            client_socket.sendall('terminal> '.encode())
            # receive data until we get a line feed pattern
            cmd_buffer = ''
            while '\n' not in cmd_buffer:
                cmd_buffer += client_socket.recv(1024).decode()
            # run the command and send the output back to the client
            if cmd_buffer.strip() == 'exit':
                client_socket.sendall('Exit code received, closing terminal.\r\n'.encode())
                break
            output = run_command(cmd_buffer)
            client_socket.sendall(output)
    client_socket.close()


def start_server(listen_host: str, listen_port: int):
    """
    Start listening on the specified host and port.
    :param listen_host: IP address to listen on (0.0.0.0 to listen on all interfaces)
    :param listen_port: port to listen to
    :return:
    """
    # start listening
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((listen_host, listen_port))
    server.listen()

    # wait for inbound connections
    while True:
        client_socket, addr = server.accept()
        # start new thread to handle this connection
        client_thread = threading.Thread(target=handle_client_connection, args=(client_socket, addr))
        client_thread.start()


def client_send(target_host: str, target_port: int, data=None):
    """
    Connect as a client to the specified target and send and receive arbitrary data.
    :param target_host: host to connect to
    :param target_port: port to connect to
    :param data: initial data to send
    :return: None
    """
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # connect to target host
    try:
        client.connect((target_host, target_port))
        if data:
            client.sendall(data.encode())
        while True:
            # wait for response from target host
            recv_len = 1
            response = ''
            while recv_len:
                data = client.recv(4096)
                recv_len = len(data)
                response += data.decode()
                if recv_len < 4096:
                    break
            print(response)
            # get further input from user
            print('Enter further input or press CTRL-D for no input.')
            data = sys.stdin.readline()
            client.sendall(data.encode())
    except Exception as e:
        print(e)
        print('[*] Exiting program.')
        client.close()


def print_verbose(message: str):
    """
    Print the specified message to STDOUT only if the verbose flag is set to True (default is False).
    :param message: message to print
    :return: None
    """
    global verbose
    if verbose:
        print(message)


def main():
    """
    Main logic.
    :return: None
    """
    # define global variables
    global command
    global execute
    global output_destination
    global verbose

    # parse command line input arguments
    parser = argparse.ArgumentParser(
        description='A pure Python replacement for Netcat (sort of) that also adds several new features.')
    parser.add_argument('-l', '--listen', action='store_true', help='Listen for incoming connections')
    parser.add_argument('-e', '--execute', help='Execute the given command after receiving a connection')
    parser.add_argument('-c', '--command', action='store_true', help='Initialize a command shell')
    parser.add_argument('-o', '--outfile', help='Write input data to the given file')
    parser.add_argument('-v', '--verbose', action='store_true', help='Print verbose messages')
    parser.add_argument('target_host', help='IP or hostname to connect to or listen on')
    parser.add_argument('port', type=int, help='Port to connect to or listen on')
    args = parser.parse_args()

    # assign input arguments
    listen = args.listen
    execute = args.execute
    command = args.command
    output_destination = args.outfile
    verbose = args.verbose
    target_host = args.target_host
    port = int(args.port)

    if listen:
        print_verbose('Listening for incoming connections on TCP {}:{}.'.format(target_host, port))
        start_server(target_host, port)
    else:
        print_verbose('Connecting to TCP {}:{}. Enter input or press CTRL-D for no input.'.format(target_host, port))
        # get input from STDIN if provided
        data = sys.stdin.readline()
        # connect to server
        client_send(target_host, port, data)


if __name__ == '__main__':
    main()
