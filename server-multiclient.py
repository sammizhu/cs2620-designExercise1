import socket
import threading

HOST = '127.0.0.1'
PORT = 65432

clients = []

def handle_client(conn, addr):
    """Handles communication with a single client."""
    print(f"New connection from {addr}")
    clients.append(conn)

    while True:
        try:
            data = conn.recv(1024).decode()
            if not data:
                break
            print(f"Client {addr}: {data}")

            # Broadcast message to all clients
            for client in clients:
                if client != conn:
                    client.sendall(f"Client {addr}: {data}".encode())

        except ConnectionResetError:
            break

    print(f"Client {addr} disconnected.")
    clients.remove(conn)
    conn.close()

def main():
    """Main function to start the chat server."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen()
        print("Chat server started. Waiting for connections...")

        while True:
            conn, addr = s.accept()
            client_thread = threading.Thread(target=handle_client, args=(conn, addr))
            client_thread.start()

if __name__ == '__main__':
    main()