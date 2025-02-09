import socket
import threading
import pymysql
import pymysql.cursors

# NEED TO REMOVE THIS LATER!! 
HOST = '127.0.0.1'  
PORT = 65432       

clients = {}  # Dictionary to store connected clients {user_id: socket} --> change this to a username mapping later 

def connectsql():
    connection = pymysql.connect(host=HOST, user='root', database='db262')
    return connection

def send_message(message, target_id, sender_id):
    """Send a private message to a specific client."""
    if target_id in clients:
        try:
            clients[target_id].sendall(f"User {sender_id}: {message}".encode())
        except:
            # I'm actually not sure what might cause this error (maybe some threading issues?) 
            # hence I just used a generic error message here for now. But we might want to consider 
            # this as an edge case later
            print(f"Error sending message to {target_id}.")
    else:
        clients[sender_id].sendall(f"Error: User {target_id} not found.\n".encode())

def handle_client(conn, addr):
    """Handles communication with a single client."""
    user_id = addr[1]  # Use the client's port number as the user ID --> later on we should change this to username for easier usability
    clients[user_id] = conn
    print(f"User {user_id} connected from {addr}")

    try:
        # Sends this to the Client after they connect to Server so they know how to send a message to a specific Client
        # conn.sendall(f"Connected as User {user_id}. Type '@UserID message' to send a DM.\n".encode()) 
        conn.sendall("Welcome to EST! Enter 1 to Register and 2 to Login.\n".encode())

        while True:
            data = conn.recv(1024).decode().strip()
            if not data:
                break  # Client disconnected

            if data.startswith("@"):
                # Direct message format: "@12345 message"
                parts = data.split(" ", 1)
                print(parts)
                if len(parts) < 2:
                    conn.sendall("Invalid message format. Use @UserID message\n".encode())
                    continue

                target_username, message = parts
                target_username = target_username[1:]

                try:
                    connection = connectsql()
                    cursor = connection.cursor()
                    cursor.execute("SELECT socket_id FROM users WHERE username = %s", target_username)
                    result = cursor.fetchone()
                    print("result: ", result)
                    if result:
                        target_id = int(result[0]) 
                        print("target_id:", target_id)
                        send_message(message, target_id, user_id)
                    else:
                        conn.sendall("User not found.\n".encode())
                except ValueError:
                    conn.sendall("Invalid UserID.\n".encode())
            else:
                conn.sendall("Error: Messages must start with '@UserID'\n".encode())

    except ConnectionResetError:
        print(f"User {user_id} disconnected.")
    
    conn.close()
    print(f"Connection with User {user_id} closed.")

def start_server():
    """Starts the server and listens for incoming connections."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((HOST, PORT))
        server_socket.listen()
        connectsql()
        print(f"Server listening on {HOST}:{PORT}...")

        while True:
            conn, addr = server_socket.accept()
            thread = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            thread.start()

if __name__ == "__main__":
    start_server()