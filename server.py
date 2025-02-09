import socket
import threading
import pymysql
import pymysql.cursors

# NEED TO REMOVE THIS LATER!!
HOST = '127.0.0.1'
PORT = 65432

clients = {}  # Dictionary to store connected clients {ephemeral_port_or_string: socket}

def connectsql():
    connection = pymysql.connect(host=HOST, user='root', database='db262')
    return connection

def send_message(message, target_id, sender_id):
    """Send a private message to a specific client.

    sender_id and target_id are ephemeral ports in your current design.
    We'll look up the sender's username by SELECTing from the DB WHERE socket_id = %s.
    That way, the receiver sees "User {actual_username}: message" instead of the ephemeral port.
    """
    # Do a quick DB lookup to find the sender's username from their stored socket_id
    connection = connectsql()
    cursor = connection.cursor()
    cursor.execute("SELECT username FROM users WHERE socket_id = %s", (str(sender_id),))
    row = cursor.fetchone()
    if row:
        sender_username = row[0]
    else:
        # If not found in DB, fall back to the ephemeral port
        sender_username = str(sender_id)

    if target_id in clients:
        try:
            clients[target_id].sendall(f"{sender_username}: {message}".encode())
        except:
            print(f"Error sending message to {target_id}.")
    else:
        # Let the sender know that the target wasn't found
        if sender_id in clients:
            clients[sender_id].sendall(f"Error: User {target_id} not found.\n".encode())

def handle_client(conn, addr):
    """Handles communication with a single client."""
    user_id = addr[1]  # Using the client's port number as an ID
    clients[user_id] = conn
    print(f"User {user_id} connected from {addr}")

    try:
        # Prompt the client after they connect
        conn.sendall("Welcome to EST! Enter 1 to Register and 2 to Login.\n".encode())

        while True:
            data = conn.recv(1024).decode().strip()
            if not data:
                break  # Client disconnected

            # If the client types something like "@someUserID message"
            if data.startswith("@"):
                # e.g. "@12345 some message"
                parts = data.split(" ", 1)
                print(parts)
                if len(parts) < 2:
                    conn.sendall("Invalid message format. Use @UserID message\n".encode())
                    continue

                target_username, message = parts
                target_username = target_username[1:]  # remove the '@'

                try:
                    # Look up that username's socket_id in the DB
                    connection = connectsql()
                    cursor = connection.cursor()
                    cursor.execute("SELECT socket_id FROM users WHERE username = %s", (target_username,))
                    result = cursor.fetchone()
                    if result:
                        # If that user is stored with a particular ephemeral port, route the message
                        target_id = int(result[0])
                        send_message(message, target_id, user_id)
                    else:
                        conn.sendall("User not found.\n".encode())
                except ValueError:
                    conn.sendall("Invalid UserID.\n".encode())
            else:
                # Any other text that doesn't start with "@"
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
        # Make sure the DB is accessible (though we're not storing it globally here)
        connectsql()
        print(f"Server listening on {HOST}:{PORT}...")

        while True:
            conn, addr = server_socket.accept()
            thread = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            thread.start()

if __name__ == "__main__":
    start_server()