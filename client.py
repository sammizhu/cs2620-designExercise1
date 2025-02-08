import socket
import threading
import pymysql
import pymysql.cursors

# NEED TO REMOVE THIS LATER!! 
HOST = '127.0.0.1'  
PORT = 65432

def receive_messages(sock):
    """Continuously listens for messages from the server."""
    while True:
        try:
            response = sock.recv(1024).decode()
            if not response:
                print("Disconnected from server.")
                break
            print(f"\n{response}\nYou: ", end="") 
        except ConnectionResetError:
            print("Server closed the connection.")
            break
    sock.close()

def connectsql():
    connection = pymysql.connect(host=HOST, user='root', database='db262')
    cursor = connection.cursor()

    connection.commit()

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))

        username = input("What is your username?: ")
        password = input("What is your password?: ")

        connection = pymysql.connect(host=HOST, user='root', database='db262')
        cursor = connection.cursor()

        connection.commit()

        with connection:
            with connection.cursor() as cursor:
                cursor.execute("CREATE TABLE IF NOT EXISTS users (username VARCHAR(255) NOT NULL PRIMARY KEY, password VARCHAR(255) NOT NULL);")
                sql = "INSERT INTO users (username, password) VALUES (%s, %s);"
                cursor.execute(sql, (username, password))

                connection.commit()

        user_id = s.getsockname()[1]  # Get client's port number as user ID

        threading.Thread(target=receive_messages, args=(s,), daemon=True).start()

        while True:
            msg = input("You: ")
            if msg.lower() == 'exit':
                print("Closing connection...")
                break
            s.sendall(msg.encode())

if __name__ == '__main__':
    main()