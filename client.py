import socket
import threading
import pymysql
import pymysql.cursors

# NEED TO REMOVE THIS LATER!! 
HOST = '127.0.0.1'  
PORT = 65432
logged_in = False

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
        connection = pymysql.connect(host=HOST, user='root', database='db262')
        cursor = connection.cursor()
        connection.commit()

        with connection:
            with connection.cursor() as cursor:
                cursor.execute("CREATE TABLE IF NOT EXISTS users (username VARCHAR(255) NOT NULL PRIMARY KEY, password VARCHAR(255) NOT NULL);")
                sql = "INSERT INTO users (username, password) VALUES (%s, %s);"
                # cursor.execute(sql, (username, password))

                connection.commit()

        user_id = s.getsockname()[1]  # Get client's port number as user ID

        threading.Thread(target=receive_messages, args=(s,), daemon=True).start()

        while True:
            msg = input()
            if msg == '1':
                username = input("Username?: ")
                # check to see if this username exists in db
                password = input("Password?: ")
                # check to see if this password matches
                # if matches:
                print(f'Welcome back {username}!')
                # else: print error
                logged_in = True
            elif msg == '2':
                username = input("Welcome first-time user! Enter a username: ")
                    # check if username is valid --> if not give error
                password = input("Enter a password: ")
                    # check if password is valid
                    # if so then hash and verify success, else give error
                if msg.lower() == 'exit':
                    print("Closing connection...")
                    break
                s.sendall(msg.encode())

if __name__ == '__main__':
    main()