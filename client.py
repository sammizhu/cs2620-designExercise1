import socket
import threading
import pymysql
import pymysql.cursors
import bcrypt

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
                print("\nDisconnected from server.")
                break
            print(f"\n{response}")
            print("You: ", end="", flush=True)
        except ConnectionResetError:
            print("\nServer closed the connection.")
            break
    sock.close()

def connectsql():
    connection = pymysql.connect(host=HOST, user='root', database='db262')
    return connection

def checkValidPassword(password):
    upper, number, special = 0, 0, 0
    if len(password) >= 7:
        for char in password:
            if (char.isupper()):
                upper += 1
            if (char.isdigit()):
                number += 1
            if (char in ['_', '@', '$', '#', '!']):
                special += 1
        if (upper > 0 and number > 0 and special > 0):
            return True
    return False

def hashPass(password):
    bytes_pass = password.encode('utf-8')
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(bytes_pass, salt)
    return hashed.decode('utf8')

def checkRealUsername(username, connection):
    cursor = connection.cursor()
    usercheck = "SELECT COUNT(*) FROM users WHERE username=%s;"
    cursor.execute(usercheck, (username,))
    connection.commit()
    result = cursor.fetchone()[0]
    return (result == 1)

def checkRealPassword(username, password, connection):
    passwordencode = password.encode('utf-8')
    cursor = connection.cursor()
    passwordquery = "SELECT password FROM users WHERE username=%s;"
    cursor.execute(passwordquery, (username,))
    connection.commit()
    row = cursor.fetchone()
    if not row:
        return False
    stored_hash = row[0].encode('utf-8')
    return bcrypt.checkpw(passwordencode, stored_hash)

def checkMessages(username, connection, s):
    cursor = connection.cursor()
    query = "SELECT COUNT(*) FROM messages WHERE receiver=%s;"
    cursor.execute(query, username)
    connection.commit()
    result = cursor.fetchone()[0]
    if result > 0:
        readmessage = input(f'You have {result} unread messages. Would you like to read them? Select 1 to read messages. Select 2 to send a new message.')
        if readmessage == 1:
            query2 = "SELECT COUNT(message), sender FROM messages GROUP by sender"
            cursor.execute(query2)
            connection.commit()
            result = cursor.fetchall()
            for num, sender in result:
                print(f'You have {num} unread messages from {sender}')
            readsender = input('Who would you like to read messages from?: ')
        elif readmessage == 2:
            sendMessage(username, s)
    else:
        sendMessage(username, s)

def sendMessage(sender, s):
    """
    Instead of just sending one message and quitting,
    let's allow the user to send multiple messages in a loop.

    """
    print("Type '@UserID message' to send a DM (or 'quit' to exit).")
    while True:
        print("You: ", end="", flush=True)
        msg = input() 
        if msg.lower() == 'exit': # leave conversation with this person but not logging off
            break
        s.sendall(msg.encode())
def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        connection = connectsql()
        cursor = connection.cursor()

        port_num = s.getsockname()[1]  

        # Start background thread to listen for incoming server messages
        threading.Thread(target=receive_messages, args=(s,), daemon=True).start()

        while True:
            logged_in = False
            msg = input()
            if msg == '1':
                # Registration
                username = input("Welcome first-time user! Enter a username (alphanumeric): ")
                while True:
                    if checkRealUsername(username, connection):
                        username = input("Username taken. Please select new username: ")
                    else: 
                        break
                password = input("Enter a password (>=7 chars, 1 uppercase, 1 digit, 1 special): ")
                
                while True:
                    if checkValidPassword(password):
                        hashed_pass = hashPass(password)
                        with connection.cursor() as cursor:
                            accountregister = "INSERT INTO users (username, password) VALUES (%s, %s);"
                            cursor.execute(accountregister, (username, hashed_pass))
                            connection.commit()
                            cursor.execute("UPDATE users SET socket_id = %s, active=1 WHERE username = %s", (str(port_num), username))
                            connection.commit()
                        print("Registration Successful!")
                        logged_in = True
                        break
                    else:
                        password = input('Please enter a valid password: ')
                    
            elif msg == '2':
                # Login
                username = input('Username: ')
                while checkRealUsername(username, connection):
                    password = input('Password: ')
                    if checkRealPassword(username, password, connection):
                        print(f'Welcome back {username}!')
                        cursor.execute("UPDATE users SET socket_id = %s, active=1 WHERE username = %s", (str(port_num), username))
                        connection.commit()
                        logged_in = True
                        break
                    else:
                        print('Password incorrect. Please try again.')
                        password = input('Password: ')
                else:
                    print('Login Failed. Please try again.')
                    break

            if logged_in:
                # Now let the user send multiple messages
                checkMessages(username, connection, s)
            else:
                print('Closing connection...')
                break

if __name__ == '__main__':
    main()

