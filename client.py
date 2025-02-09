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
                print("Disconnected from server.")
                break
            print(f"\n{response}\nYou: ", end="") 
        except ConnectionResetError:
            print("Server closed the connection.")
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
            if (char == '_' or char == '@' or char == '$' or char =='#' or char == '!'):
                special += 1
        if (upper > 0 and number > 0 and special > 0):
            return True
    return False

def hashPass(password):
    bytes = password.encode('utf-8')
    salt = bcrypt.gensalt()
    hash = bcrypt.hashpw(bytes, salt)
    string_hash = hash.decode('utf8')
    return string_hash

def checkRealUsername(username, connection):
    cursor = connection.cursor()
    usercheck = "SELECT COUNT(*) FROM users WHERE username=%s;"
    cursor.execute(usercheck, username)
    connection.commit()
    result = cursor.fetchone()[0]

    if result == 1:
        return True
    return False

def checkMessages(username, connection, s):
    # cursor = connection.cursor()
    # query = "SELECT COUNT(*) FROM messages WHERE receiver=%s;"
    # cursor.execute(query, username)
    # connection.commit()
    # result = cursor.fetchone()[0]
    # if result > 0:
    #     readmessage = input('You have %i unread messages. Would you like to read them? Select 1 to read messages. Select 2 to send a new message.')

    # if readmessage == 1:
    #     query2 = "SELECT COUNT(message), sender FROM messages GROUP by sender"
    #     cursor.execute(query2)
    #     connection.commit()
    #     result = cursor.fetchall()
    #     for num, sender in result:
    #         print(f'You have {num} unread messages from {sender}')
    #     readsender = input('Who would you like to read messages from?: ')
    # elif readmessage == 2:
    sendMessage(username, s)
    
def checkRealPassword(username, password, connection):
    passwordencode = password.encode('utf-8')

    cursor = connection.cursor()
    passwordquery = "SELECT password FROM users WHERE username=%s;"
    cursor.execute(passwordquery, username)
    connection.commit()
    hash = cursor.fetchone()[0]
    hashencode = hash.encode('utf-8')

    result = bcrypt.checkpw(passwordencode, hashencode)
    return result

def sendMessage(sender, s):
    # sender as an input to add to messages table
    msg = input("Type '@UserID message' to send a DM.\n")
    s.sendall(msg.encode())

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        connection = connectsql()
        cursor = connection.cursor()

        port_num = s.getsockname()[1]  # Get client's port number as user ID

        threading.Thread(target=receive_messages, args=(s,), daemon=True).start()

        while True:
            logged_in = False
            msg = input()
            if msg == '1':
                username = input("Welcome first-time user! Enter a username. All characters must be alphanumeric: ")
                    # check if username is valid --> if not give error
                password = input("Enter a password (Minimum 7 characters, at least one upper case alphabet character, at least 1 number between [0-9], and at least one special character [_, @, $, #, !]): ")
                # If password valid, then hash and verify successful registration; else, give error
                while True:
                    if checkValidPassword(password):
                        hash = hashPass(password)
                        with connection:
                            with connection.cursor() as cursor:
                                accountregister = "INSERT INTO users (username, password) VALUES (%s, %s);"
                                cursor.execute(accountregister, (username, hash))
                                connection.commit()
                        print("Registration Successful!")
                        break
                    else:
                        password = input('Please enter a valid password: ')
                    
            elif msg == '2':
                username = input('Username: ')
                while checkRealUsername(username, connection):
                    password = input('Password: ')
                    if checkRealPassword(username, password, connection):
                        cursor.execute("UPDATE users SET socket_id = %s WHERE username = %s", [port_num, username])
                        print(f'Welcome back {username}!')
                        logged_in = True
                        break
                    else:
                        print('Password incorrect. Please try again.')
                        password = input('Password: ')
                else:
                    print('Login Failed. Please try again.')
                    break

            # elif msg.lower() == 'exit':
            #     print('Closing connection...')
            #     break
            # s.sendall(msg.encode())

            if logged_in:
                checkMessages(username, connection, s)
            else:
                print('Closing connection...')
                break

if __name__ == '__main__':
    main()