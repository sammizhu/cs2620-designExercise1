import socket
import threading
import pymysql
import pymysql.cursors
import bcrypt
import traceback
import argparse
import os
import json

# Parse command-line arguments
parser = argparse.ArgumentParser(description="Start the chat server.")
parser.add_argument("--host", default=os.getenv("CHAT_SERVER_HOST", "0.0.0.0"), help="Server hostname or IP")
parser.add_argument("--port", type=int, default=int(os.getenv("CHAT_SERVER_PORT", 65432)), help="Port number")
args = parser.parse_args()

# Use argument or environment variable
HOST = args.host
PORT = args.port

clients = {}

def connectsql():
    return pymysql.connect(
        host=HOST,
        user='root',
        password='', 
        database='db262',
        cursorclass=pymysql.cursors.DictCursor
    )

def checkRealUsername(username):
    with connectsql() as db:
        with db.cursor() as cur:
            cur.execute("SELECT COUNT(*) AS cnt FROM users WHERE username=%s", (username,))
            row = cur.fetchone()
            return (row['cnt'] > 0)

def checkValidPassword(password):
    if len(password) < 7:
        return False
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in ['_', '@', '$', '#', '!'] for c in password)
    return (has_upper and has_digit and has_special)

def hashPass(password):
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')

def checkRealPassword(username, plain_text):
    with connectsql() as db:
        with db.cursor() as cur:
            cur.execute("SELECT password FROM users WHERE username=%s", (username,))
            row = cur.fetchone()
            if not row:
                return False
            stored_hash = row['password']
    return bcrypt.checkpw(plain_text.encode('utf-8'), stored_hash.encode('utf-8'))

def handle_registration(conn, user_id):
    # 1) Prompt repeatedly for username until it is a valid username
    while True:
        json_register_username = {"command": "1", 
                                  "server_message": "Enter a username (alphanumeric): "}
        conn.sendall(json.dumps(json_register_username).encode('utf-8'))

        reg_username_jsonstr = conn.recv(1024).decode('utf-8')
        reg_username = json.loads(reg_username_jsonstr)["username"]

        # If user just hit Enter or disconnected, cancel registration
        if not reg_username:
            json_register_cancel = {"command": "1",
                                    "server_message": "Registration canceled.\n"}
            conn.sendall(json.dumps(json_register_cancel).encode('utf-8'))
            return None
        
        # If username is taken, let user know and loop again
        if checkRealUsername(reg_username):
            json_register_checkusername = {"command": "1", 
                                           "server_message": "Username taken. Please choose another.\n"}
            conn.sendall(json.dumps(json_register_checkusername).encode('utf-8'))
            continue
        else:
            # Good username
            break
    
    # 2) Prompt repeatedly for password until valid
    while True:
        json_register_password = {"command": "1", 
                                  "server_message": "Enter a password (>=7 chars, including uppercase, digit, special): "}
        conn.sendall(json.dumps(json_register_password).encode('utf-8'))

        reg_password_jsonstr = conn.recv(1024).decode('utf-8')
        reg_password = json.loads(reg_password_jsonstr)["password"]

        if not reg_password:
            json_register_passcancel = {"command": "1",
                                        "server_message": "Registration canceled.\n"}
            conn.sendall(json.dumps(json_register_passcancel).encode('utf-8'))
            return None

        if not checkValidPassword(reg_password):
            json_register_passinvalid = {"command": "1",
                                         "server_message": "Invalid password. Please try again.\n"}
            conn.sendall(json.dumps(json_register_passinvalid).encode('utf-8'))
            continue

        # Now ask for confirmation of the password
        json_register_confirm = {"command": "1",
                                 "server_message": "Confirm your password: "}
        conn.sendall(json.dumps(json_register_confirm).encode('utf-8'))

        confirm_password_jsonstr = conn.recv(1024).decode('utf-8')
        confirm_password = json.loads(confirm_password_jsonstr)["password"]

        if reg_password != confirm_password:
            json_register_passmatch = {"command": "1",
                                       "server_message": "Passwords do not match. Please try again.\n"}
            conn.sendall(json.dumps(json_register_passmatch).encode('utf-8'))
            continue
        else:
            break

    # 3) Hash & store
    hashed = hashPass(reg_password)
    try:
        with connectsql() as db:
            with db.cursor() as cur:
                cur.execute("INSERT INTO users (username, password, active) VALUES (%s, %s, 1)",
                            (reg_username, hashed))
                cur.execute("UPDATE users SET socket_id=%s WHERE username=%s",
                            (str(user_id), reg_username))
            db.commit()
        json_register_success = {"command": "1",
                                 "server_message": "Registration successful. You are now logged in!\n"}
        conn.sendall(json.dumps(json_register_success).encode('utf-8'))
        return reg_username
    except Exception:
        traceback.print_exc()
        json_register_servercancel = {"command": "1",
                                      "server_message": "Server error. Registration canceled.\n"}
        conn.sendall(json.dumps(json_register_servercancel).encode('utf-8'))
        return None

def handle_login(conn, user_id):
    conn.sendall("Enter your username: ".encode())
    # Prompt repeatedly for username until found
    while True:
        login_username = conn.recv(1024).decode().strip()

        if not login_username:
            conn.sendall("Login canceled.\n".encode())
            return None
        
        if not checkRealUsername(login_username):
            conn.sendall("User not found. Please try again.\n".encode())
        else:
            break

    # Prompt repeatedly for password until correct
    while True:
        conn.sendall("Enter your password: ".encode())
        login_password = conn.recv(1024).decode().strip()

        if not login_password:
            conn.sendall("Login canceled.\n".encode())
            return None

        if not checkRealPassword(login_username, login_password):
            conn.sendall("Incorrect password. Try again.\n".encode())
        else:
            break

    # Mark active=1
    with connectsql() as db:
        with db.cursor() as cur:
            cur.execute("UPDATE users SET active=1, socket_id=%s WHERE username=%s",
                        (str(user_id), login_username))
        db.commit()
    conn.sendall(f"Welcome, {login_username}!\n".encode())
    return login_username

def check_messages_server_side(conn, username):
    """
    Checks if 'username' has unread messages.
    If so, we ask them whether they'd like to read or send new messages.
    If they choose read => ask from which sender, then fetch those messages, mark them read.
    If they choose send => they can just type '@username message'.
    """
    with connectsql() as db:
        with db.cursor() as cur:
            # Count how many unread messages
            cur.execute("SELECT COUNT(*) AS cnt FROM messages WHERE receiver=%s AND isread=0", (username,))
            row = cur.fetchone()
            unread_count = row['cnt']

            if unread_count == 0:
                conn.sendall("You have 0 unread messages.\n ".encode())
                return

            # If we have unread
            conn.sendall(f" ------------------------------------------\n| You have {unread_count} unread messages.              |\n| Type '1' to read them, or '2' to skip    |\n| and send new messages.                   |\n ------------------------------------------\n """.encode())

            choice = conn.recv(1024).decode().strip()

            if choice == "1":
                # Check which sender(s)
                cur.execute("SELECT sender, COUNT(*) AS num FROM messages WHERE receiver=%s AND isread=0 GROUP BY sender", (username,))
                rows = cur.fetchall()
                if not rows:
                    conn.sendall("No unread messages found (maybe they were just read?).\n".encode())
                    return
                # Show which senders
                senders_info = "\n".join([f"{row['sender']} ({row['num']} messages)" for row in rows])
                conn.sendall(f"You have unread messages from:\n{senders_info}\n".encode())
                conn.sendall("Which sender do you want to read from?\n ".encode())
                
                chosen_sender = conn.recv(1024).decode().strip()
                if not chosen_sender:
                    conn.sendall("Canceled reading messages.\n".encode())
                    return
                
                # Fetch unread messages from the database
                cur.execute(
                    "SELECT messageid, sender, message, datetime FROM messages "
                    "WHERE receiver=%s AND sender=%s AND isread=0 ORDER BY messageid",
                    (username, chosen_sender)
                )
                unread_msgs = cur.fetchall()

                if not unread_msgs:
                    conn.sendall("No unread messages from that user.\n".encode())
                    return

                # Batch size: if more than 5 messages, use batches of 5; otherwise, show all
                batch_size = 5 if len(unread_msgs) > 5 else len(unread_msgs)

                conn.sendall(f"--- Unread messages from {chosen_sender} ---\n".encode())

                for i in range(0, len(unread_msgs), batch_size):
                    batch = unread_msgs[i:i+batch_size]
                    
                    for m in batch:
                        ts = m['datetime'].strftime("%Y-%m-%d %H:%M:%S")
                        conn.sendall(f"{ts} {m['sender']}: {m['message']}\n".encode())
                    
                    # Mark the current batch as read in the database
                    batch_ids = [m['messageid'] for m in batch]
                    if len(batch_ids) == 1:
                        cur.execute("UPDATE messages SET isread=1 WHERE messageid=%s", (batch_ids[0],))
                    else:
                        placeholders = ','.join(['%s'] * len(batch_ids))
                        query = f"UPDATE messages SET isread=1 WHERE messageid IN ({placeholders})"
                        cur.execute(query, batch_ids)
                    
                    db.commit()
                    conn.sendall("The current batch of messages has been marked as read.\n".encode())

                    # If there are more messages, wait for the user input before showing the next batch.
                    if i + batch_size < len(unread_msgs):
                        conn.sendall("Type anything to see the next batch of messages...\n".encode())
                        _ = conn.recv(1024)  # Wait for user input
            elif choice == "2":
                # Skips reading, user can continue
                return 
            else:
                conn.sendall("Invalid choice. Returning to main.\n".encode())

def handle_client(conn, addr):
    user_id = addr[1]
    clients[user_id] = conn
    print(f"New connection from {addr}")
    
    logged_in = False
    username = None

    try:
        while True:
            data = conn.recv(1024).decode().strip()
            if not data:
                # client disconnected
                print(f"Client {addr} disconnected.")
                break

            # If not logged in => only handle register or login
            if not logged_in:
                if data == "1":
                    new_user = handle_registration(conn, user_id)
                    if new_user:
                        username = new_user
                        logged_in = True
                        # check unread (should be none if newly registered, but let's be consistent)
                        check_messages_server_side(conn, username)
                        conn.sendall("To send messages, use '@username message'. You can also type 'check', 'logoff',' search', 'delete', or 'deactivate'.\n ".encode())
                elif data == "2":
                    logged_user = handle_login(conn, user_id)
                    if logged_user:
                        username = logged_user
                        logged_in = True
                        # check unread for returning user
                        check_messages_server_side(conn, username)
                        conn.sendall("To send messages, use '@username message'. You can also type 'check', 'logoff',' search', 'delete', or 'deactivate'.\n ".encode())
            
            # If logged in => handle DM sending, check, or logoff
            else:
                if data.lower() == "logoff":
                    # Mark user inactive
                    with connectsql() as db:
                        with db.cursor() as cur:
                            cur.execute("UPDATE users SET active=0 WHERE username=%s", (username,))
                        db.commit()
                    conn.sendall("Logged off.\n".encode())
                    break

                elif data.lower() == "check":
                    check_messages_server_side(conn, username)
                
                elif data.startswith("@"):
                    # parse DM
                    parts = data.split(" ", 1)
                    if len(parts) < 2:
                        conn.sendall("Invalid format. Use '@username message'.\n".encode())
                        continue
                    target_username, message = parts[0][1:], parts[1]
                    try:
                        with connectsql() as db:
                            with db.cursor() as cur:
                                cur.execute("INSERT INTO messages (receiver, sender, message, isread) VALUES (%s, %s, %s, 0)", (target_username, username, message))
                                db.commit()

                                # If target online, send message --> otherwise just keep it stored in messages table above
                                cur.execute("SELECT socket_id, active FROM users WHERE username=%s", (target_username,))
                                row = cur.fetchone()
                                if row and row['socket_id'] and row['socket_id'].isdigit() and row['active']:
                                    tsid = int(row['socket_id'])
                                    if tsid in clients:
                                        cur.execute("SELECT messageid FROM messages WHERE message=%s", (message))
                                        msg_id = cur.fetchall()
                                        msg_ids = tuple([m['messageid'] for m in msg_id])
                                        query = "UPDATE messages SET isread=1 WHERE messageid=%s"
                                        cur.execute(query, (msg_ids[0],))
                                        db.commit()
                                        clients[tsid].sendall(f"{username}: {message}\n".encode())
                    except Exception:
                        traceback.print_exc()
                        conn.sendall("Error storing/sending message.\n".encode())
                
                elif data.lower() == "search":
                    # List all users in the users table
                    try:
                        with connectsql() as db:
                            with db.cursor() as cur:
                                cur.execute("SELECT username FROM users")
                                rows = cur.fetchall()
                        if len(rows) > 0:
                            all_usernames = ", ".join([row['username'] for row in rows if row['username'] != username])
                            conn.sendall(f"\nAll users:\n{all_usernames}\n ".encode())
                        else:
                            conn.sendall("No users found.\n".encode())
                    except Exception as e:
                        traceback.print_exc()
                        conn.sendall("Error while searching for users.\n".encode())
                
                elif data.lower() == "delete":
                    # Check if user has sent any unread messages
                    try:
                        with connectsql() as db:
                            with db.cursor() as cur:
                                cur.execute("SELECT messageid FROM messages WHERE sender=%s AND isread=0 ORDER BY messageid DESC LIMIT 1""", (username,))
                                row = cur.fetchone()
                                if row:
                                    last_msg_id = row['messageid']
                                    # Confirm with the user that they want to delete the last message they sent
                                    conn.sendall("Are you sure you want to delete the last message you sent? Type 'yes' or 'no':\n ".encode())
                                    confirm_resp = conn.recv(1024).decode().strip().lower()
                                    if confirm_resp == 'yes':
                                        cur.execute("DELETE FROM messages WHERE messageid=%s", (last_msg_id,))
                                        db.commit()
                                        conn.sendall("Your last message has been deleted.\n".encode())
                                    else:
                                        conn.sendall("Delete canceled.\n".encode())
                                else:
                                    conn.sendall("You have not sent any messages able to be deleted. Note that you cannot delete messages already read.\n".encode())
                    except Exception as e:
                        traceback.print_exc()
                        conn.sendall("Error deleting your last message. Please try again.\n".encode())

                elif data.lower() == "deactivate":
                    # Confirm with the user that this will deactivate (delete) their account
                    conn.sendall(
                        "Are you sure you want to deactivate your account?\n"
                        "This will remove your account and all messages you've sent.\n"
                        "Type 'yes' to confirm or 'no' to cancel.\n ".encode()
                    )
                    confirm_resp = conn.recv(1024).decode().strip().lower()
                    if confirm_resp == 'yes':
                        try:
                            with connectsql() as db:
                                with db.cursor() as cur:
                                    # Delete all messages sent by this user
                                    cur.execute("DELETE FROM messages WHERE sender=%s", (username,))
                                    # Delete the user record
                                    cur.execute("DELETE FROM users WHERE username=%s", (username,))
                                    db.commit()
                            conn.sendall("Your account and all your sent messages have been removed. Goodbye.\n".encode())
                        except Exception as e:
                            traceback.print_exc()
                            conn.sendall("Error deactivating your account.\n".encode())
                        finally:
                            # Force a break so we exit the loop and close connection
                            break
                    else:
                        conn.sendall("Account deactivation canceled.\n".encode())
                
                else:
                    # unrecognized command
                    conn.sendall("Error: Messages must start with '@username' or use 'check', 'logoff',' search', 'delete', or 'deactivate'.\n ".encode())

    except Exception as e:
        print("Exception in handle_client:", e)
        traceback.print_exc()
    finally:
        # If user was logged in, mark them inactive
        if username:
            with connectsql() as db:
                with db.cursor() as cur:
                    cur.execute("UPDATE users SET active=0 WHERE username=%s", (username,))
                db.commit()

        if user_id in clients:
            del clients[user_id]
        conn.close()
        print(f"Connection with {addr} closed.")

def start_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((HOST, PORT))
        server_socket.listen()
        print(f"Server listening on {HOST}:{PORT}...")

        while True:
            conn, addr = server_socket.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            t.start()

if __name__ == "__main__":
    start_server()