import socket
import threading
import queue
import pymysql
import pymysql.cursors
import bcrypt
import traceback
import tkinter as tk
from tkinter import messagebox
from tkinter.scrolledtext import ScrolledText

# Server connection details
HOST = '127.0.0.1'
PORT = 65432


clients = {}  # ephemeral_port -> conn

def connectsql():
    return pymysql.connect(
        host=HOST,
        user='root',
        password='',  # fill in if needed
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

########################################################################
# Login/Registration Frame
########################################################################
class LoginFrame(tk.Frame):
    def __init__(self, master, login_callback, register_callback):
        super().__init__(master)
        self.login_callback = login_callback
        self.register_callback = register_callback

        self.header = tk.Label(self, text='Welcome to EST!', font=('Helvetica', 24))
        self.header.pack(pady=10)

        self.button_frame = tk.Frame(self)
        self.button_frame.pack(pady=10)
        self.login_button = tk.Button(self.button_frame, text='Register', width=10, command=self.handle_registration)
        self.login_button.pack(side=tk.LEFT, padx=5)
        self.register_button = tk.Button(self.button_frame, text='Login', width=10, command=self.attempt_login)
        self.register_button.pack(side=tk.LEFT, padx=5)



        # Title label
        self.title_label = tk.Label(self, text="Login / Registration", font=("Helvetica", 16))
        self.title_label.pack(pady=10)

        # Username label and entry
        self.username_label = tk.Label(self, text="Username:")
        self.username_label.pack(pady=(10, 0))
        self.username_entry = tk.Entry(self)
        self.username_entry.pack(pady=(0, 10), ipadx=50)

        # Password label and entry
        self.password_label = tk.Label(self, text="Password:")
        self.password_label.pack(pady=(10, 0))
        self.password_entry = tk.Entry(self, show="*")
        self.password_entry.pack(pady=(0, 10), ipadx=50)

        # Buttons frame
        self.button_frame = tk.Frame(self)
        self.button_frame.pack(pady=10)
        self.login_button = tk.Button(self.button_frame, text="Login", width=10, command=self.attempt_login)
        self.login_button.pack(side=tk.LEFT, padx=5)
        self.register_button = tk.Button(self.button_frame, text="Register", width=10, command=self.attempt_register)
        self.register_button.pack(side=tk.LEFT, padx=5)

        # Error message label
        self.error_label = tk.Label(self, text="", fg="red")
        self.error_label.pack(pady=5)

    def attempt_login(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        if not username or not password:
            self.set_error("Username and password cannot be empty.")
            return
        self.set_error("")
        self.login_callback(username, password)

    def attempt_register(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        if not username or not password:
            self.set_error("Username and password cannot be empty.")
            return
        self.set_error("")
        self.register_callback(username, password)

    def set_error(self, message):
        self.error_label.config(text=message)

    def handle_registration(self, conn, user_id):
        # 1) Prompt repeatedly for username until it's not taken
        while True:
            # Username label and entry
            self.username_label = tk.Label(self, text="Enter a username (alphanumeric characters only):")
            self.username_label.pack(pady=(10, 0))
            self.username_entry = tk.Entry(self)
            self.username_entry.pack(pady=(0, 10), ipadx=50)

            if not self.username_entry:
                # If user just hit Enter or disconnected
                self.username_label = tk.Label(self, text="Registration canceled.")
                self.username_label.pack(pady=(10, 0))
                return None

            # Password label and entry
            self.password_label = tk.Label(self, text="Password:")
            self.password_label.pack(pady=(10, 0))
            self.password_entry = tk.Entry(self, show="*")
            self.password_entry.pack(pady=(0, 10), ipadx=50)
            
            # If username is taken, let them know and loop again
            # if checkRealUsername(reg_username):
            #     conn.sendall("Username taken. Please choose another.\n".encode())
            #     continue
            # else:
            #     # Good username
            #     break

        # 2) Prompt repeatedly for password until valid
        # while True:
        #     conn.sendall("Enter a password (>=7 chars, including uppercase, digit, special): ".encode())
        #     reg_password = conn.recv(1024).decode().strip()

        #     if not reg_password:
        #         conn.sendall("Registration canceled.".encode())
        #         return None
            
        #     if not checkValidPassword(reg_password):
        #         conn.sendall("Invalid password. Please try again.\n".encode())
        #     else:
        #         break

        # # 3) Hash & store
        # hashed = hashPass(reg_password)
        # try:
        #     with connectsql() as db:
        #         with db.cursor() as cur:
        #             cur.execute("INSERT INTO users (username, password, active) VALUES (%s, %s, 1)",
        #                         (reg_username, hashed))
        #             cur.execute("UPDATE users SET socket_id=%s WHERE username=%s",
        #                         (str(user_id), reg_username))
        #         db.commit()
        #     conn.sendall("Registration successful. You are now logged in!\n".encode())
        #     return reg_username
        # except Exception:
        #     traceback.print_exc()
        #     conn.sendall("Server error. Registration canceled.\n".encode())
        #     return None


########################################################################
# Chat Frame (After login/registration succeeds)
########################################################################
class ChatFrame(tk.Frame):
    def __init__(self, master, send_callback):
        super().__init__(master)
        self.send_callback = send_callback

        # ScrolledText widget for chat messages (and system prompts)
        self.chat_display = ScrolledText(self, state='disabled', wrap='word', width=80, height=24)
        self.chat_display.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        # Frame to hold the message entry and send button
        self.input_frame = tk.Frame(self)
        self.input_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        self.message_entry = tk.Entry(self.input_frame, width=70)
        self.message_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.message_entry.bind("<Return>", self.send_message)
        self.send_button = tk.Button(self.input_frame, text="Send", command=self.send_message)
        self.send_button.pack(side=tk.LEFT, padx=(5, 0))

    def append_message(self, message):
        self.chat_display.configure(state='normal')
        self.chat_display.insert(tk.END, message + "\n")
        self.chat_display.configure(state='disabled')
        self.chat_display.yview(tk.END)

    def send_message(self, event=None):
        message = self.message_entry.get().strip()
        if message:
            self.send_callback(message)
            self.message_entry.delete(0, tk.END)

########################################################################
# Main Client Application Class
########################################################################
class ClientApp:
    def __init__(self, master):
        self.master = master
        master.title("Chat Client")
        self.running = True

        # Set up the socket connection.
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.sock.connect((HOST, PORT))
        except Exception as e:
            messagebox.showerror("Connection Error", f"Could not connect to server: {e}")
            master.destroy()
            return

        # A thread-safe queue to pass messages from the receive thread to the GUI.
        self.msg_queue = queue.Queue()

        # Create and pack the login frame.
        self.login_frame = LoginFrame(master, self.do_login, self.do_register)
        self.login_frame.pack(fill="both", expand=True)
        # Chat frame will be created after successful login/registration.
        self.chat_frame = None

    def do_login(self, username, password):
        threading.Thread(target=self.login_process, args=(username, password), daemon=True).start()

    def login_process(self, username, password):
        try:
            # Receive the initial welcome message from the server.
            welcome = self.sock.recv(1024).decode()
            # Tell the server we wish to login by sending "2"
            self.sock.sendall("2".encode())
            # Expect a prompt for the username.
            prompt1 = self.sock.recv(1024).decode()
            # Send the username.
            self.sock.sendall(username.encode())
            # Expect a prompt for the password.
            prompt2 = self.sock.recv(1024).decode()
            # Send the password.
            self.sock.sendall(password.encode())
            # Receive the final response (either a welcome message or an error).
            response = self.sock.recv(1024).decode()
            if "Welcome" in response:
                self.master.after(0, self.show_chat_frame)
            else:
                self.master.after(0, lambda: self.login_frame.set_error(response))
        except Exception as e:
            self.master.after(0, lambda: self.login_frame.set_error("Login error: " + str(e)))

    def do_register(self, username, password):
        threading.Thread(target=self.register_process, args=(username, password), daemon=True).start()

    def register_process(self, username, password):
        try:
            # Receive the initial welcome message from the server.
            welcome = self.sock.recv(1024).decode()
            # Tell the server we wish to register by sending "1"
            self.sock.sendall("1".encode())
            # Expect a prompt for the username.
            prompt1 = self.sock.recv(1024).decode()
            # Send the chosen username.
            self.sock.sendall(username.encode())
            # Expect a prompt for the password.
            prompt2 = self.sock.recv(1024).decode()
            # Send the password.
            self.sock.sendall(password.encode())
            # Receive the final response.
            response = self.sock.recv(1024).decode()
            if "successful" in response:
                self.master.after(0, self.show_chat_frame)
            else:
                self.master.after(0, lambda: self.login_frame.set_error(response))
        except Exception as e:
            self.master.after(0, lambda: self.login_frame.set_error("Registration error: " + str(e)))

    def show_chat_frame(self):
        # Hide the login frame.
        self.login_frame.pack_forget()
        # Create and show the chat frame.
        self.chat_frame = ChatFrame(self.master, self.send_message)
        self.chat_frame.pack(fill="both", expand=True)
        # Start a thread to receive chat messages.
        self.chat_thread = threading.Thread(target=self.chat_receive, daemon=True)
        self.chat_thread.start()
        # Begin polling the message queue.
        self.master.after(100, self.poll_queue)

    def send_message(self, message):
        try:
            self.sock.sendall(message.encode())
            if message.lower() == "logoff":
                self.running = False
        except Exception as e:
            if self.chat_frame:
                self.chat_frame.append_message("Error sending message: " + str(e))

    def chat_receive(self):
        while self.running:
            try:
                data = self.sock.recv(1024)
                if not data:
                    self.msg_queue.put("Server closed connection.")
                    break
                self.msg_queue.put(data.decode())
            except Exception as e:
                self.msg_queue.put("Receive error: " + str(e))
                break
        self.running = False

    def poll_queue(self):
        try:
            while True:
                msg = self.msg_queue.get_nowait()
                if self.chat_frame:
                    self.chat_frame.append_message(msg)
        except queue.Empty:
            pass
        if self.running:
            self.master.after(100, self.poll_queue)
        else:
            if self.chat_frame:
                self.chat_frame.append_message("Disconnected.")

    def close(self):
        self.running = False
        try:
            self.sock.close()
        except:
            pass
        self.master.destroy()

########################################################################
# Main entry point
########################################################################
def main():
    root = tk.Tk()
    app = ClientApp(root)
    root.protocol("WM_DELETE_WINDOW", app.close)
    root.mainloop()

if __name__ == "__main__":
    main()