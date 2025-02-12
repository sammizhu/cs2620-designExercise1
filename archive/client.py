import socket
import threading

HOST = '127.0.0.1'
PORT = 65432

def receive_messages(sock):
    while True:
        try:
            data = sock.recv(1024).decode()
            if not data:
                print("Server closed connection.")
                break
            # Print exactly what the server sends (which should include newlines)
            print(data, end="", flush=True)
        except:
            break
    sock.close()

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))

    # Start a background thread to listen/print server messages
    threading.Thread(target=receive_messages, args=(s,), daemon=True).start()

    try:
        # Loop for user input
        while True:
            user_input = input()
            if not user_input:
                continue
            s.sendall(user_input.encode())
            if user_input.lower() == "logoff":
                break
    except KeyboardInterrupt:
        print("Exiting...")
    finally:
        s.close()

if __name__ == "__main__":
    main()