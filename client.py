import socket

def main():
    HOST = '127.0.0.1'  # The server's hostname or IP address
    PORT = 65432        # The port used by the server
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        print("Connected to the server. Type your message and press enter.")
        
        while True:
            msg = input("You: ")
            if msg.lower() == 'exit':
                print("Closing connection...")
                break
            s.sendall(msg.encode())
            
            response = s.recv(1024).decode()
            if not response:
                print("Server disconnected.")
                break
            print(f"Server: {response}")
        
if __name__ == '__main__':
    main()