import socket

def main():
    HOST = '127.0.0.1'  # Standard loopback interface address (localhost)
    PORT = 65432        # Port to listen on
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print("Chat server started. Waiting for connection...")
        
        conn, addr = s.accept()
        with conn:
            print(f"Connected by {addr}")
            
            while True:
                data = conn.recv(1024).decode()
                if not data:
                    print("Client disconnected.")
                    break
                print(f"Client: {data}")
                
                response = input("You: ")
                if response.lower() == 'exit':
                    print("Closing connection...")
                    break
                conn.sendall(response.encode())
        
if __name__ == '__main__':
    main()
