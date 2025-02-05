# Rock-Paper-Scissors
# Networked server, human opponent, 3 rounds

from socketHelper import create_new_socket
import client as rlib

HOST = '127.0.0.1'  # Standard loopback interface address (localhost)
PORT = 65432        # Port to listen on (non-privileged ports are > 1023)

def main():
    with create_new_socket() as s:
        s.bind(HOST, PORT)
        s.listen()
        print("ROSHAMBO dumb server started. Listening on", (HOST, PORT))

        conn2client, addr = s.accept()
        with conn2client:
            print('Connected by', addr)
            
            while True:
                msg = conn2client.recv()
                if not msg:
                    break

                # Client narrates the game play, which it sends in the "body"
                # of its message
                print(msg[rlib.HEADER_SZ:])

                if msg[0] == rlib.QUERY_CHOICE:
                    # Match continues. Grab a shape from our player and
                    # send it to the client.
                    choice = rlib.player_choice()
                    conn2client.sendall(choice)

            print('Disconnected')

if __name__ == '__main__':
    main()