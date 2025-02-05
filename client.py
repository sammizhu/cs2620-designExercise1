# Rock-Paper-Scissors
# Networked client, human opponent, 3 rounds

import random
from socketHelper import create_new_socket

shapes = ['rock', 'paper', 'scissors']

HOST = '127.0.0.1'  # The server's hostname or IP address
PORT = 65432        # The port used by the server

'''
My client and server exchange messages in the following simple format:
The message header is one character in size.  It is either `QUERY_CHOICE`
or `STAY_SILENT`. The rest of the message is the body that the server
should always print.
'''
HEADER_SZ = 1
QUERY_CHOICE = 'q'
STAY_SILENT = '!'


def player_choice():
    """ Returns the hand shape selected by the local player. """
    while True:
        choice = input('Please pick your shape: ').lower()
        if choice in shapes:
            break
        print('Not a recognized hand shape. Try again...')
    return choice


def shoot(s, msg):
    """ A roshambo turn.
    Params: A connected socket and a message to send.
    Returns: A tuple. The first element is 1 if user wins, -1 if
    computer wins, and 0 on a tie. The second element is the
    next message to send.
    """
    # Grab a choice from our player. This must come before the
    # blocking call to `recv` that grabs the opponent's choice.
    my_choice = player_choice()

    # Send the current message to the server and get back the
    # opponent's next hand shape.
    s.sendall(msg)
    their_choice = s.recv()

    print(f'You: {my_choice}   Opponent: {their_choice}')
    msg = QUERY_CHOICE + f'You: {their_choice}   Opponent: {my_choice}\n'
    if my_choice == their_choice:
        print("It's a tie!")
        msg += "It's a tie!"
        return 0, msg
    elif ((my_choice == 'rock' and their_choice == 'scissors') or
          (my_choice == 'paper' and their_choice == 'rock') or
          (my_choice == 'scissors' and their_choice == 'paper')):
        print('You win!')
        msg += 'You lose!'
        return 1, msg
    else:
        print('You lose!')
        msg += 'You win!'
        return -1, msg


def main():
    msg = QUERY_CHOICE + '## Welcome to ROSHAMBO! ##'
    print(msg[HEADER_SZ:])

    wins = 0    # number of wins by player
    matches = 0

    # Open the connection to start the match
    with create_new_socket() as s:
        s.connect(HOST, PORT)

        while matches < 3:
            r, msg = shoot(s, msg)
            wins += 1 if r > 0 else 0
            matches += 1 if r != 0 else 0

        # The server needs to print the final round result
        msg = STAY_SILENT + msg[HEADER_SZ:]

        # Print the match result for both the client and server
        print(f'matches = {matches}   wins = {wins}')
        msg += '\n' + f'matches = {matches}   wins = {matches - wins}\n'
        if wins > 1:
            print('You won the match!')
            msg += 'You lost the match!'
        else:
            print('You lost the match!')
            msg += 'You won the match!'
        s.sendall(msg)

if __name__ == '__main__':
    main()