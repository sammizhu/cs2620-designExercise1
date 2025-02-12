# Chat Application Documentation

## Table of Contents
- [Introduction](#introduction)
- [Server Setup](#server-setup)
  - [Requirements](#requirements)
  - [Running the Server](#running-the-server)
- [Client Setup](#client-setup)
  - [Running the Client](#running-the-client)
  - [Using the Client](#using-the-client)
- [Features](#features)
- [Commands](#commands)

## Introduction
This is a simple chat application that consists of a **server** and a **client**. The server manages user authentication, messaging, and storing user messages. The client provides a graphical interface for users to communicate.

## Server Setup
### Requirements
Ensure you have the following installed:
- Python 3.x
- Required Python libraries:
  ```sh
  pip install -r requirements.txt
  ```
- MySQL Database set up with a database named `db262`, and a `users` and `messages` table. First run, `mysql -u root -p db262 < db262.sql`
  to import the sql file. Then run `mysql -u root -p` to enter the sql terminal. Once in, run `USE db262` and then you can use regular sql commands to check your database. 

### Running the Server
There are two servers. One running with JSON and the other via a custom wire protocol. 
-  To run the JSON version, run 
   ```sh
   python serverJSON.py
     ```
-  To run the custom wire protocol version, run 
   ```sh
   python serverCustom.py
   ```

### Running the Client
Note: Make sure you have tkinter installed. 
There are two clients. One running with JSON and the other via a custom wire protocol. 
Howver, if you run a JSON server, you must run a JSON client, vice versa.  
-  To run the JSON version, run 
   ```sh
   python clientJSON.py
     ```
-  To run the custom wire protocol version, run 
   ```sh
   python clientCustom.py
   ```
3. A GUI window should appear for login, registration, and messaging.

### Using the Client
1. **Login or Register:**
   - On the welcome screen, choose "Login" or "Register".
   - If registering, enter a username and a strong password (must contain an uppercase letter, digit, and special character).
   - If logging in, enter your existing credentials.

2. **Messaging:**
   - Once logged in, you can send messages by typing `@username message`.
   - You can check unread messages by typing `check`.
   - Log off by typing `logoff`.
   
## Features
- **User Authentication:** Register and log in securely.
- **Messaging System:** Send direct messages to registered users.
- **Unread Messages:** Unread messages can be viewed upon login. 
    - If there is an overload of messages, the messages will be displayed in batches of 5. 
- **User Management:** Users can delete their last message or deactivate their account.

## Commands
| Command           | Description |
|------------------|-------------|
| `@username message` | Sends a direct message to a user. |
| `check` | Displays unread messages. |
| `logoff` | Logs out from the server. |
| `search` | Lists all registered users. |
| `delete` | Deletes the last sent message. |
| `deactivate` | Permanently deletes your account. |
