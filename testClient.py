#!/usr/bin/env python3
"""
testClient.py

This file contains unit, regression, and integration tests for the chat client.
We create a subclass (TestableChatClient) that does not call mainloop() so tests can run.
We also simulate socket responses using a fake socket (FakeSocketClient).

Usage:
  python -m unittest testClient.py
"""

import unittest
from unittest.mock import patch, MagicMock
import tkinter as tk
from tkinter import scrolledtext
import threading
import socket
import queue

# Import the client module
# (Make sure the original client code is saved as clientCustom.py in the same directory.)
import clientCustom as client

# -------------------------------------------------------------------
# A Testable subclass of ChatClient that does not call mainloop
# -------------------------------------------------------------------
class TestableChatClient(client.ChatClient):
    def __init__(self):
        # Instead of calling super().__init__(), we replicate the setup to avoid mainloop.
        self.root = tk.Tk()
        self.root.title("Test Chat Client")
        self.socket = None
        self.receive_queue = queue.Queue()
        self.running = False  # Flag for the receiving thread

        # Create the frames, but do NOT call mainloop().
        self.welcome_frame = tk.Frame(self.root)
        self.login_frame = tk.Frame(self.root)
        self.register_frame = tk.Frame(self.root)
        self.chat_frame = tk.Frame(self.root)

        self.build_welcome_frame()
        self.build_login_frame()
        self.build_register_frame()
        self.build_chat_frame()

    def destroy(self):
        try:
            self.root.destroy()
        except tk.TclError:
            # In case the widget has already been destroyed
            pass

# -------------------------------------------------------------------
# A fake socket for client tests
# -------------------------------------------------------------------
class FakeSocketClient:
    """
    A fake socket for simulating server responses in the client.
    Initialize with a list of responses. The client will call recv()
    to get these responses in order.
    """
    def __init__(self, responses):
        self.responses = responses[:]  # copy so original isn’t modified
        self.sent_messages = []
        self.closed = False

    def sendall(self, data):
        self.sent_messages.append(data.decode())

    def recv(self, bufsize):
        if self.responses:
            return self.responses.pop(0).encode()
        return "".encode()  # No more responses

    def connect(self, address):
        # For testing we do nothing
        pass

    def close(self):
        self.closed = True

# -------------------------------------------------------------------
# UNIT TESTS
# -------------------------------------------------------------------
class TestClientUnit(unittest.TestCase):
    """
    Unit Tests focus on verifying individual functions and small units of behavior 
    within ChatClient, without full end-to-end interactions.
    """
    def setUp(self):
        self.client = TestableChatClient()

    def tearDown(self):
        self.client.destroy()

    def test_build_welcome_frame(self):
        """Check that the welcome frame is built and has children."""
        children = self.client.welcome_frame.winfo_children()
        self.assertGreater(len(children), 0, "Welcome frame should have child widgets.")

    def test_show_welcome_page(self):
        """Check that show_welcome_page hides other frames and shows the welcome frame."""
        self.client.welcome_frame.pack = MagicMock()
        self.client.login_frame.pack_forget = MagicMock()
        self.client.register_frame.pack_forget = MagicMock()
        self.client.chat_frame.pack_forget = MagicMock()

        self.client.show_welcome_page()
        self.client.welcome_frame.pack.assert_called()
        self.client.login_frame.pack_forget.assert_called()
        self.client.register_frame.pack_forget.assert_called()
        self.client.chat_frame.pack_forget.assert_called()

    def test_append_message(self):
        """Verify append_message inserts text into the chat_display widget."""
        self.client.chat_display.configure(state='normal')
        self.client.chat_display.delete("1.0", tk.END)
        self.client.append_message("Test message", sent_by_me=True)
        content = self.client.chat_display.get("1.0", tk.END)
        self.assertIn("Test message", content, "Message should be appended to chat display.")

    def test_send_message(self):
        """Check that send_message uses the entry text, appends it, and sends over socket."""
        fake_socket = FakeSocketClient([])
        self.client.socket = fake_socket
        self.client.message_entry.insert(0, "Hello world")

        self.client.send_message()
        self.assertIn("Hello world", fake_socket.sent_messages,
                      "Message entry content should be sent via socket.")

    def test_on_close(self):
        """Ensure on_close sends logoff and closes the socket."""
        fake_socket = FakeSocketClient([])
        self.client.socket = fake_socket

        with patch.object(fake_socket, 'sendall') as mock_sendall, \
             patch.object(fake_socket, 'close') as mock_close:
            self.client.on_close()
            mock_sendall.assert_called_with("logoff".encode())
            mock_close.assert_called()

    def test_poll_receive_queue(self):
        """Verify poll_receive_queue takes messages from queue and calls append_message."""
        self.client.append_message = MagicMock()
        self.client.receive_queue.put("Test from queue")
        self.client.running = False  # so that after processing queue, we show "Disconnected."

        self.client.poll_receive_queue()

        # Extract messages from the mock's call arguments
        messages = [call.args[0] for call in self.client.append_message.call_args_list]
        self.assertIn("Test from queue", messages)
        self.assertIn("Disconnected.", messages)

# -------------------------------------------------------------------
# REGRESSION TESTS
# -------------------------------------------------------------------
class TestClientRegression(unittest.TestCase):
    """
    Regression Tests focus on preventing known bugs or regressions.
    These tests often replicate previous bug scenarios or stress key code paths
    that have historically failed.
    """
    def setUp(self):
        self.client = TestableChatClient()

    def tearDown(self):
        self.client.destroy()

    def test_invalid_username_handling(self):
        """
        Previously, the client might have crashed if the username was empty 
        or had invalid characters. We'll confirm it handles that gracefully.
        """
        # We won't mock the socket here to show that the client won't crash
        # even if we do "something" invalid with the username.
        self.client.login_username_var.set("")  # empty username
        self.client.login_password_var.set("Abcdef1!")

        # Instead of calling login_thread directly, we might just check the internal logic
        # or do a partial check that it doesn't break.
        try:
            self.client.login_thread("", "Abcdef1!")
        except Exception as e:
            self.fail(f"Client crashed with empty username: {e}")

    def test_extra_long_username(self):
        """
        Check that a very long username doesn't cause crashes or issues in the GUI.
        This is a typical regression scenario if there was a buffer handling bug.
        """
        long_username = "x" * 500
        self.client.login_username_var.set(long_username)
        self.client.login_password_var.set("Abcdef1!")
        try:
            self.client.login_thread(long_username, "Abcdef1!")
        except Exception as e:
            self.fail(f"Client crashed with extra long username: {e}")

    def test_unexpected_server_message(self):
        """
        If the server sends an unexpected or malformed message,
        ensure the client doesn't crash. We simulate that with a FakeSocketClient.
        """
        responses = ["GarbageDataThatDoesNotConform"]
        fake_socket = FakeSocketClient(responses)
        self.client.socket = fake_socket

        # Try polling the receive queue (as if messages were incoming).
        # We'll pretend we started receiving.
        self.client.running = True
        # Start "fake receiving" in a thread if necessary.
        # For a direct approach, call poll_receive_queue:
        try:
            self.client.receive_queue.put(fake_socket.recv(1024).decode())
            self.client.poll_receive_queue()
        except Exception as e:
            self.fail(f"Client crashed when receiving unexpected server message: {e}")

# -------------------------------------------------------------------
# INTEGRATION TESTS
# -------------------------------------------------------------------
class TestClientIntegration(unittest.TestCase):
    """
    Integration Tests check how the client interacts with a (fake) server socket
    and transitions through different frames (login -> chat, register -> error, etc.).
    """
    def setUp(self):
        self.client = TestableChatClient()

    def tearDown(self):
        self.client.destroy()

    @patch('socket.socket')
    def test_login_thread_success(self, mock_socket_class):
        """
        Simulate a successful login conversation:
          - The client sends '2' for login choice
          - Then username/password
          - The final server response indicates success.
        """
        responses = [
            "Prompt after sending '2'",
            "Prompt after sending username",
            "Welcome, testuser!"
        ]
        fake_socket = FakeSocketClient(responses)
        mock_socket_class.return_value = fake_socket

        self.client.login_username_var.set("testuser")
        self.client.login_password_var.set("Abcdef1!")

        self.client.login_thread("testuser", "Abcdef1!")
        # Process pending events so that show_chat_page is (potentially) called
        self.client.root.update()

        # Check that the chat frame got packed, implying success
        try:
            _ = self.client.chat_frame.pack_info()
            # If we get here, it is packed
        except tk.TclError:
            self.fail("Chat frame is not packed after successful login.")

    @patch('socket.socket')
    def test_register_thread_failure(self, mock_socket_class):
        """
        Simulate registration failure:
          - The server returns "Error: Username taken."
          - The client should display that error in register_error_label.
        """
        responses = [
            "Prompt after sending '1'",
            "Prompt after sending username",
            "Prompt after sending password",
            "Error: Username taken."
        ]
        fake_socket = FakeSocketClient(responses)
        mock_socket_class.return_value = fake_socket

        self.client.reg_username_var.set("existinguser")
        self.client.reg_password_var.set("Abcdef1!")
        self.client.reg_confirm_var.set("Abcdef1!")

        self.client.register_thread("existinguser", "Abcdef1!", "Abcdef1!")
        # Process pending events so that the error label updates
        self.client.root.update()

        error_text = self.client.register_error_label.cget("text")
        self.assertIn("Error", error_text, "Expected an error message on registration failure.")

# -------------------------------------------------------------------
# Main entry point for running tests
# -------------------------------------------------------------------
if __name__ == '__main__':
    unittest.main()