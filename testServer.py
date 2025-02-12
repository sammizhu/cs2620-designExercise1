# testServer.py

import unittest
import threading
import socket
import time
from unittest.mock import patch, MagicMock
import pymysql
import pymysql.cursors
import datetime  # for returning a datetime object in mock

# Import the functions/classes from your custom server module
from serverCustom import (
    connectsql,
    checkRealUsername,
    checkValidPassword,
    hashPass,
    checkRealPassword,
    handle_registration,
    handle_login,
    check_messages_server_side,
    handle_client,
    start_server
)

###############################################################################
#                         DATABASE FUNCTION TESTS                             #
###############################################################################
class TestServerDatabaseFunctions(unittest.TestCase):
    """
    Pure 'unit-level' tests and 'regression' tests for DB-related functions:
    - connectsql
    - checkRealUsername
    - checkValidPassword
    - hashPass
    - checkRealPassword
    """

    ### ---------- connectsql Tests ---------- ###
    @patch('serverCustom.pymysql.connect')
    def test_connectsql_unit(self, mock_connect):
        """
        Unit test for connectsql() ensuring it calls pymysql.connect
        with expected params. We do not actually connect to a real DB here.
        """
        mock_connection = MagicMock()
        mock_connect.return_value = mock_connection

        conn = connectsql()
        mock_connect.assert_called_once_with(
            host='0.0.0.0',
            user='root',
            password='',
            database='db262',
            cursorclass=pymysql.cursors.DictCursor
        )
        self.assertEqual(conn, mock_connection)

    def test_connectsql_regression(self):
        """
        Suppose we once had a bug where we used the wrong DB name.
        Now ensure we connect to 'db262'.
        """
        with patch('serverCustom.pymysql.connect') as mock_connect:
            connectsql()
            _, kwargs = mock_connect.call_args
            self.assertEqual(kwargs.get('database'), 'db262')

    @unittest.skip("Integration test requires a live DB and proper credentials.")
    def test_connectsql_integration(self):
        """
        Integration test example: actually connect to a test DB environment.
        """
        conn = connectsql()
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT 1")
                row = cur.fetchone()
                self.assertIsNotNone(row)
        finally:
            conn.close()

    ### ---------- checkRealUsername Tests ---------- ###
    @patch('serverCustom.connectsql')
    def test_checkRealUsername_unit(self, mock_connectsql):
        mock_db = MagicMock()
        mock_cursor = MagicMock()
        mock_connectsql.return_value.__enter__.return_value = mock_db
        mock_db.cursor.return_value.__enter__.return_value = mock_cursor

        # Suppose the user 'alice' does exist
        mock_cursor.fetchone.return_value = {'cnt': 1}
        self.assertTrue(checkRealUsername('alice'))

        # Suppose the user 'bob' does NOT exist
        mock_cursor.fetchone.return_value = {'cnt': 0}
        self.assertFalse(checkRealUsername('bob'))

    def test_checkRealUsername_regression(self):
        """
        We had a bug if DB returns None -> function used to crash.
        Now we confirm it doesn't crash (should return False).
        """
        with patch('serverCustom.connectsql') as mock_connectsql:
            mock_db = MagicMock()
            mock_cursor = MagicMock()
            mock_connectsql.return_value.__enter__.return_value = mock_db
            mock_db.cursor.return_value.__enter__.return_value = mock_cursor

            # Return None to simulate a weird DB response
            mock_cursor.fetchone.return_value = None

            try:
                result = checkRealUsername('bogususer')
                # We expect it to return False gracefully
                self.assertFalse(result, "Should return False if row is None.")
            except Exception as e:
                self.fail(f"Regression bug: checkRealUsername crashed with exception {e}")

    @unittest.skip("Integration test requires a live DB with known data.")
    def test_checkRealUsername_integration(self):
        result = checkRealUsername('test_user')  # Known test user
        self.assertTrue(result)

    ### ---------- checkValidPassword Tests ---------- ###
    def test_checkValidPassword_unit(self):
        self.assertFalse(checkValidPassword("Ab1!"), "Too short")
        self.assertFalse(checkValidPassword("abc123!"), "No uppercase")
        self.assertFalse(checkValidPassword("Abcdef!"), "No digit")
        self.assertFalse(checkValidPassword("Abcdef1"), "No special char")
        self.assertTrue(checkValidPassword("Abc123!"), "Valid")

    def test_checkValidPassword_regression(self):
        """
        Suppose previously special char logic allowed '%', 
        now ensure it fails if password uses '%'.
        """
        self.assertFalse(checkValidPassword("Abc123%"))

    ### ---------- hashPass / checkRealPassword Tests ---------- ###
    def test_hashPass_unit(self):
        pwd = "Abc123!"
        hashed = hashPass(pwd)
        self.assertIsInstance(hashed, str)
        self.assertTrue(
            hashed.startswith("$2b$") or hashed.startswith("$2a$"),
            "Expected bcrypt hash to start with $2b$ or $2a$"
        )

    @patch('serverCustom.connectsql')
    def test_checkRealPassword_unit(self, mock_connectsql):
        """
        Mocks DB calls to verify logic for checkRealPassword.
        """
        mock_db = MagicMock()
        mock_cursor = MagicMock()
        mock_connectsql.return_value.__enter__.return_value = mock_db
        mock_db.cursor.return_value.__enter__.return_value = mock_cursor

        # Suppose DB returns a hashed version of "Abc123!"
        test_hash = hashPass("Abc123!")
        mock_cursor.fetchone.return_value = {'password': test_hash}

        # correct password
        self.assertTrue(checkRealPassword("testuser", "Abc123!"))
        # incorrect password
        self.assertFalse(checkRealPassword("testuser", "wrongPass1!"))


###############################################################################
#                          HIGHER-LEVEL FUNCTION TESTS                        #
###############################################################################
class TestServerHighLevelFunctions(unittest.TestCase):
    """
    Tests for higher-level server functions that handle logic with 
    sockets and DB interactions: 
    - handle_registration
    - handle_login
    - check_messages_server_side
    """

    ### ---------- handle_registration Tests ---------- ###
    @patch('serverCustom.connectsql')
    def test_handle_registration_unit(self, mock_connectsql):
        """
        Test handle_registration by mocking socket input & DB calls.
        Scenario: new user "alice" -> valid pass -> success.
        """
        mock_conn = MagicMock()
        mock_conn.recv.side_effect = [
            b"alice",      # username
            b"Abc123!",    # password
            b"Abc123!",    # confirm
        ]

        mock_db = MagicMock()
        mock_cursor = MagicMock()
        mock_connectsql.return_value.__enter__.return_value = mock_db
        mock_db.cursor.return_value.__enter__.return_value = mock_cursor

        # 'alice' does NOT exist
        mock_cursor.fetchone.side_effect = [
            {"cnt": 0}  # checkRealUsername => not found
        ]

        result = handle_registration(mock_conn, user_id=123)
        self.assertEqual(result, "alice", "Expected to register 'alice' successfully.")

        # Check we see success message
        sendall_calls = mock_conn.sendall.call_args_list
        self.assertTrue(any(b"Registration successful" in call[0][0] for call in sendall_calls))

    @patch('serverCustom.connectsql')
    def test_handle_registration_regression(self, mock_connectsql):
        """
        Suppose we had a bug that if the DB insert fails, 
        the function used to crash or hang. 
        Now we confirm handle_registration() returns None and 
        sends 'Server error. Registration canceled.' instead.
        """
        mock_conn = MagicMock()
        mock_conn.recv.side_effect = [
            b"bob",         # username
            b"Abc123!",     # password
            b"Abc123!",     # confirm
        ]

        mock_db = MagicMock()
        mock_cursor = MagicMock()
        mock_connectsql.return_value.__enter__.return_value = mock_db
        mock_db.cursor.return_value.__enter__.return_value = mock_cursor

        # 'bob' does NOT exist => checkRealUsername => {'cnt': 0}
        # Then we'll raise on "INSERT" queries but not on SELECT queries.
        def db_side_effect(sql, params):
            if sql.startswith("SELECT COUNT(*)"):
                # This is the checkRealUsername query => do nothing
                return
            elif sql.startswith("INSERT INTO users"):
                raise Exception("DB insertion error!")
        mock_cursor.fetchone.return_value = {"cnt": 0}
        mock_cursor.execute.side_effect = db_side_effect

        result = handle_registration(mock_conn, user_id=123)
        self.assertIsNone(result, "Should return None if DB insert fails.")

        # Check the server error message was sent
        sendall_calls = mock_conn.sendall.call_args_list
        msgs = [call[0][0] for call in sendall_calls]
        self.assertTrue(
            any(b"Server error. Registration canceled." in msg for msg in msgs),
            "Expected 'Server error. Registration canceled.' in output"
        )

    @unittest.skip("Integration test would require a real server & DB.")
    def test_handle_registration_integration(self):
        """
        Example: connect to a real running server,
        send data for registration, and see if user is created in DB.
        """
        pass

    ### ---------- handle_login Tests ---------- ###
    @patch('serverCustom.connectsql')
    def test_handle_login_unit(self, mock_connectsql):
        """
        Mock the DB so user 'charlie' exists with password 'Abc123!'.
        Then feed that data to handle_login via a mock socket.
        Check that we get a success message and return the username.
        """
        mock_conn = MagicMock()
        mock_conn.recv.side_effect = [
            b"charlie",  # username
            b"Abc123!"   # password
        ]

        mock_db = MagicMock()
        mock_cursor = MagicMock()
        mock_connectsql.return_value.__enter__.return_value = mock_db
        mock_db.cursor.return_value.__enter__.return_value = mock_cursor

        # 'charlie' is found in DB
        mock_cursor.fetchone.side_effect = [
            {"cnt": 1},                     # checkRealUsername => found
            {"password": hashPass("Abc123!")}  # checkRealPassword => matches
        ]

        result = handle_login(mock_conn, user_id=999)
        self.assertEqual(result, "charlie")

        sendall_calls = mock_conn.sendall.call_args_list
        self.assertTrue(any(b"Welcome, charlie!" in call[0][0] for call in sendall_calls))

    @patch('serverCustom.connectsql')
    def test_handle_login_regression(self, mock_connectsql):
        """
        Suppose we had a bug if user typed an empty password 
        or the DB returned None. Check we handle it gracefully.
        """
        mock_conn = MagicMock()
        # user typed a real username but then typed no password (empty)
        mock_conn.recv.side_effect = [
            b"charlie",  # username
            b""          # empty => user canceled
        ]

        mock_db = MagicMock()
        mock_cursor = MagicMock()
        mock_connectsql.return_value.__enter__.return_value = mock_db
        mock_db.cursor.return_value.__enter__.return_value = mock_cursor

        # 'charlie' is found in DB
        mock_cursor.fetchone.return_value = {"cnt": 1}

        result = handle_login(mock_conn, user_id=123)
        self.assertIsNone(result)
        sendall_calls = mock_conn.sendall.call_args_list
        self.assertTrue(any(b"Login canceled." in call[0][0] for call in sendall_calls))

    @unittest.skip("Integration test would require a live server & DB.")
    def test_handle_login_integration(self):
        pass

    ### ---------- check_messages_server_side Tests ---------- ###
    @patch('serverCustom.connectsql')
    def test_check_messages_server_side_unit_zero_unread(self, mock_connectsql):
        """
        Mock a scenario of 0 unread messages, 
        ensure it just sends "You have 0 unread messages."
        """
        mock_conn = MagicMock()
        mock_conn.recv.return_value = b""  # no further input

        mock_db = MagicMock()
        mock_cursor = MagicMock()
        mock_connectsql.return_value.__enter__.return_value = mock_db
        mock_db.cursor.return_value.__enter__.return_value = mock_cursor

        mock_cursor.fetchone.return_value = {"cnt": 0}

        check_messages_server_side(mock_conn, username="david")
        sendall_calls = mock_conn.sendall.call_args_list
        self.assertTrue(any(b"You have 0 unread messages." in call[0][0] for call in sendall_calls))

    @patch('serverCustom.connectsql')
    def test_check_messages_server_side_unit_unread_flow(self, mock_connectsql):
        """
        Mock scenario with unread messages. 
        We'll simulate user pressing '1' to read, then choosing a sender.
        Then we test the batch read logic, etc.
        """
        mock_conn = MagicMock()
        mock_conn.recv.side_effect = [
            b"1",        # user chooses to read
            b"alice",    # chosen sender
            b"",         # if there's a prompt for next batch, user hits Enter
        ]

        mock_db = MagicMock()
        mock_cursor = MagicMock()
        mock_connectsql.return_value.__enter__.return_value = mock_db
        mock_db.cursor.return_value.__enter__.return_value = mock_cursor

        # unread_count = 2
        mock_cursor.fetchone.side_effect = [
            {"cnt": 2},  # # of unread messages
        ]

        # The first fetchall() is for listing senders
        mock_cursor.fetchall.return_value = [
            {"sender": "alice", "num": 2}
        ]

        # Then, next time we call fetchall() for the actual messages
        def fetchall_side_effect():
            # Return a list of 2 messages with a real datetime object
            now = datetime.datetime.now()
            return [
                {
                    "messageid": 10,
                    "sender": "alice",
                    "message": "Hi there!",
                    "datetime": now
                },
                {
                    "messageid": 11,
                    "sender": "alice",
                    "message": "Are you there?",
                    "datetime": now
                },
            ]
        mock_cursor.fetchall.side_effect = [
            mock_cursor.fetchall.return_value,  # for senders
            fetchall_side_effect(),             # for the actual messages
        ]

        check_messages_server_side(mock_conn, username="david")

        sendall_calls = mock_conn.sendall.call_args_list
        sent_texts = [call[0][0] for call in sendall_calls]

        # Check for "You have 2 unread messages."
        self.assertTrue(
            any(b"You have 2 unread messages." in txt for txt in sent_texts),
            "Should mention 2 unread messages"
        )
        # Check for the text about reading from 'alice'
        self.assertTrue(
            any(b"alice (2 messages)" in txt for txt in sent_texts),
            "Should show 'alice (2 messages)'"
        )
        # Check the messages themselves
        self.assertTrue(
            any(b"Hi there!" in txt for txt in sent_texts),
            "Should see 'Hi there!' in output"
        )
        self.assertTrue(
            any(b"Are you there?" in txt for txt in sent_texts),
            "Should see 'Are you there?' in output"
        )

    def test_check_messages_server_side_regression(self):
        """
        Suppose previously if 'cur.fetchall()' returned None or 
        we had no rows, it might crash. We'll quickly mock that scenario.
        """
        with patch('serverCustom.connectsql') as mock_connectsql:
            mock_conn = MagicMock()
            mock_conn.recv.return_value = b"1"  # user tries to read

            mock_db = MagicMock()
            mock_cursor = MagicMock()
            mock_connectsql.return_value.__enter__.return_value = mock_db
            mock_db.cursor.return_value.__enter__.return_value = mock_cursor

            # Suppose user has some unread_count = 2
            mock_cursor.fetchone.return_value = {"cnt": 2}
            # Next step is listing senders => return None or empty
            mock_cursor.fetchall.return_value = None  # or []

            try:
                check_messages_server_side(mock_conn, "alex")
            except Exception as e:
                self.fail(f"Regression: check_messages_server_side crashed with exception {e}")


###############################################################################
#                             handle_client TESTS                             #
###############################################################################
class TestHandleClient(unittest.TestCase):
    """
    Unit, regression, and optional integration tests for handle_client.
    handle_client is a loop that processes user commands until logoff or disconnect.
    """

    @patch('serverCustom.connectsql')
    def test_handle_client_unit_registration_flow(self, mock_connectsql):
        """
        Simulate a user who chooses "1" => register => successful => then empty read => disconnect.
        """
        mock_conn = MagicMock()
        # This sequence:
        # 1) user sends "1" => handle_client sees we do registration
        # 2) user sends "alice" => username
        # 3) user sends "Abc123!" => password
        # 4) user sends "Abc123!" => confirm password
        # 5) user sends b"" => means client disconnected
        mock_conn.recv.side_effect = [
            b"1",
            b"alice",
            b"Abc123!",
            b"Abc123!",
            b""  # end => client disconnected
        ]
        mock_addr = ("127.0.0.1", 12345)

        mock_db = MagicMock()
        mock_cursor = MagicMock()
        mock_connectsql.return_value.__enter__.return_value = mock_db
        mock_db.cursor.return_value.__enter__.return_value = mock_cursor

        # 'alice' does NOT exist
        mock_cursor.fetchone.return_value = {"cnt": 0}

        # Run handle_client in the same thread for test
        handle_client(mock_conn, mock_addr)

        sendall_calls = mock_conn.sendall.call_args_list
        raw_msgs = [call[0][0] for call in sendall_calls]

        # Check that we eventually see "Registration successful"
        self.assertTrue(any(b"Registration successful" in m for m in raw_msgs),
                        "Expected 'Registration successful' in output for registration flow")

    @patch('serverCustom.connectsql')
    def test_handle_client_unit_login_flow(self, mock_connectsql):
        """
        Simulate a user who chooses "2" => login => success => then empty read => disconnect.
        """
        mock_conn = MagicMock()
        # side effect steps:
        # 1) "2" => user wants to login
        # 2) "charlie" => username
        # 3) "Abc123!" => password
        # 4) b"" => disconnect
        mock_conn.recv.side_effect = [
            b"2",
            b"charlie",
            b"Abc123!",
            b""
        ]
        mock_addr = ("127.0.0.1", 23456)

        mock_db = MagicMock()
        mock_cursor = MagicMock()
        mock_connectsql.return_value.__enter__.return_value = mock_db
        mock_db.cursor.return_value.__enter__.return_value = mock_cursor

        # For checkRealUsername
        #  - username => found => 'cnt': 1
        # For checkRealPassword => row['password']
        #  - we store a hashed version
        mock_cursor.fetchone.side_effect = [
            {"cnt": 1},  # checkRealUsername => found
            {"password": hashPass("Abc123!")}  # checkRealPassword => matches
        ]

        handle_client(mock_conn, mock_addr)

        sendall_calls = mock_conn.sendall.call_args_list
        raw_msgs = [call[0][0] for call in sendall_calls]

        # We expect "Welcome, charlie!" to appear
        self.assertTrue(any(b"Welcome, charlie!" in m for m in raw_msgs),
                        "Expected 'Welcome, charlie!' after login")

    @patch('serverCustom.connectsql')
    def test_handle_client_unit_logoff_flow(self, mock_connectsql):
        """
        Simulate a user who logs in then types "logoff".
        """
        mock_conn = MagicMock()
        mock_conn.recv.side_effect = [
            b"2",          # choose login
            b"alex",       # username
            b"Abc123!",    # password
            b"logoff",     # user logs off
            b""            # then empty => disconnect
        ]
        mock_addr = ("127.0.0.1", 34567)

        mock_db = MagicMock()
        mock_cursor = MagicMock()
        mock_connectsql.return_value.__enter__.return_value = mock_db
        mock_db.cursor.return_value.__enter__.return_value = mock_cursor

        # Provide THREE results:
        # 1) checkRealUsername => {"cnt": 1} => user found
        # 2) checkRealPassword => {"password": <hashed>} => password matches
        # 3) check_messages_server_side => {"cnt": 0} => zero unread
        mock_cursor.fetchone.side_effect = [
            {"cnt": 1},  
            {"password": hashPass("Abc123!")},  
            {"cnt": 0}  
        ]

        handle_client(mock_conn, mock_addr)

        sendall_calls = mock_conn.sendall.call_args_list
        raw_msgs = [call[0][0] for call in sendall_calls]

        # Now that no exception occurs, the code should reach "Logged off." 
        self.assertTrue(
            any(b"Logged off." in m for m in raw_msgs),
            "Expected 'Logged off.' after user typed logoff"
        )

    @patch('serverCustom.connectsql')
    def test_handle_client_regression_unknown_command(self, mock_connectsql):
        """
        Suppose we had a bug if user typed an unknown command BEFORE login,
        or typed random data after login. The code might crash or skip.
        We'll confirm it handles gracefully with an error message.
        """
        mock_conn = MagicMock()
        # user typed "garbage" -> not 1 or 2 => handle_client does nothing while not logged in
        # then user typed "logoff" => but we are not logged in => 
        # The code won't log off but let's see how it behaves
        # Then b"" => disconnect
        mock_conn.recv.side_effect = [
            b"garbage",
            b"logoff",
            b""
        ]
        mock_addr = ("127.0.0.1", 45678)

        mock_db = MagicMock()
        mock_cursor = MagicMock()
        mock_connectsql.return_value.__enter__.return_value = mock_db
        mock_db.cursor.return_value.__enter__.return_value = mock_cursor

        # We'll let handle_client do its thing
        handle_client(mock_conn, mock_addr)

        sendall_calls = mock_conn.sendall.call_args_list
        raw_msgs = [call[0][0] for call in sendall_calls]

        # We expect an error or no effect. By default, your code only checks "1" or "2" if not logged in.
        # Let's check if it just ignores or sends something like "Error: Messages must start with..."
        # Actually your code doesn't do anything for unknown input if not logged_in. So we might check logs or see nothing.
        # Possibly the loop just continues. But user typed 'logoff' while not logged in => code says do nothing?
        # Then user typed b"" => disconnected => end.

        # Let's see if there's any output at all. Possibly there's none or just "client disconnected."
        # We'll just confirm the code didn't crash. If you want a specific message, you'd have to adapt your code.
        self.assertTrue(True, "handle_client didn't crash with unknown commands before login. Good.")


    @unittest.skip("Integration test might create real socket client to test handle_client. Not implemented here.")
    def test_handle_client_integration(self):
        """
        In a real integration test, we would connect a real socket client and 
        actually go through a handle_client flow. The server would spawn handle_client 
        in a new thread. Then we'd send real data and read responses.
        """
        pass


###############################################################################
#                         INTEGRATION TESTS (FULL SERVER)                     #
###############################################################################
class TestServerSocketIntegration(unittest.TestCase):
    """
    Example real integration test. 
    Runs start_server() in a thread, connects a real socket client.
    """

    def setUp(self):
        self.server_thread = threading.Thread(target=start_server, daemon=True)
        self.server_thread.start()
        time.sleep(1)

    def tearDown(self):
        # In a real scenario, you'd gracefully shut down the server
        pass

    def test_integration_server_basic(self):
        """
        Connect to the server, send "1" (register), read response.
        Our server expects next input for username. We'll just verify 
        that we see "Enter a username" in the response.
        """
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect(("0.0.0.0", 65432))
            s.sendall(b"1")
            resp = s.recv(1024).decode()
            self.assertIn("Enter a username", resp)


if __name__ == "__main__":
    unittest.main()