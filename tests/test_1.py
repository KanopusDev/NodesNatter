import sys
import os
import pytest
import socket
import json
from unittest.mock import patch, MagicMock, ANY  # Add ANY to imports

# Add the directory containing server.py and client.py to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from server import ChatServer, Database
from client import ChatClient, UIManager

@pytest.fixture
def setup_database():
    db = Database()
    db.create_tables()
    db.add_user("testuser", "testpass")
    yield db
    db.conn.close()

def test_user_authentication(setup_database):
    db = setup_database
    user = db.verify_user("testuser", "testpass")
    assert user is not None
    assert user[1] == "testuser"

def test_invalid_user_authentication(setup_database):
    db = setup_database
    user = db.verify_user("invaliduser", "invalidpass")
    assert user is None

def test_log_message(setup_database):
    db = setup_database
    db.log_message("testuser", "Hello, world!")
    messages = db.get_message_history(limit=1)
    assert len(messages) == 1
    assert messages[0][0] == "testuser"
    assert messages[0][1] == "Hello, world!"

@pytest.fixture
def setup_server():
    server = ChatServer(host="127.0.0.1", port=12345)
    server.clients = {MagicMock(): {'username': 'testuser'}}
    return server

def test_broadcast_message(setup_server):
    server = setup_server
    mock_client = list(server.clients.keys())[0]
    server.broadcast("Hello, everyone!", "system")
    
    # Get the actual call arguments
    call_args = mock_client.send.call_args[0][0].decode()
    sent_data = json.loads(call_args.strip())  # Remove newline and parse JSON
    
    # Verify the message structure
    assert sent_data['type'] == 'message'
    assert sent_data['message'] == "Hello, everyone!"
    assert sent_data['msg_type'] == "system"
    assert isinstance(sent_data['timestamp'], str)  # Verify timestamp is a string
    
    # Verify the message was sent only once
    mock_client.send.assert_called_once()

@pytest.fixture
def setup_client():
    client = ChatClient(host="127.0.0.1", port=12345)
    client.socket = MagicMock()
    client.ui = MagicMock()  # Initialize the UI mock
    return client

def test_send_message(setup_client):
    client = setup_client
    msg_data = {
        'type': 'message',
        'message': 'Hello, world!',
        'id': 'test_id',
        'sender': 'testuser',
        'timestamp': '2024-11-30T12:00:00'
    }
    client.send_message(msg_data)
    # Include newline in expected message
    expected_message = json.dumps(msg_data) + '\n'
    client.socket.sendall.assert_called_once_with(expected_message.encode())

def test_handle_command(setup_client):
    client = setup_client
    client.socket = MagicMock()
    client.handle_command('/help')
    client.socket.send.assert_called_once()
    sent_command = json.loads(client.socket.send.call_args[0][0].decode())
    assert sent_command['type'] == 'command'
    assert sent_command['message'] == '/help'

def test_input_processing(mocker, setup_client):
    client = setup_client
    mock_ui = MagicMock()
    mock_ui.get_input.return_value = "Hello, world!"
    client.ui = mock_ui
    # Set running to False after first iteration
    client.running = True
    def stop_after_message(*args, **kwargs):
        client.running = False
    mock_ui.get_input.side_effect = ["Hello, world!", KeyboardInterrupt]

    with patch.object(client, 'send_message') as mock_send:
        client.input_loop()
        mock_send.assert_called_once()
        assert mock_send.call_args[0][0]['message'] == "Hello, world!"

@pytest.fixture
def setup_mock_socket(mocker):
    mock_socket = MagicMock()
    mock_socket.recv.return_value = json.dumps({
        'type': 'message',
        'message': 'Test message',
        'sender': 'server',
        'timestamp': '2024-11-30T12:00:00'
    }).encode()
    return mock_socket

def test_receive_message(setup_client, setup_mock_socket):
    client = setup_client
    client.socket = setup_mock_socket
    client.running = True

    with patch.object(client, 'ui', MagicMock()) as mock_ui:
        client.receive_messages()
        mock_ui.add_message.assert_called_with('server: Test message', 'normal')


