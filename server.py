import argparse
import getpass
import hashlib
import json
import logging
import os
import socket
import sqlite3
import threading
import time
from datetime import datetime
from logging.handlers import RotatingFileHandler

def setup_logging():
    # Create logs directory if it doesn't exist
    os.makedirs('logs', exist_ok=True)
    
    # Configure logging
    logger = logging.getLogger('NodesNatter')
    logger.setLevel(logging.DEBUG)
    
    # File handler with rotation (10MB max size, keep 5 backup files)
    file_handler = RotatingFileHandler(
        'logs/server.log', 
        maxBytes=10*1024*1024, 
        backupCount=5
    )
    file_handler.setLevel(logging.DEBUG)
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    
    # Formatting
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)
    
    # Add handlers
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    return logger

class Database:
    def __init__(self):
        self.conn = sqlite3.connect('chat.db', check_same_thread=False)
        self.cursor = self.conn.cursor()
        self.create_tables()
        
    def create_tables(self):
        # Users table
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                is_admin BOOLEAN DEFAULT 0,
                password_change_required BOOLEAN DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Messages table
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY,
                sender TEXT NOT NULL,
                content TEXT NOT NULL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Logs table
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY,
                event_type TEXT NOT NULL,
                description TEXT NOT NULL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        self.conn.commit()

    def add_user(self, username, password, is_admin=False):
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        try:
            self.cursor.execute(
                'INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)',
                (username, hashed_password, is_admin)
            )
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False

    def verify_user(self, username, password):
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        self.cursor.execute(
            'SELECT * FROM users WHERE username=? AND password=?',
            (username, hashed_password)
        )
        return self.cursor.fetchone()

    def log_message(self, sender, content):
        self.cursor.execute(
            'INSERT INTO messages (sender, content) VALUES (?, ?)',
            (sender, content)
        )
        self.conn.commit()

    def log_event(self, event_type, description):
        self.cursor.execute(
            'INSERT INTO logs (event_type, description) VALUES (?, ?)',
            (event_type, description)
        )
        self.conn.commit()

    def get_user_messages(self, limit=50):
        self.cursor.execute(
            'SELECT * FROM messages ORDER BY timestamp DESC LIMIT ?',
            (limit,)
        )
        return self.cursor.fetchall()

    def is_admin(self, username):
        self.cursor.execute('SELECT is_admin FROM users WHERE username=?', (username,))
        result = self.cursor.fetchone()
        return result[0] if result else False

    def get_all_users(self):
        self.cursor.execute('SELECT * FROM users ORDER BY username')
        return self.cursor.fetchall()

    def delete_user(self, username):
        try:
            self.cursor.execute('DELETE FROM users WHERE username = ?', (username,))
            self.conn.commit()
            return True
        except:
            return False

    def create_initial_admin(self):
        """Create initial admin if default admin doesn't exist"""
        try:
            self.cursor.execute('SELECT * FROM users WHERE username=?', ('demo',))
            if not self.cursor.fetchone():
                self.add_user('demo', 'demo123', is_admin=True)
                self.conn.commit()
                print("Default admin 'demo' created.")
        except Exception as e:
            print(f"Error creating initial admin: {e}")

    def change_password(self, username, new_password):
        try:
            hashed_password = hashlib.sha256(new_password.encode()).hexdigest()
            self.cursor.execute(
                'UPDATE users SET password = ? WHERE username = ?',
                (hashed_password, username)
            )
            self.conn.commit()
            return True
        except:
            return False

    def require_password_change(self, username, required=True):
        try:
            self.cursor.execute(
                'UPDATE users SET password_change_required = ? WHERE username = ?',
                (required, username)
            )
            self.conn.commit()
            return True
        except:
            return False

    def get_message_history(self, limit=50):
        """Get recent message history"""
        try:
            self.cursor.execute('''
                SELECT m.sender, m.content, m.timestamp 
                FROM messages m 
                ORDER BY m.timestamp DESC 
                LIMIT ?
            ''', (limit,))
            messages = self.cursor.fetchall()
            return [(sender, content, timestamp) for sender, content, timestamp in messages][::-1]
        except Exception as e:
            print(f"Error getting message history: {e}")
            return []

class CommandLineInterface:
    def __init__(self):
        self.db = Database()
        
    def authenticate_admin(self):
        username = input("Admin username: ")
        password = getpass.getpass("Admin password: ")
        
        user = self.db.verify_user(username, password)
        if user and self.db.is_admin(username):
            return True
        print("Authentication failed. Must be an admin to use this tool.")
        return False
        
    def add_user(self, username, password, is_admin=False):
        if self.db.add_user(username, password, is_admin):
            print(f"Successfully created {'admin' if is_admin else 'user'}: {username}")
            self.db.log_event('user_creation', f"New {'admin' if is_admin else 'user'} {username} created")
        else:
            print(f"Failed to create user: {username} (might already exist)")
            
    def list_users(self):
        users = self.db.get_all_users()
        print("\nRegistered Users:")
        print("-" * 50)
        print(f"{'Username':<20} {'Admin':<10} {'Created At'}")
        print("-" * 50)
        for user in users:
            print(f"{user[1]:<20} {'Yes' if user[3] else 'No':<10} {user[4]}")
            
    def delete_user(self, username):
        if self.db.delete_user(username):
            print(f"Successfully deleted user: {username}")
            self.db.log_event('user_deletion', f"User {username} deleted")
        else:
            print(f"Failed to delete user: {username}")

    def change_password(self, username, new_password):
        if self.db.change_password(username, new_password):
            print(f"Successfully changed password for user: {username}")
            self.db.log_event('password_change', f"Password changed for {username}")
        else:
            print(f"Failed to change password for user: {username}")

    def reset_password(self, username):
        temp_password = 'changeme123'
        if self.db.change_password(username, temp_password):
            print(f"Password reset for {username}")
            print(f"Temporary password: {temp_password}")
            print("Please ask the user to change their password on next login")
            self.db.log_event('password_reset', f"Password reset for {username}")

class ChatServer:
    def __init__(self, host='0.0.0.0', port=5555):
        self.logger = setup_logging()
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.clients = {}  # {client_socket: {'username': str, 'admin': bool}}
        self.db = Database()
        self.db.create_initial_admin()
        self.message_handlers = {
            'message': self.handle_chat_message,
            'command': self.handle_command,
            'file': self.handle_file_transfer,
            'passwd': self.handle_password_change
        }

    def start(self):
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        self.logger.info(f"Server started on {self.host}:{self.port}")
        while True:
            try:
                client_socket, address = self.server_socket.accept()
                threading.Thread(target=self.handle_client, args=(client_socket, address), daemon=True).start()
            except Exception as e:
                self.logger.error(f"Error accepting connection: {e}")

    def handle_client(self, client_socket, address):
        try:
            username = self.authenticate_client(client_socket)
            if not username:
                client_socket.close()
                return
            self.clients[client_socket] = {'username': username, 'admin': self.db.is_admin(username)}
            self.send_welcome_package(client_socket)
            self.broadcast(f"{username} joined the chat", "system")
            while True:
                msg_data = self.receive_message(client_socket)
                if msg_data:
                    self.process_message(client_socket, msg_data)
                else:
                    break
        except Exception as e:
            self.logger.error(f"Error handling client {address}: {e}")
        finally:
            self.remove_client(client_socket)

    def authenticate_client(self, client_socket):
        try:
            data = client_socket.recv(1024).decode()
            auth_info = json.loads(data)
            username = auth_info.get('username')
            password = auth_info.get('password')
            if self.db.verify_user(username, password):
                client_socket.send("AUTH_SUCCESS".encode())
                self.logger.info(f"User {username} authenticated")
                return username
            else:
                client_socket.send("AUTH_FAILED".encode())
                self.logger.warning(f"Authentication failed for {username}")
                return None
        except Exception as e:
            self.logger.error(f"Authentication error: {e}")
            return None

    def send_welcome_package(self, client_socket):
        """Send initial data to newly connected client"""
        try:
            # Get message history from the database
            history = self.db.get_message_history(limit=50)
            messages = []
            for sender, content, timestamp in history:
                message = {
                    'type': 'message',
                    'message': content,
                    'sender': sender,
                    'timestamp': timestamp,
                    'msg_type': 'history'
                }
                messages.append(message)
            welcome_package = {
                'type': 'history',
                'messages': messages
            }
            self._send_message(client_socket, welcome_package)
        except Exception as e:
            self.logger.error(f"Error sending welcome package: {e}", exc_info=True)
            self.send_error(client_socket, "Failed to send welcome package.")

    def _send_message(self, client_socket, msg_data):
        """Helper method to properly send JSON messages"""
        try:
            encoded_message = json.dumps(msg_data) + '\n'
            client_socket.sendall(encoded_message.encode())
        except (BrokenPipeError, ConnectionResetError) as e:
            self.logger.error(f"Error sending message to client: {e}")
            self.remove_client(client_socket)
        except Exception as e:
            self.logger.error(f"Error sending message to client: {e}")

    def process_message(self, client_socket, msg_data):
        """Enhanced message processing with validation and logging"""
        try:
            self.logger.debug(f"Processing message: {json.dumps(msg_data, indent=2)}")
            
            # Basic message validation
            if not isinstance(msg_data, dict):
                raise ValueError("Invalid message format")
            
            msg_type = msg_data.get('type')
            if not msg_type:
                raise ValueError("Message type not specified")

            username = self.clients[client_socket]['username']
            
            # Check for duplicate messages
            msg_id = msg_data.get('id')
            if msg_id and msg_id in self.message_cache:
                self.logger.debug(f"Duplicate message detected: {msg_id}")
                return
                
            # Generate server-side message ID if none provided
            if not msg_id:
                msg_id = self.generate_message_id(username)
                msg_data['id'] = msg_id
                
            # Add message to cache
            self.message_cache[msg_id] = time.time()
            
            # Clean old cache entries
            self._clean_message_cache()
            
            # Route message to appropriate handler
            if msg_type in self.message_handlers:
                handler = self.message_handlers[msg_type]
                handler(client_socket, msg_data)
            else:
                raise ValueError(f"Unknown message type: {msg_type}")
                
        except Exception as e:
            self.logger.error(f"Message processing error: {e}", exc_info=True)
            self.send_error(client_socket, f"Error processing message: {str(e)}")

    def handle_chat_message(self, client_socket, msg_data):
        """Handle regular chat messages"""
        try:
            sender = self.clients[client_socket]['username']
            message = msg_data.get('message', '')
            if not message.strip():
                return  # Ignore empty messages

            if self.is_muted(client_socket):
                self.send_error(client_socket, "You are muted and cannot send messages.")
                return

            # Log the message
            self.db.log_message(sender, message)

            # Broadcast the message to other clients
            msg_data = {
                'type': 'message',
                'sender': sender,
                'message': message,
                'timestamp': datetime.now().isoformat(),
                'msg_type': 'normal'
            }
            self.broadcast_message(msg_data, exclude=client_socket)
        except Exception as e:
            self.logger.error(f"Chat message handling error: {e}")
            self.send_error(client_socket, "Failed to process your message.")

    def broadcast_message(self, msg_data, exclude=None):
        """Send a specific message to all clients"""
        try:
            for client in self.clients:
                if exclude and client == exclude:
                    continue
                self._send_message(client, msg_data)
        except Exception as e:
            self.logger.error(f"Broadcast message error: {e}")

    def _clean_message_cache(self):
        """Clean old messages from cache"""
        current_time = time.time()
        expired = [msg_id for msg_id, timestamp in self.message_cache.items()
                  if current_time - timestamp > 3600]  # 1 hour expiry
        for msg_id in expired:
            del self.message_cache[msg_id]

    def send_error(self, client_socket, message):
        """Send error message to client"""
        try:
            error_data = {
                'type': 'error',
                'message': message,
                'msg_type': 'error',
                'timestamp': datetime.now().isoformat(),
                'id': self.generate_message_id('system')
            }
            client_socket.sendall((json.dumps(error_data) + '\n').encode())
        except (BrokenPipeError, ConnectionResetError) as e:
            self.logger.error(f"Error sending error message to client: {e}")
            self.remove_client(client_socket)
        except Exception as e:
            self.logger.error(f"Error sending error message to client: {e}")

    def handle_special_message(self, client_socket, message):
        msg_type = message.get('type')
        if msg_type == 'passwd':
            # Handle password change
            pass
        elif msg_type == 'file':
            self.handle_file_transfer(client_socket, message['filepath'])

    def authenticate_client(self, client_socket):
        try:
            auth_data = json.loads(client_socket.recv(1024).decode())
            username = auth_data['username']
            password = auth_data['password']
            
            user = self.db.verify_user(username, password)
            if user:
                self.clients[client_socket] = {
                    'username': username,
                    'admin': self.db.is_admin(username),
                    'muted_until': 0
                }
                self.db.log_event('login', f'User {username} logged in')
                client_socket.send('AUTH_SUCCESS'.encode())
                
                # Send message history after successful authentication
                history = self.db.get_message_history(50)  # Get last 50 messages
                history_data = {
                    'type': 'history',
                    'messages': [
                        {
                            'sender': sender,
                            'message': content,
                            'timestamp': str(timestamp)
                        } for sender, content, timestamp in history
                    ]
                }
                client_socket.send((json.dumps(history_data) + '\n').encode())
                
                return username
            else:
                client_socket.send('AUTH_FAILED'.encode())
                return None
        except:
            return None

    def handle_command(self, client_socket, command):
        parts = command.split()
        username = self.clients[client_socket]['username']
        is_admin = self.clients[client_socket]['admin']

        if not is_admin:
            self.send_message(client_socket, "You don't have admin privileges")
            return

        if parts[0] == '/adduser' and is_admin:
            if len(parts) >= 3:
                new_username = parts[1]
                password = parts[2]
                is_new_admin = len(parts) > 3 and parts[3] == '--admin'
                if self.db.add_user(new_username, password, is_new_admin):
                    self.broadcast(f"New {'admin' if is_new_admin else 'user'} {new_username} created", "system")
                else:
                    self.send_message(client_socket, f"Failed to create user {new_username}")

        elif parts[0] == '/deluser' and is_admin:
            if len(parts) == 2:
                target = parts[1]
                if target != 'demo':  # Prevent deletion of default admin
                    if self.db.delete_user(target):
                        self.broadcast(f"User {target} has been deleted", "system")
                    else:
                        self.send_message(client_socket, f"Failed to delete user {target}")
                else:
                    self.send_message(client_socket, "Cannot delete default admin account")

        elif parts[0] == '/passwd' and is_admin:
            if len(parts) == 3:
                target = parts[1]
                new_password = parts[2]
                if self.db.change_password(target, new_password):
                    self.send_message(client_socket, f"Password changed for {target}")
                else:
                    self.send_message(client_socket, f"Failed to change password for {target}")

        elif parts[0] == '/listusers' and is_admin:
            users = self.db.get_all_users()
            user_list = "\nRegistered Users:\n" + "-"*50 + "\n"
            user_list += f"{'Username':<20} {'Admin':<10} {'Created At'}\n" + "-"*50 + "\n"
            for user in users:
                user_list += f"{user[1]:<20} {'Yes' if user[3] else 'No':<10} {user[4]}\n"
            self.send_message(client_socket, user_list)

        elif parts[0] == '/kick' and is_admin:
            target = parts[1]
            self.kick_user(target)
            self.db.log_event('kick', f'{username} kicked {target}')
            
        elif parts[0] == '/mute' and is_admin:
            target = parts[1]
            duration = int(parts[2]) if len(parts) > 2 else 300  # Default 5 minutes
            self.mute_user(target, duration)
            self.db.log_event('mute', f'{username} muted {target} for {duration}s')
            
        elif parts[0] == '/unmute' and is_admin:
            target = parts[1]
            self.unmute_user(target)
            self.db.log_event('unmute', f'{username} unmuted {target}')
            
        elif parts[0] == '/file':
            self.handle_file_transfer(client_socket, parts[1])

    def handle_file_transfer(self, client_socket, filepath):
        try:
            filename = os.path.basename(filepath)
            filesize = os.path.getsize(filepath)
            
            if filesize > 10 * 1024 * 1024:  # 10MB limit
                self.send_message(client_socket, "File too large (max 10MB)")
                return
                
            with open(filepath, 'rb') as f:
                data = f.read()
                encoded = base64.b64encode(data).decode()
                
            file_data = {
                'type': 'file',
                'name': filename,
                'data': encoded
            }
            
            self.broadcast(json.dumps(file_data), exclude=client_socket)
            self.db.log_event('file_share', f'{self.clients[client_socket]["username"]} shared {filename}')
        except Exception as e:
            self.send_message(client_socket, f"File transfer failed: {str(e)}")

    def broadcast(self, message, msg_type="normal", exclude=None):
        """Send message to all connected clients"""
        try:
            msg_data = {
                'type': 'message',
                'sender': 'SYSTEM',
                'message': message,
                'timestamp': datetime.now().isoformat(),
                'msg_type': msg_type
            }
            for client in self.clients:
                if exclude and client == exclude:
                    continue
                if hasattr(client, 'send') and callable(client.send):  # Ensure client has send method
                    self._send_message(client, msg_data)
        except Exception as e:
            self.logger.error(f"Broadcast error: {e}")

    def broadcast_user_list(self):
        users = [self.clients[client]['username'] for client in self.clients]
        user_data = {
            'type': 'users',
            'users': users
        }
        
        for client in self.clients:
            try:
                client.send(json.dumps(user_data).encode())
            except:
                self.remove_client(client)

    def remove_client(self, client_socket):
        if client_socket in self.clients:
            username = self.clients[client_socket]['username']
            del self.clients[client_socket]
            self.broadcast(f"{username} left the chat", "system")
            self.broadcast_user_list()
            try:
                client_socket.close()
            except:
                pass

    def is_muted(self, client_socket):
        if client_socket in self.clients:
            muted_until = self.clients[client_socket].get('muted_until', 0)
            return time.time() < muted_until
        return False

    def send_message(self, client_socket, message):
        try:
            msg_data = {
                'type': 'message',
                'message': message,
                'msg_type': 'system'
            }
            client_socket.send(json.dumps(msg_data).encode())
        except:
            self.remove_client(client_socket)

    def receive_message(self, client_socket):
        """Receive and decode message from client"""
        try:
            message = client_socket.recv(1024).decode()
            if not message:
                return None
            
            # Try to parse as JSON in case it's a command
            try:
                return json.loads(message)
            except json.JSONDecodeError:
                # If not JSON, return as plain text
                return message.strip()
        except:
            return None
    
    def reconnect(self):
        """Attempt to reconnect if connection is lost"""
        MAX_RETRIES = 3
        retry_count = 0
        
        while retry_count < MAX_RETRIES:
            try:
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.socket.connect((self.host, self.port))
                self.running = True
                return True
            except:
                retry_count += 1
                time.sleep(2)
        return False
    
    def handle_password_change(self, client_socket, msg_data):
        """Handle password change requests"""
        try:
            username = self.clients[client_socket]['username']
            old_password = msg_data.get('old_password')
            new_password = msg_data.get('new_password')
            
            if not old_password or not new_password:
                raise ValueError("Missing password information")
                
            # Verify old password
            if not self.db.verify_user(username, old_password):
                self.send_error(client_socket, "Current password is incorrect")
                return
                
            # Change password
            if self.db.change_password(username, new_password):
                success_msg = {
                    'type': 'message',
                    'message': "Password changed successfully",
                    'msg_type': 'system',
                    'timestamp': datetime.now().isoformat()
                }
                self.send_message(client_socket, success_msg)
                self.db.log_event('password_change', f'User {username} changed their password')
            else:
                self.send_error(client_socket, "Failed to change password")
                
        except Exception as e:
            self.logger.error(f"Password change error: {e}", exc_info=True)
            self.send_error(client_socket, "Password change failed")

    def cleanup_inactive_clients(self):
        current_time = time.time()
        inactive_timeout = 300  # 5 minutes
        to_remove = []
        for client in self.clients:
            if current_time - self.clients[client].get('last_active', 0) > inactive_timeout:
                to_remove.append(client)
        for client in to_remove:
            self.remove_client(client)

def main():
    logger = setup_logging()
    logger.info("Starting NodesNatter Server")
    
    parser = argparse.ArgumentParser(description='NodesNatter Server')
    parser.add_argument('--mode', choices=['server', 'admin'], default='server',
                       help='Run in server mode or admin CLI mode')
    parser.add_argument('--action', choices=['add-user', 'add-admin', 'list-users', 
                                           'delete-user', 'change-password', 'reset-password'])
    parser.add_argument('--username', help='Username for the target user')
    args = parser.parse_args()
    
    if args.mode == 'server':
        server = ChatServer()
        server.start()
    else:
        cli = CommandLineInterface()
        if not cli.authenticate_admin():
            sys.exit(1)
            
        if args.action in ['change-password', 'reset-password', 'delete-user'] and not args.username:
            print("Username is required for this action")
            sys.exit(1)

        if args.action == 'add-user':
            password = getpass.getpass("Enter password for new user: ")
            cli.add_user(args.username, password, False)
        elif args.action == 'add-admin':
            password = getpass.getpass("Enter password for new admin: ")
            cli.add_user(args.username, password, True)
        elif args.action == 'list-users':
            cli.list_users()
        elif args.action == 'delete-user':
            cli.delete_user(args.username)
        elif args.action == 'change-password':
            new_password = getpass.getpass("Enter new password: ")
            confirm_password = getpass.getpass("Confirm new password: ")
            if new_password == confirm_password:
                cli.change_password(args.username, new_password)
            else:
                print("Passwords don't match!")
        elif args.action == 'reset-password':
            cli.reset_password(args.username)

if __name__ == "__main__":
    main()