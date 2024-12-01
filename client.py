import argparse
import curses
import json
import logging
import os
import socket
import sys
import threading
import time
from datetime import datetime
from logging.handlers import RotatingFileHandler

class UIManager:
    def __init__(self):
        self.screen = curses.initscr()
        self.setup_colors()
        self.setup_windows()
        self.messages = []
        self.users = set()
        self.input_buffer = ""
        self.cursor_x = 0
        self.last_update = time.time()
        self.update_interval = 0.1  # 100ms minimum between updates
        curses.start_color()
        curses.use_default_colors()
        curses.cbreak()
        curses.noecho()
        self.screen.keypad(1)
        self.screen.clear()
        self.screen.refresh()
        self.last_message_count = 0
        self.max_messages = 1000  # Keep a maximum of 1000 messages in memory
        self.scroll_position = 0  # Add scroll position tracking
        
    def setup_colors(self):
        curses.start_color()
        curses.use_default_colors()
        curses.init_pair(1, curses.COLOR_GREEN, -1)  # System messages
        curses.init_pair(2, curses.COLOR_CYAN, -1)   # Usernames
        curses.init_pair(3, curses.COLOR_YELLOW, -1) # Commands
        curses.init_pair(4, curses.COLOR_RED, -1)    # Errors
        curses.init_pair(5, curses.COLOR_WHITE, curses.COLOR_BLUE)  # Status bar
        curses.init_pair(6, curses.COLOR_MAGENTA, -1)   # Private messages
        curses.init_pair(7, curses.COLOR_BLACK, curses.COLOR_WHITE)  # Input highlight
        curses.init_pair(8, curses.COLOR_BLUE, -1)      # Timestamps
        curses.init_pair(9, curses.COLOR_WHITE, curses.COLOR_RED)    # Important alerts
        
        # In UIManager class, modify setup_windows():
    def setup_windows(self):
        # Get terminal dimensions
        self.height, self.width = self.screen.getmaxyx()
        
        # Calculate window sizes with proper positioning
        chat_height = self.height - 4  # Leave room for status and input
        users_width = 20
        chat_width = self.width - users_width  # Main chat takes remaining width
        
        # Create windows with correct left-to-right positioning
        self.chat_win = curses.newwin(chat_height, chat_width, 0, 0)  # Start at 0,0
        self.users_win = curses.newwin(chat_height, users_width, 0, chat_width)  # Users on right
        self.status_win = curses.newwin(1, self.width, chat_height, 0)  # Status below chat
        self.input_win = curses.newwin(3, self.width, chat_height + 1, 0)  # Input at bottom
        
        # Enable scrolling for chat window
        self.chat_win.scrollok(True)
        
        # Add boundaries check
        if self.width < 40 or self.height < 10:
            raise ValueError("Terminal window too small. Minimum 40x10 required.")
            
        # Prevent recursive calls in refresh
        self.is_refreshing = False
        
        # Draw borders and titles
        self._draw_borders()
        
    def _draw_borders(self):
        """Separate method for drawing borders to avoid recursion"""
        for win in [self.chat_win, self.users_win, self.input_win]:
            win.box()
        
        # Add titles with error checking
        try:
            self.chat_win.addstr(0, 2, " Chat Messages ", curses.color_pair(2))
            self.users_win.addstr(0, 2, " Online Users ", curses.color_pair(2))
            self.input_win.addstr(0, 2, " Message Input ", curses.color_pair(7))
        except curses.error:
            pass  # Handle gracefully if window too small
    
    def refresh_chat(self):
        """Modified to prevent recursion"""
        if self.is_refreshing:
            return
            
        self.is_refreshing = True
        try:
            self.chat_win.clear()
            self.chat_win.box()
            
            # Calculate visible message range
            height = self.chat_win.getmaxyx()[0] - 2
            start_idx = max(0, len(self.messages) - height)
            visible_messages = self.messages[start_idx:]
            
            for i, (msg, color) in enumerate(visible_messages, 1):
                try:
                    # Truncate message if necessary to fit in the window
                    max_width = self.chat_win.getmaxyx()[1] - 4  # Account for borders and padding
                    msg_to_display = msg[:max_width]
                    self.chat_win.addstr(i, 1, msg_to_display, curses.color_pair(color))
                except curses.error:
                    pass  # Handle display errors gracefully
                    
            self.chat_win.refresh()
        finally:
            self.is_refreshing = False
            
    def refresh_all(self):
        self.chat_win.refresh()
        self.users_win.refresh()
        self.input_win.refresh()
        self.status_win.refresh()
        
    def add_message(self, message, msg_type="normal"):
        timestamp = datetime.now().strftime("%H:%M:%S")
        colors = {
            "system": 1,    # Green
            "user": 2,      # Cyan
            "command": 3,   # Yellow
            "error": 4,     # Red
            "private": 6,   # Magenta
            "self": 2,      # Cyan (for your own messages)
            "normal": 2     # Cyan
        }
        color = colors.get(msg_type, 0)
        
        # Add visual indicator for sent messages
        if (msg_type == "self"):
            formatted_msg = f"[{timestamp}] ➤ {message}"  # Add arrow for your messages
        else:
            formatted_msg = f"[{timestamp}] {message}"
            
        # Ensure message encoding is correct
        formatted_msg = formatted_msg.encode('utf-8', 'replace').decode('utf-8', 'replace')

        self.messages.append((formatted_msg, color))
        if len(self.messages) > self.max_messages:
            self.messages = self.messages[-self.max_messages:]
        
        self.refresh_chat()
        self.scroll_to_bottom()  # Auto-scroll to the latest message

            
    def update_users(self, users):
        current_time = time.time()
        if current_time - self.last_update >= self.update_interval:
            self.users = set(users)
            self.users_win.clear()
            self.users_win.box()
            self.users_win.addstr(0, 2, "Users Online")
            
            height = self.users_win.getmaxyx()[0]
            for i, user in enumerate(sorted(self.users)):
                if i < height - 2:  # Leave space for borders
                    try:
                        self.users_win.addstr(i + 1, 2, user[:16])
                    except curses.error:
                        pass
            
            self.users_win.refresh()
            self.last_update = current_time
        
    def update_status(self, status):
        self.status_win.clear()
        self.status_win.bkgd(' ', curses.color_pair(5))
        self.status_win.addstr(0, 0, status[:self.width-1])
        self.status_win.refresh()
        
    def get_input(self):
        self.input_win.clear()
        self.input_win.box()
        try:
            # Show prompt
            self.input_win.addstr(1, 1, "> ")
            # Show input buffer
            self.input_win.addstr(1, 3, self.input_buffer[:self.width-6])
            self.input_win.refresh()
        except curses.error:
            pass
        
        while True:
            try:
                ch = self.screen.getch()
                
                if ch == ord('\n'):
                    temp = self.input_buffer
                    self.input_buffer = ""
                    self.cursor_x = 0
                    self.get_input()
                    return temp
                    
                elif ch == curses.KEY_BACKSPACE or ch == 127:
                    if self.cursor_x > 0:
                        self.input_buffer = self.input_buffer[:-1]
                        self.cursor_x -= 1
                        
                elif ch == curses.KEY_RESIZE:
                    self.resize()
                    
                elif 32 <= ch <= 126:  # Printable characters
                    if self.cursor_x < self.width - 4:
                        self.input_buffer += chr(ch)
                        self.cursor_x += 1
                        
                self.get_input()
                
            except KeyboardInterrupt:
                return '/quit'
                
    def resize(self):
        try:
            self.height, self.width = self.screen.getmaxyx()
            if self.height < 10 or self.width < 40:
                raise ValueError("Terminal too small")
            self.setup_windows()
            self.refresh_chat()
            self.update_users(self.users)
            self.get_input()
        except Exception as e:
            self.logger.error(f"Resize error: {e}")
        
    def cleanup(self):
        curses.endwin()

    def get_password(self, prompt):
        self.update_status(prompt)
        password = ""
        while True:
            ch = self.screen.getch()
            if ch == ord('\n'):
                break
            elif ch == curses.KEY_BACKSPACE or ch == 127:
                if len(password) > 0:
                    password = password[:-1]
            elif 32 <= ch <= 126:
                password += chr(ch)
            
            # Show asterisks for password
            self.input_win.clear()
            self.input_win.box()
            self.input_win.addstr(1, 1, '*' * len(password))
            self.input_win.refresh()
            
        return password

    def process_input(self, message, msg_type="chat"):
        """New method to process input before sending"""
        try:
            if message.strip():
                formatted_msg = {
                    'type': msg_type,
                    'content': message.strip(),
                    'timestamp': datetime.now().isoformat(),
                    'status': 'sending'  # Add status tracking
                }
                # Show sending indicator
                self.add_message(f"Sending: {message}", "system")
                return formatted_msg
        except Exception as e:
            self.add_message("Error processing message", "error")
            return None

    def scroll_to_bottom(self):
        """Scroll to show the most recent messages"""
        try:
            height = self.chat_win.getmaxyx()[0]
            total_messages = len(self.messages)
            
            # If we have more messages than display height, adjust scroll position
            if total_messages > height - 2:  # Account for borders
                self.scroll_position = 0  # Reset to bottom
                self.refresh_chat()
        except Exception as e:
            self.logger.error(f"Error scrolling to bottom: {e}")

    async def get_async_input(self):
        """Asynchronously get user input without blocking."""
        return await asyncio.get_event_loop().run_in_executor(None, self.get_input)

def setup_logging():
    # Create logs directory if it doesn't exist
    os.makedirs('logs', exist_ok=True)
    
    # Configure logging
    logger = logging.getLogger('NodesNatter-Client')
    logger.setLevel(logging.DEBUG)
    
    # File handler
    file_handler = RotatingFileHandler(
        'logs/client.log',
        maxBytes=10*1024*1024,
        backupCount=5
    )
    file_handler.setLevel(logging.DEBUG)
    
    # Formatting
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    file_handler.setFormatter(formatter)
    
    # Add handlers
    logger.addHandler(file_handler)
    
    return logger

class ChatClient:
    def __init__(self, host='localhost', port=5555):
        self.logger = setup_logging()
        self.host = host
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.username = None
        self.running = False
        self.ui = None
        self.logger.info(f"Chat client initialized for {host}:{port}")
        self.message_queue = []  # Add message queue
        self.last_message_id = 0  # Add message ID tracking
        self.received_messages = []  # Add buffer for received messages
        self.last_user_update = 0    # Track last user list update
        
    def generate_message_id(self):
        """Generate unique message ID"""
        self.last_message_id += 1
        return f"{self.username}_{int(time.time())}_{self.last_message_id}"
        logger.debug(f"Generated message ID: {msg_id}, {message}")

    def queue_message(self, message):
        """Add message to queue with ID and status"""
        msg_id = self.generate_message_id()
        msg_data = {
            'id': msg_id,
            'type': 'message',
            'message': message,
            'sender': self.username,
            'timestamp': datetime.now().isoformat(),
            'status': 'queued'
        }
        self.message_queue.append(msg_data)
        return msg_id
        logger.debug(f"Queued message: {msg_id}, {message}")

    def send_queued_messages(self):
        """Process and send queued messages"""
        while self.message_queue:
            msg_data = self.message_queue.pop(0)
            try:
                msg_data['status'] = 'sending'
                encoded_message = json.dumps(msg_data) + '\n'
                self.socket.sendall(encoded_message.encode())
                self.logger.debug(f"Sent message: {msg_data['id']}")
                
                # Wait for acknowledgment (optional)
                msg_data['status'] = 'sent'
                self.ui.add_message(f"✓ {msg_data['message']}", "system")
            except Exception as e:
                self.logger.error(f"Failed to send message: {e}")
                msg_data['status'] = 'failed'
                self.message_queue.append(msg_data)  # Re-queue failed message
                self.ui.add_message("Message queued for retry", "error")
                break

    def start(self):
        try:
            self.socket.connect((self.host, self.port))
            self.logger.info(f"Connected to server at {self.host}:{self.port}")
            self.running = True
            
            # Initialize UI
            self.ui = UIManager()
            
            # Login
            self.login()
            
            # Start message receiving thread
            receive_thread = threading.Thread(target=self.receive_messages)
            receive_thread.daemon = True
            receive_thread.start()
            
            # Update status
            self.ui.update_status(f"Connected as {self.username} | /help for commands")
            
            # Add periodic refresh timer
            refresh_thread = threading.Thread(target=self._periodic_refresh)
            refresh_thread.daemon = True
            refresh_thread.start()
            
            # Main input loop
            self.input_loop()
            
        except Exception as e:
            self.logger.error(f"Error starting client: {e}", exc_info=True)
            if self.ui:
                self.ui.cleanup()
            print(f"Error: {e}")
        finally:
            if self.ui:
                self.ui.cleanup()
            self.socket.close()
            self.logger.info("Client shutdown")
            
    def login(self):
        curses.echo()  # Enable terminal echo for username input
        while True:
            try:
                # Clear screen and show login prompt
                self.ui.screen.clear()
                self.ui.screen.addstr(0, 0, "NodesNatter Chat Login")
                self.ui.screen.addstr(2, 0, "Username: ")
                self.ui.screen.refresh()
                
                # Get username
                self.username = self.ui.screen.getstr().decode('utf-8')
                
                # Get password using the secure password input
                self.ui.screen.addstr(3, 0, "Password: ")
                self.ui.screen.refresh()
                curses.noecho()  # Disable echo for password
                password = self.ui.get_password("")
                
                auth_data = {
                    'username': self.username,
                    'password': password
                }
                
                # Send authentication request
                self.socket.send(json.dumps(auth_data).encode())
                response = self.socket.recv(1024).decode()
                
                if response == 'AUTH_SUCCESS':
                    self.logger.info(f"Successfully logged in as {self.username}")
                    self.ui.add_message("Login successful!", "system")
                    break
                else:
                    self.logger.warning(f"Login failed for user {self.username}")
                    self.ui.screen.clear()
                    self.ui.screen.addstr(0, 0, "Login failed. Press any key to try again.")
                    self.ui.screen.refresh()
                    self.ui.screen.getch()
                    curses.echo()  # Re-enable echo for next attempt
            except Exception as e:
                self.logger.error(f"Login error: {e}", exc_info=True)
                self.ui.screen.clear()
                self.ui.screen.addstr(0, 0, f"Error: {str(e)}\nPress any key to try again.")
                self.ui.screen.refresh()
                self.ui.screen.getch()
                curses.echo()  # Re-enable echo for next attempt

    def receive_messages(self):
        buffer = ""
        while self.running:
            try:
                data = self.socket.recv(4096).decode()
                if not data:
                    self.logger.warning("Connection closed by server")
                    self.running = False
                    break

                buffer += data
                while '\n' in buffer:
                    message, buffer = buffer.split('\n', 1)
                    if not message.strip():
                        continue

                    try:
                        msg_data = json.loads(message)
                        self.handle_message(msg_data)
                    except json.JSONDecodeError as je:
                        self.logger.error(f"Invalid JSON received: {message[:100]}")
                        continue
            except (ConnectionResetError, ConnectionAbortedError) as e:
                self.logger.warning(f"Connection to server was lost: {e}")
                self.running = False
                break
            except Exception as e:
                self.logger.error(f"Error receiving messages: {e}", exc_info=True)
                time.sleep(1)  # Add a delay before retrying

    def handle_message(self, msg_data):
        """Handle incoming messages from the server."""
        try:
            msg_type = msg_data.get('type')
            self.logger.debug(f"Handling message type: {msg_type}")

            if msg_type is None:
                self.logger.warning("Received message without type field")
                self.ui.add_message("Error: Received message without type field", "error")
                return

            if msg_type == 'message':
                sender = msg_data.get('sender', 'Unknown')
                message = msg_data.get('message', '')
                msg_subtype = msg_data.get('msg_type', 'normal')

                # Don't process empty messages
                if not message.strip():
                    return

                # Handle message based on sender
                if (sender == self.username):
                    # Skip our own messages
                    return
                elif sender == 'SYSTEM':
                    # System messages
                    self.ui.add_message(message, "system")
                else:
                    # Messages from other users
                    self.ui.add_message(f"{sender}: {message}", msg_subtype)

            elif msg_type == 'users':
                # Update the list of online users
                users = msg_data.get('users', [])
                if users:
                    self.ui.update_users(users)

            elif msg_type == 'history':
                # Load chat history
                messages = msg_data.get('messages', [])
                if messages:
                    for msg in messages:
                        self.handle_message(msg)  # Process each message

            elif msg_type == 'error':
                # Display error messages
                error_message = msg_data.get('message', 'Unknown error')
                self.ui.add_message(f"Error: {error_message}", "error")

            elif msg_type == 'file':
                # Handle incoming file
                self.handle_file_receive(msg_data)

            elif msg_type == 'command_response':
                # Handle responses to commands
                response = msg_data.get('message', '')
                self.ui.add_message(response, "command")

            else:
                # Unknown message type
                self.logger.warning(f"Unknown message type: {msg_type}")
                self.ui.add_message(f"Unknown message type received: {msg_type}", "error")

            # Refresh the UI
            self.ui.refresh_all()

        except Exception as e:
            self.logger.error(f"Error handling message: {e}", exc_info=True)
            self.ui.add_message(f"Error handling message: {str(e)}", "error")

    def handle_file_receive(self, file_data):
        filename = file_data['name']
        file_content = base64.b64decode(file_data['data'])
        
        with open(f"received_{filename}", 'wb') as f:
            f.write(file_content)
        print(f"\rReceived file: received_{filename}\n> ", end="")

        # In ChatClient class, modify input_loop():
    def input_loop(self):
        while self.running:
            try:
                message = self.ui.get_input()
                if not message:  # Changed condition to handle empty strings better
                    continue

                message = message.strip()
                self.logger.debug(f"Processing input: {message}")

                if message.startswith('/'):
                    self.logger.debug(f"Processing command: {message}")
                    if message.lower() == '/quit':
                        self.ui.add_message("Quitting...", "system")
                        self.running = False
                        break
                    elif message.lower() == '/help':
                        self.show_help()
                        continue  # Skip regular message processing
                    elif message.lower().startswith('/file '):
                        filepath = message.split(' ', 1)[1]
                        self.send_file(filepath)
                        continue
                    elif message.lower() == '/passwd':
                        self.change_password()
                        continue
                    else:
                        # Send other commands to server
                        self.handle_command(message)
                        continue
                else:
                    # Regular message handling
                    msg_data = {
                        'type': 'message',
                        'message': message,
                        'sender': self.username,
                        'timestamp': datetime.now().isoformat()
                    }
                    self.send_message(msg_data)

            except KeyboardInterrupt:
                self.logger.info("Received keyboard interrupt")
                self.running = False
                break
            except Exception as e:
                self.logger.error(f"Input loop error: {e}", exc_info=True)
                self.ui.add_message(f"Error: {str(e)}", "error")

    def show_help(self):
        """Fixed help command display"""
        help_text = [
            "=== Available Commands ===",
            "/help - Show this help message",
            "/quit - Exit the chat",
            "/file <path> - Send a file (max 10MB)",
            "/passwd - Change your password",
            "",
            "=== Admin Commands ===",
            "/adduser <username> <password> [--admin] - Create new user",
            "/deluser <username> - Delete user",
            "/passwd <username> <newpass> - Change user's password",
            "/listusers - List all registered users",
            "/kick <username> - Kick a user",
            "/mute <username> <seconds> - Mute a user",
            "/unmute <username> - Unmute a user"
        ]
        
        for line in help_text:
            self.ui.add_message(line, "command")
            self.ui.refresh_chat()  # Force refresh after each line

    def send_message(self, msg_data):
        """Fixed message sending with proper message construction"""
        try:
            # Add required fields
            msg_data.update({
                'id': self.generate_message_id(),
                'sender': self.username,
                'timestamp': datetime.now().isoformat(),
                'type': 'message',  # Ensure message type is set
                'msg_type': 'normal'  # Set default message type
            })
            
            # Send message
            encoded_message = json.dumps(msg_data) + '\n'
            self.socket.sendall(encoded_message.encode())
            
            # Log the sent message
            self.logger.debug(f"Sent message: {msg_data}")
            
            # Display in UI immediately
            self.ui.add_message(f"{msg_data['message']}", "self")
            self.ui.refresh_chat()
            
            return True
            
        except (BrokenPipeError, ConnectionResetError) as e:
            self.logger.error(f"Send error: {e}", exc_info=True)
            self.ui.add_message(f"Failed to send message: {str(e)}", "error")
            self.reconnect()  # Attempt to reconnect
            return False
        except Exception as e:
            self.logger.error(f"Send error: {e}", exc_info=True)
            self.ui.add_message(f"Failed to send message: {str(e)}", "error")
            return False

    def handle_command(self, command):
        """Fixed command handling"""
        try:
            cmd_data = {
                'type': 'command',
                'message': command,
                'sender': self.username,
                'timestamp': datetime.now().isoformat()
            }
            self.socket.sendall((json.dumps(cmd_data) + '\n').encode())
            self.logger.debug(f"Sent command: {command}")
            self.ui.add_message(f"Sent command: {command}", "system")
            self.ui.refresh_chat()
        except (BrokenPipeError, ConnectionResetError) as e:
            self.logger.error(f"Command error: {e}", exc_info=True)
            self.ui.add_message(f"Failed to send command: {str(e)}", "error")
            self.reconnect()  # Attempt to reconnect
        except Exception as e:
            self.logger.error(f"Command error: {e}", exc_info=True)
            self.ui.add_message(f"Failed to send command: {str(e)}", "error")

    def change_password(self):
        try:
            old_password = self.ui.get_password("Enter current password: ")
            new_password = self.ui.get_password("Enter new password: ")
            confirm_password = self.ui.get_password("Confirm new password: ")

            if new_password != confirm_password:
                self.ui.add_message("Passwords don't match!", "error")
                return

            passwd_data = {
                'type': 'passwd',
                'old_password': old_password,
                'new_password': new_password
            }
            self.socket.send(json.dumps(passwd_data).encode())
        except:
            self.ui.add_message("Password change failed!", "error")

    def reconnect(self):
        """Attempt to reconnect if connection is lost"""
        MAX_RETRIES = 3
        retry_count = 0
        
        while retry_count < MAX_RETRIES:
            try:
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.socket.connect((self.host, self.port))
                self.running = True
                self.send_queued_messages()
                return True
            except:
                retry_count += 1
                time.sleep(2)
        return False

    def _periodic_refresh(self):
        """Periodically refresh the UI"""
        while self.running:
            try:
                self.ui.refresh_all()
                time.sleep(0.1)  # 100ms refresh rate
            except Exception as e:
                self.logger.error(f"Refresh error: {e}")
        client = ChatClient()

def main():
    logger = setup_logging()
    logger.info("Starting NodesNatter Client")
    parser = argparse.ArgumentParser(description='NodesNatter Client')
    parser.add_argument('--host', default='localhost', help='Server host')
    parser.add_argument('--port', type=int, default=5555, help='Server port')
    args = parser.parse_args()
    try:
        client = ChatClient(host=args.host, port=args.port)
        client.start()
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main()