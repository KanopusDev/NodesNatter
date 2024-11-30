import socket
import threading
import json
import os
import sys
import termios
import tty
import curses 
from datetime import datetime
import base64
import logging
from logging.handlers import RotatingFileHandler
import time

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
        
    def setup_windows(self):
        # Get terminal dimensions
        self.height, self.width = self.screen.getmaxyx()
        
        # Calculate window sizes
        chat_height = self.height - 4
        chat_width = max(self.width - 22, 20)  # Ensure minimum width
        users_width = 20
        
        # Create main chat window
        self.chat_win = curses.newwin(chat_height, chat_width, 0, 0)
        self.chat_win.scrollok(True)
        
        # Create users window
        self.users_win = curses.newwin(chat_height, users_width, 0, chat_width)
        
        # Create status bar
        self.status_win = curses.newwin(1, self.width, chat_height, 0)
        
        # Create input window
        self.input_win = curses.newwin(3, self.width, chat_height + 1, 0)
        
        # Draw borders
        self.chat_win.box()
        self.users_win.box()
        self.input_win.box()
        
        # Add title to chat window
        self.chat_win.attron(curses.color_pair(2))
        self.chat_win.addstr(0, 2, " Chat Messages ")
        self.chat_win.attroff(curses.color_pair(2))
        
        # Add title to users window
        self.users_win.attron(curses.color_pair(2))
        self.users_win.addstr(0, 2, " Online Users ")
        self.users_win.attroff(curses.color_pair(2))
        
        # Style input window
        self.input_win.attron(curses.color_pair(7))
        self.input_win.addstr(0, 2, " Message Input ")
        self.input_win.attroff(curses.color_pair(7))
        
        # Initial refresh
        self.screen.clear()
        self.screen.refresh()
        self.refresh_all()
        
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
        if msg_type == "self":
            formatted_msg = f"[{timestamp}] ➤ {message}"  # Add arrow for your messages
        else:
            formatted_msg = f"[{timestamp}] {message}"
            
        self.messages.append((formatted_msg, color))
        if len(self.messages) > self.max_messages:
            self.messages = self.messages[-self.max_messages:]
        
        self.refresh_chat()
        self.scroll_to_bottom()  # Auto-scroll to the latest message

    def refresh_chat(self):
        try:
            self.chat_win.clear()
            self.chat_win.box()
            
            # Add title
            self.chat_win.attron(curses.color_pair(2))
            self.chat_win.addstr(0, 2, " Chat Messages ")
            self.chat_win.attroff(curses.color_pair(2))
            
            height, width = self.chat_win.getmaxyx()
            display_height = height - 2  # Account for borders
            display_width = width - 2    # Account for borders
            
            # Calculate which messages to show based on scroll position
            total_messages = len(self.messages)
            start_idx = max(0, total_messages - display_height + self.scroll_position)
            end_idx = min(start_idx + display_height, total_messages)
            
            # Display messages
            for i, (message, color) in enumerate(self.messages[start_idx:end_idx]):
                try:
                    # Split message into timestamp and content
                    timestamp_end = message.find(']') + 1
                    timestamp = message[:timestamp_end]
                    content = message[timestamp_end:]
                    
                    # Draw timestamp in blue
                    self.chat_win.attron(curses.color_pair(8))
                    self.chat_win.addstr(i + 1, 1, timestamp)
                    self.chat_win.attroff(curses.color_pair(8))
                    
                    # Draw message content in specified color
                    self.chat_win.attron(curses.color_pair(color))
                    self.chat_win.addstr(i + 1, timestamp_end + 1, content[:display_width-timestamp_end-2])
                    self.chat_win.attroff(curses.color_pair(color))
                except curses.error:
                    pass
            
            self.chat_win.refresh()
        except Exception as e:
            self.logger.error(f"Error refreshing chat: {e}")
            
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
        self.height, self.width = self.screen.getmaxyx()
        self.setup_windows()
        self.refresh_chat()
        self.update_users(self.users)
        self.get_input()
        
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
        self.logger = logging.getLogger('NodesNatter-Client')
        self.host = host
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.username = None
        self.running = False
        self.ui = None
        self.logger.info(f"Chat client initialized for {host}:{port}")
        self.message_queue = []  # Add message queue
        self.last_message_id = 0  # Add message ID tracking
        
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
                    break

                self.logger.debug(f"Received data chunk: {data[:100]}...")
                buffer += data

                # Process complete messages
                while '\n' in buffer:
                    try:
                        # Find the next complete message
                        message_end = buffer.find('\n')
                        message = buffer[:message_end]
                        buffer = buffer[message_end + 1:]

                        # Skip empty messages
                        if not message.strip():
                            continue

                        # Parse and handle the message
                        try:
                            msg_data = json.loads(message)
                            self.logger.debug(f"Processing message: {msg_data['type']}")
                            self.handle_message(msg_data)
                        except json.JSONDecodeError as je:
                            self.logger.error(f"Invalid JSON message: {message[:100]}")
                            self.logger.debug(f"JSON Error: {str(je)}")
                            continue

                    except Exception as e:
                        self.logger.error(f"Error processing message chunk: {e}")
                        buffer = ""  # Clear buffer on error

            except Exception as e:
                if not self.running:
                    break
                self.logger.error(f"Connection error: {e}", exc_info=True)
                if not self.reconnect():
                    break
                time.sleep(1)

    def handle_message(self, msg_data):
        """Enhanced message handling with better UI updates"""
        try:
            msg_type = msg_data.get('type')
            self.logger.debug(f"Handling message type: {msg_type}")

            if msg_type == 'message':
                sender = msg_data.get('sender', 'Unknown')
                message = msg_data.get('message', '')
                msg_subtype = msg_data.get('msg_type', 'normal')
                
                if sender == self.username:
                    # Don't show our own messages again
                    return
                elif sender == 'SYSTEM':
                    self.ui.add_message(message, "system")
                else:
                    self.ui.add_message(f"{sender}: {message}", msg_subtype)
                    
            elif msg_type == 'users':
                self.logger.debug(f"Updating users list: {msg_data.get('users', [])}")
                self.ui.update_users(msg_data.get('users', []))
            elif msg_type == 'history':
                self.logger.debug("Processing message history")
                self.handle_history(msg_data.get('messages', []))
            elif msg_type == 'error':
                self.ui.add_message(msg_data.get('message', 'Unknown error'), 'error')
            
            self.ui.refresh_chat()
            
        except Exception as e:
            self.logger.error(f"Error in handle_message: {e}", exc_info=True)

    def handle_history(self, messages):
        """Handle message history"""
        try:
            self.ui.messages.clear()
            for msg in messages:
                try:
                    timestamp = datetime.fromisoformat(msg['timestamp']).strftime("%H:%M")
                    message = f"{msg['sender']}: {msg['message']}"
                    self.ui.add_message(message, "normal")
                except Exception as e:
                    self.logger.error(f"Error processing history message: {e}")
        except Exception as e:
            self.logger.error(f"Error handling history: {e}", exc_info=True)

    def handle_file_receive(self, file_data):
        filename = file_data['name']
        file_content = base64.b64decode(file_data['data'])
        
        with open(f"received_{filename}", 'wb') as f:
            f.write(file_content)
        print(f"\rReceived file: received_{filename}\n> ", end="")

    def input_loop(self):
        """Modified input loop with improved message handling"""
        while self.running:
            try:
                message = self.ui.get_input()
                if not message or not message.strip():
                    continue
                    
                self.logger.debug(f"Processing input: {message}")
                
                if message.startswith('/'):
                    if message.lower() == '/quit':
                        self.running = False
                        break
                    elif message.lower() == '/help':
                        self.show_help()
                    elif message.lower().startswith('/file'):
                        filepath = message.split(' ', 1)[1]
                        self.send_file(filepath)
                    elif message.lower() == '/passwd':
                        self.change_password()
                    else:
                        self.handle_command(message)
                else:
                    # Construct and send message
                    msg_data = {
                        'type': 'message',
                        'message': message.strip(),
                        'id': self.generate_message_id(),
                        'sender': self.username,
                        'timestamp': datetime.now().isoformat()
                    }
                    self.send_message(msg_data)
                    # Show the message in the UI immediately
                    self.ui.add_message(f"{message}", "self")
                    
            except KeyboardInterrupt:
                self.running = False
                break
            except Exception as e:
                self.logger.error(f"Input loop error: {e}", exc_info=True)
                self.ui.add_message(f"Error: {str(e)}", "error")
                time.sleep(0.1)

    def send_message(self, msg_data):
        """Enhanced message sending with better error handling"""
        try:
            # Add newline to ensure proper message termination
            encoded_message = json.dumps(msg_data) + '\n'
            self.logger.debug(f"Sending message: {encoded_message.strip()}")
            self.socket.sendall(encoded_message.encode())
            
            # Immediately show the message in UI
            if msg_data['type'] == 'message':
                self.ui.add_message(f"You: {msg_data['message']}", "self")
                self.ui.refresh_chat()
                
            # Wait for server acknowledgment
            return True
                
        except ConnectionError as e:
            self.logger.error(f"Connection error while sending: {e}")
            self.ui.add_message("Connection lost. Attempting to reconnect...", "error")
            if not self.reconnect():
                self.running = False
            return False
        except Exception as e:
            self.logger.error(f"Error sending message: {e}", exc_info=True)
            self.ui.add_message("Failed to send message", "error")
            self.ui.refresh_chat()
            return False

    def handle_command(self, command):
        """New method to handle commands"""
        cmd_data = {
            'type': 'command',
            'message': command,
            'sender': self.username,
            'timestamp': datetime.now().isoformat()
        }
        self.socket.send((json.dumps(cmd_data) + '\n').encode())

    def show_help(self):
        help_text = [
            "Available Commands:",
            "/help - Show this help message",
            "/file <path> - Send a file (max 10MB)",
            "/quit - Exit the chat",
            "/passwd - Change your password",
            "Admin Commands:",
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
        self.ui.refresh_chat()  # Force refresh after help display

    def send_file(self, filepath):
        if not os.path.exists(filepath):
            print("File not found!")
            return
            
        self.socket.send(f"/file {filepath}".encode())

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
                return True
            except:
                retry_count += 1
                time.sleep(2)
        return False

if __name__ == "__main__":
    logger = setup_logging()
    logger.info("Starting NodesNatter Client")
    
    try:
        client = ChatClient()
        client.start()
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)