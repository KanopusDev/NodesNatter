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
        
    def setup_windows(self):
        # Get terminal dimensions
        self.height, self.width = self.screen.getmaxyx()
        
        # Calculate window sizes (fixed proportions)
        self.chat_height = self.height - 4
        self.chat_width = int(self.width * 0.8)  # 80% of width for chat
        self.users_width = self.width - self.chat_width
        
        # Create windows with proper positioning
        self.chat_win = curses.newwin(self.chat_height, self.chat_width, 0, 0)
        self.users_win = curses.newwin(self.chat_height, self.users_width, 0, self.chat_width)
        self.status_win = curses.newwin(1, self.width, self.chat_height, 0)
        self.input_win = curses.newwin(3, self.width, self.chat_height + 1, 0)
        
        # Enable scrolling for chat window
        self.chat_win.scrollok(True)
        self.chat_win.idlok(True)
        
        # Draw borders
        self.chat_win.box()
        self.users_win.box()
        self.input_win.box()
        
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
        timestamp = datetime.now().strftime("%H:%M")
        color = {
            "system": 1,
            "user": 2,
            "command": 3,
            "error": 4
        }.get(msg_type, 0)
        
        self.messages.append((f"[{timestamp}] {message}", color))
        
        # Limit number of stored messages
        if len(self.messages) > self.max_messages:
            self.messages = self.messages[-self.max_messages:]
            
        self.refresh_chat()

    def refresh_chat(self):
        try:
            self.chat_win.clear()
            self.chat_win.box()
            
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
                    self.chat_win.attron(curses.color_pair(color))
                    self.chat_win.addstr(i + 1, 1, message[:display_width])
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
                data = self.socket.recv(1024).decode()
                if not data:
                    break
                    
                buffer += data
                while '\n' in buffer:
                    message, buffer = buffer.split('\n', 1)
                    try:
                        msg_data = json.loads(message)
                        self.handle_message(msg_data)
                    except json.JSONDecodeError:
                        if message.strip():
                            self.ui.add_message(message.strip())
                    except Exception as e:
                        self.logger.error(f"Error processing message: {e}")
                        
            except Exception as e:
                if not self.running:
                    break
                self.logger.error(f"Error receiving message: {e}")
                time.sleep(0.1)

    def handle_message(self, msg_data):
        """Handle different types of messages"""
        try:
            msg_type = msg_data.get('type', 'normal')
            if msg_type == 'message':
                self.ui.add_message(msg_data['message'], msg_data.get('msg_type', 'normal'))
            elif msg_type == 'users':
                self.ui.update_users(msg_data['users'])
            elif msg_type == 'history':
                self.ui.messages.clear()
                for msg in msg_data['messages']:
                    timestamp = datetime.fromisoformat(msg['timestamp']).strftime("%H:%M")
                    message = f"{msg['sender']}: {msg['message']}"
                    self.ui.add_message(message, "normal")
            self.ui.refresh_all()
        except Exception as e:
            self.logger.error(f"Error handling message: {e}")

    def handle_file_receive(self, file_data):
        filename = file_data['name']
        file_content = base64.b64decode(file_data['data'])
        
        with open(f"received_{filename}", 'wb') as f:
            f.write(file_content)
        print(f"\rReceived file: received_{filename}\n> ", end="")

    def input_loop(self):
        while self.running:
            try:
                message = self.ui.get_input()
                
                if message:  # Only process non-empty messages
                    if message.lower() == '/quit':
                        self.running = False
                        break
                    elif message.lower() == '/help':
                        self.show_help()
                    elif message.lower() == '/passwd':
                        self.change_password()
                    elif message.startswith('/file'):
                        self.handle_file_send(message[6:])
                    else:
                        # Send message to server
                        msg_data = {
                            'type': 'message',
                            'message': message
                        }
                        self.socket.send((json.dumps(msg_data) + '\n').encode())
                        # Don't add local echo - wait for server to echo back
                        
            except Exception as e:
                self.logger.error(f"Error in input loop: {e}")
                time.sleep(0.1)

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

if __name__ == "__main__":
    logger = setup_logging()
    logger.info("Starting NodesNatter Client")
    
    try:
        client = ChatClient()
        client.start()
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)