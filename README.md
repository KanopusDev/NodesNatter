
# NodesNatter

NodesNatter is a chat application that allows users to communicate in real-time. It includes both server and client components, with features such as user authentication, message broadcasting, and administrative commands.

## Features

- User authentication
- Real-time messaging
- Message history
- Administrative commands (add user, delete user, list users, etc.)
- File transfer
- Password management

## Installation

### Prerequisites

- Python 3.8+
- `pip` package manager

### Clone the Repository

```sh
git clone https://github.com/Kanopusdev/NodesNatter.git
cd NodesNatter
```

### Install Dependencies

```sh
pip install -r requirements.txt
```

## Usage

### Running the Server

To start the server, run:

```sh
python server.py --mode server
```

### Running the Client

To start the client, run:

```sh
python client.py --host <server_host> --port <server_port>
```

### Administrative Commands

The server can also be run in admin mode to manage users:

```sh
python server.py --mode admin --action <action> --username <username>
```

Available actions:
- `add-user`: Add a new user
- `add-admin`: Add a new admin
- `list-users`: List all users
- `delete-user`: Delete a user
- `change-password`: Change a user's password
- `reset-password`: Reset a user's password


## Project Structure

```
NodesNatter/
├── client.py           # Client application
├── server.py           # Server application   
└── README.md           # Project documentation
```

## Contributing

Contributions are welcome! Please fork the repository and submit a pull request.

## License

This project is licensed under the Kanopus Development License. See the [LICENSE](LICENSE) file for details.

## Contact

For any questions or suggestions, please contact [Discord](https://discord.gg/JUhv27kzcJ).

---