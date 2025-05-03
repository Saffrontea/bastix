# Bastix

Bastix is a comprehensive GUI management tool for FreeBSD's Bastille jail system. 

It enables users to easily manage, configure, and operate jails through an intuitive interface. With Bastix, tasks like creating, controlling, or removing jails become seamless.

## Features
- **Jail Management**: Create, destroy, start, stop, and restart FreeBSD jails.
- **GUI Interface**: A user-friendly graphical interface built for managing bastille jails without the need for terminal commands.
- **Network Configuration** :TODO: Allow users to set up port forwarding and manage jail network settings.
- **Bootstrap Support**: Automate FreeBSD release bootstrapping for jail environments.
- **Monitoring Tools**: View jail details, logs, and activity status in real-time.

## System Requirements
- **Operating System**: FreeBSD (13 or higher recommended).
- **Python**: Version 3.6 or higher (tested with Python 3.11).
- **Dependencies**:
    - `PyQt5`
    - `request`
    - `doas`
    - `qt-sudo` 

## Installation
First, download the Bastix project and run the following commands:

### 1. Configure the Build
```bash
./configure --prefix=/custom/path
```
- `--prefix` specifies the installation directory (default: `/usr/local`).

### 2. Install Bastix
```bash
make install
```

### 3. Run Bastix
Once installed, simply run the following command to start the GUI:
```bash
bastix
```

## Uninstallation
To uninstall Bastix, use the following command:
```bash
make uninstall
```

## Development
### Files and Structure
- **`bastix`**:
  The entry-point shell script, responsible for verifying dependencies and launching the Python application.
- **`bastix.py`**:
  The core application that provides the GUI for managing FreeBSD's Bastille jail system.
- **`Makefile`**:
  Used for managing installation and uninstallation processes.
- **`configure`**:
  A setup script for specifying installation preferences and validating dependencies.

### How to Contribute
Contributions are welcome! Please fork the repository and submit pull requests with detailed summaries of your changes.

## License
This project is licensed under the MIT License. See the `LICENSE` file for details.

## Support
If you encounter any issues or have questions, feel free to open an issue in the GitHub repository.
