# ArchLinux Configuration

Jon's personal manager for all ArchLinux configuration.

## Setup

Current local development just uses a virtual environment.

    python3 -m venv venv
    source venv/bin/activate
    pip install -U pip
    pip install -e .

Afterwards, you can run the `arch-config` command.

## WSL2

Create `/etc/wsl.conf` on the Linux distribution (or `.wslconfig`) with:

    [automount]
    options="metadata"
