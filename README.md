# This is a work-in-progress and not ready to be used!

# RickDangerousUpdate Script

This script aims to help people adding improvements, fixing known bugs or resetting certain configurations.

# Installation & Run

You might need to install the paramiko module before running:
```
pip3 install paramiko
python3 update.py
```

# Attention

The script currently does not support automatically pulling the improvement archives, you need to download them manually.
They are available in the `#improvements` channel on Ricks Discord Server: https://discord.gg/mEXFv7yhhW

Be aware: The script will overwrite the files on your retropie according to the file structure in the zip-archive.
It is recommended to check first if the file paths are correct. The script requires paths starting at root (/).

You will loose any changes you made to gamelist.xml or any other configuration file if they are included in any improvement archive.
