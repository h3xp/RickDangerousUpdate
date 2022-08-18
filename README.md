# RickDangerousUpdate Script

This script aims to help people adding improvements, fixing known bugs or resetting certain configurations.
It can be run directly from the retropie and apply updates locally, or you can run it on a device in the same local network by providing ssh credentials.


```
 ===========[ MAIN MENU ]=============

 1. Load Improvements ✨
 2. Fix known bugs 🐛
 3. Restore retroarch configurations 👾
 4. Update this script 📄
 9. Quit ❌
```

# Installation

Make sure you have python3 and pip3 installed. If you are running this on the retropie directly install pip3 with this command:

```
sudo apt-get install python3-pip
```

You can download this repository with your browser by pressing the green "Code ▼" button and clicking on "Download ZIP".
Make sure to extract the zip afterwards.

Alternatively if you have git installed on your computer (it is installed on your retropie) you can run:
```bash
git clone https://github.com/h3xp/RickDangerousUpdate.git
```

```bash
cd RickDangerousUpdate
pip3 install -r requirements.txt
```

# Usage

The script is self-explanatory, it will guide you through the whole process, you make your choices by simple pressing numbers on your keyboard.
Just run the script inside a terminal like this:

```
python3 update.py 
```

# Attention

The script automatically creates a 'config.ini' which saves your SSH credentials.

The script will overwrite files on your retropie.

You will lose any changes you made to gamelist.xml or any other configuration file if they are included in any improvement archive.
