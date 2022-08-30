![Nice banner saying Insanium Edition Update Tool](banner.png)

**Disclaimer:** This repository is only for educational purpose. Only use this with your own files/backups.

This script aims to help people adding improvements, fixing known bugs or resetting certain configurations.
It can be run directly from the retropie and apply updates locally, or you can run it on a device in the same local network by providing ssh credentials.


Join Ricks discord server to keep track on the latest changes.


![RickDangerousDiscordBanner](https://discordapp.com/api/guilds/857515631422603286/widget.png?style=banner2)


```
 ===========[ MAIN MENU ]=============

 1. Load Improvements ✨ [recommended]
 2. Fix known bugs 🐛 [recommended]
 3. Restore retroarch configurations 👾
 4. Reset emulationstation configurations ⌨
 9. Quit ❌
```

# Easy Installation & Usage (recommended)
The easiest way to run the updater is to install it on to your RetroPie directly, this will make it available via the Options menu.

You can now install the updater onto your RetroPie directory using SSH on your personal computers, by running the following command on your personal computer:
(Replace [IP] with the IP address of your RetroPie)
(Replace [link] with a URL to the mega storage containing the updates)

```
ssh pi@[IP] "python3 <(curl 'https://raw.githubusercontent.com/h3xp/RickDangerousUpdate/v1.0.1/install.py' -s -N) '[link]'"
```

If you do not want to install the updater on your RetroPie, you can still run the updater from the RetroPie directly by running the following command in the RetroPie terminal:
(Replace [link] with a URL to the mega storage containing the updates)


```
bash <(curl "https://raw.githubusercontent.com/h3xp/RickDangerousUpdate/main/run.sh" -s -N) [link]
```

![A short gif showing a demo of the tool in use.](demo.gif)

# Alternative Installation (using SSH)

If you wish to run it manually or on a Windows system make sure python3 and pip3 is installed.

You can download this repository with your browser by pressing the green "Code ▼" button and clicking on "Download ZIP".
Make sure to extract the zip afterwards.

Alternatively if you have git installed on your computer (it is installed on your retropie) you can run:

```bash
git clone https://github.com/h3xp/RickDangerousUpdate.git
cd RickDangerousUpdate
pip3 install -r requirements.txt
```


The script is self-explanatory, it will guide you through the whole process, you make your choices by simple pressing numbers on your keyboard.
Just run the script inside a terminal like this (replace [URL] with a URL to the mega storage containing the updates):

```
python3 update.py [link]
```

# Attention

The script automatically creates a 'config.ini' which saves your SSH credentials if you use it remotely.

The script has been tested, however we can't give a 100% guarantee that it might not break something on
your retropie. Therefore, use this at your own risk.
