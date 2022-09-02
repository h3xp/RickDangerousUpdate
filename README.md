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
 5. Installtion
 9. Quit ❌
```

The update tool has an "Installation" menu option.
Installation will make the tool available from the "Options" tab in EmulationStation.

The three options on the "Installation" menu are:
- Install - this option will install fresh, overwriting any existing configuration.
- Update - this option will update your version to the most current version available.
- Uninstall - this option will remove the tool entirely from the "Options" tab in EmulationStation..


# Easy Installation & Usage (recommended)
The easiest way to run the updater is to install it on to your RetroPie directly, this will make it available via the Options menu.

You can now install the update tool onto your RetroPie directory using SSH from your personal computer, or directly on your RetroPie.
- (Replace [IP] with the IP address of your RetroPie)
- (Replace [link] with a URL to the mega storage containing the updates)

From your personal computer using SSH:

```
ssh pi@[IP] "bash <(curl 'https://raw.githubusercontent.com/h3xp/RickDangerousUpdate/main/install.sh' -s -N) [link]"
```

Or directly from your RetroPie:

```
bash <(curl 'https://raw.githubusercontent.com/h3xp/RickDangerousUpdate/main/install.sh' -s -N) [link]
```


If you do not want to install the update tool on your RetroPie, you can still run the update tool directly from the RetroPie by running the following command in the RetroPie terminal (you will still be able to install via the "Installation" menu if you wish):
- (Replace [link] with a URL to the mega storage containing the updates)

```
bash <(curl 'https://raw.githubusercontent.com/h3xp/RickDangerousUpdate/main/run.sh' -s -N) [link]
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
Just run the script inside a terminal like this:
- (Replace [URL] with a URL to the mega storage containing the updates):

```
python3 update.py [link]
```

# Attention

The script automatically creates a 'config.ini' which saves your SSH credentials if you use it remotely.

The script has been tested, however we can't give a 100% guarantee that it might not break something on
your retropie. Therefore, use this at your own risk.
