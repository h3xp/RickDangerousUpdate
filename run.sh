#!/bin/bash
: '
This script makes the installation process very easy.
It installs pip3 (necessary to install package dependencies), clones the repository of the updater,
installs dependencies and starts the updater.
'
sudo apt-get -y install python3-pip && pip3 install -r <(curl "https://raw.githubusercontent.com/h3xp/RickDangerousUpdate/main/requirements.txt" -s -N) && python3 <(curl "https://raw.githubusercontent.com/h3xp/RickDangerousUpdate/main/update.py" -s -N)
