#!/bin/bash
: '
This script makes running the script very easy.
It refreshes apt repository information,
installs pip3 (necessary to install package dependencies),
installs dependencies and starts the updater.
'
sudo apt-get update && sudo apt-get -y install python3-pip && pip3 install -r <(curl "https://raw.githubusercontent.com/h3xp/RickDangerousUpdate/main/requirements.txt" -s -N) && python3 <(curl "https://raw.githubusercontent.com/h3xp/RickDangerousUpdate/main/install.py" -s -N) $1 $2
