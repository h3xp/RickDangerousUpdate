#!/bin/bash
: '
This script makes running the script very easy.
It installs pip3 (necessary to install package dependencies),
installs dependencies and starts the updater.
'
sudo apt-get -y install python3-pip && pip3 install -r <(curl "https://raw.githubusercontent.com/h3xp/RickDangerousUpdate/v2.2.0/requirements.txt" -s -N) && python3 <(curl "https://raw.githubusercontent.com/h3xp/RickDangerousUpdate/v2.2.0/install.py" -s -N) $1 $2