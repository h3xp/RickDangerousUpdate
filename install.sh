#!/bin/bash
: '
This script makes running the script very easy.
It installs pip3 (necessary to install package dependencies),
installs dependencies and starts the updater.

parameters [git repo, mega link (optional), "-update" or "-remove" (optional)]
'
sudo apt-get -y install python3-pip && pip3 install -r <(curl "https://raw.githubusercontent.com/h3xp/RickDangerousUpdate/main/requirements.txt" -s -N) && python3 <(curl "https://raw.githubusercontent.com/h3xp/RickDangerousUpdate/main/install.py" -s -N) "main" $3