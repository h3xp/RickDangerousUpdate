#!/bin/bash
: '
This script makes the installation process very easy.
It installs pip3 (necessary to install package dependencies), clones the repository of the updater,
installs dependencies and starts the updater.
'
sudo apt-get install python3-pip -y && git clone https://github.com/h3xp/RickDangerousUpdate && cd RickDangerousUpdate && pip3 install -r requirements.txt && python3 update.py