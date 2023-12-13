"""
Update Script for Rick Dangerous' Insanium/R.P.E
https://github.com/h3xp/RickDangerousUpdate
"""

from asyncio import streams
from genericpath import isdir, isfile
from http.client import OK
import os
import zipfile
import platform
#from distutils.dir_util import copy_tree
import distutils.dir_util
import json
from pathlib import Path
import re
import tempfile
import requests
import logging
import urllib.request
from Crypto.Cipher import AES
from Crypto.Util import Counter
from mega.crypto import base64_to_a32, base64_url_decode, decrypt_attr, decrypt_key, a32_to_str, get_chunks, str_to_a32
from mega.errors import RequestError
import xml.etree.ElementTree as ET
import datetime
import shutil
import sys
import configparser
import subprocess
from dialog import Dialog
from packaging import version
import copy
import traceback
import time

d = Dialog()
d.autowidgetsize = True

logger = logging.getLogger(__name__)
update_available_result = "no connection"
tool_ini = "/home/pi/.update_tool/update_tool.ini"

genres = {}
update_being_processed = "None"

def print_files(current_files: dict, file_list: list, log_file: str, spacer="\t", starter="-"):
    for file in file_list:
        if file in current_files:
            values = current_files[file]
            file_sizes = ""
            if values[0] == "ADDED":
                file_sizes = f"(current size: {values[2]})"
            elif values[0] == "UPDATED":
                file_sizes = f"(current size: {values[2]}, previous size: {values[3]})"
            elif values[0] == "DELETED":
                file_sizes = f"(previous size: {values[3]})"

            log_this(log_file, f"{starter}\"{file}\"{spacer}{file_sizes}")

    return


def list_info_in_update(current_files: dict, path: str, log_file: str, directories: list):
    files = {}
    files_added = []
    files_deleted = []
    files_updated = []
    pre_processing = []
    post_processing = []

    log_this(log_file, "")
    log_this(log_file, "")
    log_this(log_file, "**********")
    log_this(log_file, f"Now Processing: \"{os.path.basename(path)}\" [{convert_filesize(str(os.path.getsize(path)))}]")
    log_this(log_file, "**********")

    with zipfile.ZipFile(path, 'r') as zip_ref:
        if "read me do this first!.txt" in zip_ref.namelist():
            zip_ref.extract("read me do this first!.txt", "/tmp")
            with open("/tmp/read me do this first!.txt", 'r', encoding='utf-8') as f:
                lines = f.readlines()
                for line in lines:
                    line = line.strip()
                    previous_size = None
                    file_dir = get_file_dir(line, directories)
                    if len(file_dir) > 0:
                        if line in current_files:
                            values = current_files[line]
                            #previous_size = convert_filesize(values[2])
                            previous_size = values[2]

                        current_files[line] = ["DELETED", os.path.basename(path), None, previous_size]
                        files_deleted.append(line)
                        
        if "read me pre-process!.txt" in zip_ref.namelist():
            zip_ref.extract("read me pre-process!.txt", "/tmp")
            with open("/tmp/read me pre-process!.txt", 'r', encoding='utf-8') as f:
                lines = f.readlines()
                for line in lines:
                    pre_processing.append(line)

        if "read me post-process!.txt" in zip_ref.namelist():
            zip_ref.extract("read me post-process!.txt", "/tmp")
            with open("/tmp/read me post-process!.txt", 'r', encoding='utf-8') as f:
                lines = f.readlines()
                for line in lines:
                    post_processing.append(line)

        for file_listing in zip_ref.infolist():
            #info_dict = parse_zipinfo(file_listing)
            #print(f"{file_listing.filename}\t{file_listing.file_size}")
            file = "/" + file_listing.filename
            file_dir = get_file_dir(file, directories)
            
            if len(file_dir) > 0:
                print(file)
                status = ""
                file_size = convert_filesize(str(file_listing.file_size))
                if file in current_files.keys():
                    values = current_files[file]
                    if values[0] == "DELETED":
                        files_added.append(file)
                        current_files[file] = ["ADDED", os.path.basename(file), file_size, None]
                    else:
                        files_updated.append(file)
                        current_files[file] = ["UPDATED", os.path.basename(file), file_size, values[2]]
                else:
                    files_added.append(file)
                    current_files[file] = ["ADDED", os.path.basename(file), file_size, None]

    if len(files_deleted) > 0:
        log_this(log_file, "")
        log_this(log_file,"DELETED")
        files_deleted = print_sort(files_deleted, directories)
        print_files(current_files, files_deleted, log_file)

    if len(pre_processing) > 0:
        log_this(log_file, "")
        log_this(log_file,"PRE-PROCESSING COMMANDS")
        for pre_cmd in pre_processing:
            log_this(log_file, pre_cmd)

    if len(files_added) > 0:
        log_this(log_file, "")
        log_this(log_file,"ADDED")
        files_added = print_sort(files_added, directories)
        print_files(current_files, files_added, log_file)

    if len(files_updated) > 0:
        log_this(log_file, "")
        log_this(log_file,"UPDATED")
        files_updated = print_sort(files_updated, directories)
        print_files(current_files, files_updated, log_file)

    if len(post_processing) > 0:
        log_this(log_file, "")
        log_this(log_file,"POST-PROCESSING COMMANDS")
        for post_cmd in post_processing:
            log_this(log_file, post_cmd)

    return

def get_org_files(dirs: list):
    files = {}

    for dir in dirs:
        print(f"Getting {dir}...")
        os.chdir(dir)
        subprocess.check_output(["/bin/bash","-c","find . -ls > /tmp/full_dir_listing.txt"])

        with open("/tmp/full_dir_listing.txt", 'r') as file:
            lines = file.readlines()
            for line in lines:
                loc = line.find("./")
                if loc >= 0:
                    str = line[loc:].replace("\\ ", " ").replace("./", dir).strip()
                    if os.path.isfile(str):
                        size = convert_filesize(get_parsed_part(line, 7))
                        files[str] = size
                        log_this("/tmp/org_full_dir_listing.txt", str + "\t" + files[str])           

    files = {}

    with open("/tmp/org_full_dir_listing.txt", 'r', encoding='utf-8') as f:
        lines = f.readlines()
        for line in lines:
            line = line.strip()
            file = line.split("\t")
            files[file[0]] = ("ADDED", "Current Filesystem State", file[1], None)
            #file_dir = get_file_dir(file[0])
            #if len(file_dir) > 0:
                #print(file[0])
                #files[file[0]] = ("ADDED", "Current Filesystem State", file[1], None)

    if os.path.isfile("/tmp/full_dir_listing.txt"):
        os.remove("/tmp/full_dir_listing.txt")
    if os.path.isfile("/tmp/org_full_dir_listing.txt"):
        os.remove("/tmp/org_full_dir_listing.txt")

    return files


def print_sort(file_list: list, directories: list):
    retval = []
    dirs = {}
    for file in file_list:
        file_dir = get_file_dir(file, directories)
        if len(file_dir) > 0:
            files = []
            if file_dir in dirs:
                files = dirs[file_dir]
            files.append(file)
            dirs[file_dir] = files

    sorted_dirs = sorted(dirs.keys())
    for sorted_dir in sorted_dirs:
        files = dirs[sorted_dir]
        files.sort()
        for file in files:
            retval.append(file)

    return retval


def get_file_dir(filename: str, directories: list):
    #rom_path = "/home/pi/RetroPie/roms/"
    #if rom_path in filename:
    for directory in directories:
        if directory not in filename:
            continue
        current_file = filename.replace(os.path.basename(filename), "")
        if current_file.find("/") >= 0:
            #rom_dir = rom_path + current_file[0:current_file.find("/")]
            file_dir = filename[0:filename.rindex("/") + 1]
            file_name = filename.replace(file_dir, "")
            if len(file_name.strip()) == 0:
                return ""

            return file_dir

    return ""


def get_parsed_part(line: str, part: int):
    retval = ""
    i = 0
    pos = 0

    while i < part:
        retval = ""
        while line[pos:pos+1] == " ":
            pos += 1
        i += 1
        while line[pos:pos+1] != " ":
            retval += line[pos:pos+1]
            pos += 1

    return retval.strip()


def get_manual_updates_story():
    log_file = "/home/pi/.update_tool/manual_updates_story.txt"
    dir_list = get_config_value("ALWAYS_OVERWRITE", "relevant_directories")
    directories = dir_list.strip().split(",")

    megadrive = check_drive()

    update_dir = get_valid_path_portion(get_default_update_dir())
    update_dir = manual_updates_dialog(update_dir, False)
    update_dir = get_config_value("CONFIG_ITEMS", "update_dir")
    
    # forcing this to a directory
    updates = official_improvements_dialog(update_dir=get_config_value("CONFIG_ITEMS", "update_dir"), process_improvements=False)
    if updates is None or len(updates) == 0:
        d.msgbox("No updates selected!")
        return
    updates = sort_official_updates(updates)

    print("Getting current filesystem state, then processing...")
    current_files = get_org_files(directories)

    log_this(log_file, "**********", overwrite=True)
    log_this(log_file, "Manual Updates Story!")
    log_this(log_file, "**********")
    log_this(log_file, "")
    log_this(log_file, "These are the changes to your filesystem that would happen from applying these updates...")
    log_this(log_file, "")

    log_this(log_file, "Directories processed:")
    for directory in directories:
        log_this(log_file, "- " + directory)
    log_this(log_file, "")

    log_this(log_file, "Updates evaulated:")
    for update in updates:
        log_this(log_file, "- " + os.path.join(update_dir, update[0]))
    
    for update in updates:
        print("Processing \"" + os.path.join(update_dir, update[0]) + "\"...")
        list_info_in_update(current_files, os.path.join(update_dir, update[0]), log_file, directories)

    cls()
    d.textbox(log_file, title=f"Contents of {log_file}")       

    return


def safe_write_backup(file_path: str, file_time=""):
    if file_time == "":
        file_time = datetime.datetime.utcnow().strftime("%Y%m%d-%H%M%S")

    shutil.copy2(file_path, file_path + "--" + file_time)

    return file_time


def safe_write_check(file_path: str, file_time: str):
    if os.path.getsize(file_path) == 0:
        # this somehow failed badly
        shutil.copy2(file_path + "--" + file_time, file_path)
        return False

    os.remove(file_path + "--" + file_time)

    return True


def get_git_repo():
    if os.path.exists(tool_ini):
        git_repo = get_config_value("CONFIG_ITEMS", "git_repo")
        if git_repo is not None:
            return git_repo

    return "https://raw.githubusercontent.com/h3xp/RickDangerousUpdate"


def get_git_branch():
    if os.path.exists(tool_ini):
        git_branch = get_config_value("CONFIG_ITEMS", "git_branch")
        if git_branch is not None:
            return git_branch

    return "main"
    
    
def get_overlay_systems():
    retval = [[], []]
    path = "/opt/retropie/configs"

    for file in os.listdir(path):
        if file == "all":
            continue

        system = os.path.join(path, file)
        if os.path.isdir(system):
            if os.path.isfile(os.path.join(system, "retroarch.cfg")):
                with open(os.path.join(system, "retroarch.cfg"), 'r') as configfile:
                    system_overlay = False
                    overlay_on = False

                    lines = configfile.readlines()
                    for line in lines:
                        if "input_overlay" in line:
                            pos = line.find("=")
                            if pos > 0:
                                if len(line[pos].strip()) > 0:
                                    if file not in retval[0]:
                                        retval[0].append(file)
                                    if line.strip()[0:1] != "#":
                                        if file not in retval[1]:
                                            retval[1].append(file)

    retval[0].sort()

    return retval


def read_ini(ini_file: str):
    if os.path.isfile(ini_file):
        config = configparser.ConfigParser()
        config.optionxform = str
        config.read(ini_file)
        return config

    return None


def read_config():
    if os.path.exists(tool_ini):
        if os.path.isfile(tool_ini):
            config = configparser.ConfigParser()
            config.optionxform = str
            config.read(tool_ini)
            return config
    return None
    

def get_ini_section(ini_file: str, section: str):
    config = read_ini(ini_file)
    if config is not None:
        if config.has_section(section):
            return config.items(section)

    return None


def get_config_section(section: str):
    config = read_config()
    if config is not None:
        if config.has_section(section):
            return config.items(section)

    return None


def get_ini_value(ini_file: str, section: str, key: str, return_none=True):
    config = read_ini(ini_file)
    if config is not None:
        if config.has_option(section, key):
            return config[section][key]

    if return_none == False:
        return ""

    return None


def get_config_value(section: str, key: str, return_none=True):
    config = read_config()
    if config is not None:
        if config.has_option(section, key):
            return config[section][key]

    if return_none == False:
        return ""

    return None


def is_valid_mega_link(url: str):
    pattern = re.compile("^https://mega\.nz/((folder|file)/([^#]+)#(.+)|#(F?)!([^!]+)!(.+))$")
    if pattern.match(url):
        return True

    return False


def retrieve_mega_config(read_config: bool):
    mega_dir = get_config_value("CONFIG_ITEMS","mega_dir")
    if is_valid_mega_link(mega_dir):
        mega_config = configparser.ConfigParser()
        mega_config.optionxform = str
        mega_ini = f"/home/pi/.update_tool/mega_{mega_dir.split('/')[-1]}.ini"
        if read_config:
            mega_config.read(mega_ini)
        return mega_config,mega_ini

    return None,None


def get_mega_config_section(section: str):
    mega_config,mega_ini = retrieve_mega_config(True)
    if mega_config is not None:
        if mega_config.has_section(section):
            return mega_config.items(section)

    return None


def get_mega_config_value(section: str, key: str):
    mega_config,mega_ini = retrieve_mega_config(True)
    if mega_config is not None:
        if mega_config.has_option(section, key):
            return mega_config[section][key]

    return None


def set_config_value(section: str, key: str, value: str):
    config = read_config()
    if config is not None:
        if config.has_section(section) == False:
            config.add_section(section)

        config[section][key] = value

        with open(tool_ini, 'w') as configfile:
            config.write(configfile)

        return True

    return False


def set_mega_config_value(section: str, key: str, value: str):
    mega_config,mega_ini = retrieve_mega_config(True)
    if mega_config is not None:
        if mega_config.has_section(section) == False:
            mega_config.add_section(section)

        mega_config[section][key] = value

        with open(mega_ini, 'w') as configfile:
            mega_config.write(configfile)

        return True

    return False


def mega_ini_check():
    mega_config,mega_ini = retrieve_mega_config(False)
    # if the mega ini files does not exist then initialize it
    if os.path.exists(mega_ini) == False:
        mega_config.add_section("INSTALLED_UPDATES")
        with open(mega_ini, 'w') as configfile:
            mega_config.write(configfile)
    
    return True

    
def restart_es():
    runcmd("sudo reboot")
    #runcmd("touch /tmp/es-restart && pkill -f \"/opt/retropie/supplementary/.*/emulationstation([^.]|$)\"")
    #runcmd("sudo systemctl restart autologin@tty1.service")
    return


def cronjob_exists(unique):
    output = runcmd("crontab -l 2>/dev/null")
    if unique in output:
        return True
    else:
        return False


def autostart_exists(unique):
    output = runcmd("cat /opt/retropie/configs/all/autostart.sh")
    if unique in output:
        return True
    else:
        return False


def toggle_countofficialonly():
    if os.path.exists(tool_ini):
        if get_config_value('CONFIG_ITEMS', 'count_official_only') == "True":
            toggle = "False"
            toggle_msg = "disabled"
        else:
            toggle = "True"
            toggle_msg = "enabled"

        set_config_value('CONFIG_ITEMS', 'count_official_only', toggle)
        d.msgbox('Count official games ' + toggle_msg + '! Reboot to apply changes')
        main_dialog()
    else:
        d.msgbox('To use this feature make sure to install the tool.')
        main_dialog()


def toggle_autoclean():
    if os.path.exists(tool_ini):
        if get_config_value('CONFIG_ITEMS', 'auto_clean') == "True":
            toggle = "False"
            toggle_msg = "disabled"
        else:
            toggle = "True"
            toggle_msg = "enabled"

        set_config_value('CONFIG_ITEMS', 'auto_clean', toggle)
        d.msgbox('Auto clean ' + toggle_msg + '! Reboot to apply changes')
        main_dialog()
    else:
        d.msgbox('To use this feature make sure to install the tool.')
        main_dialog()
    

def remove_notification():
    runcmd("crontab -l | sed '/.update_tool/d' | crontab")
    runcmd("sed '/update_tool/d' /opt/retropie/configs/all/autostart.sh >/tmp/ut.$$ ; mv /tmp/ut.$$ /opt/retropie/configs/all/autostart.sh")

    return


def select_notification():
    if os.path.exists(tool_ini):
        previous_method = get_config_value('CONFIG_ITEMS', 'display_notification')

        code, tag = d.radiolist("Choose which notification method you want to use",
                    choices=[("False", "Do not notify about game updates", previous_method == "False"),
                             ("Theme", "Notify about game updates via themes", previous_method == "Theme"),
                             ("Tool", "Notify about game updates via update tool", previous_method == "Tool")],
                    title="Game Update Notification",
                    ok_label="Set Method")

        if code == d.OK:
            remove_notification()
            if tag in ["Theme", "Tool"]:
                runcmd("( echo 'update_tool notify' ; cat /opt/retropie/configs/all/autostart.sh ) >/tmp/ut.$$ ; mv /tmp/ut.$$ /opt/retropie/configs/all/autostart.sh")
            set_config_value('CONFIG_ITEMS', 'display_notification', tag)
            d.msgbox('Display Notification ' + tag + '!\n\n Reboot to apply changes')
                        
        #if code == d.OK and previous_method != tag:
        #    if tag == "False":
        #        if previous_method == "Theme":
        #            runcmd("crontab -l | sed '/.update_tool/d' | crontab")
        #        if previous_method == "Tool":
        #            runcmd("sed '/update_tool/d' /opt/retropie/configs/all/autostart.sh >/tmp/ut.$$ ; mv /tmp/ut.$$ /opt/retropie/configs/all/autostart.sh")

        #    if tag == "Theme":
        #        if not cronjob_exists("update_tool"):
        #            runcmd("( crontab -l 2>/dev/null ; echo '@reboot python3 /home/pi/.update_tool/notification.py' ) | crontab")
        #        if previous_method == "Tool":
        #            runcmd("sed '/update_tool/d' /opt/retropie/configs/all/autostart.sh >/tmp/ut.$$ ; mv /tmp/ut.$$ /opt/retropie/configs/all/autostart.sh")

        #    if tag == "Tool":
        #        if not autostart_exists("update_tool"):
        #            runcmd("( echo 'update_tool notify' ; cat /opt/retropie/configs/all/autostart.sh ) >/tmp/ut.$$ ; mv /tmp/ut.$$ /opt/retropie/configs/all/autostart.sh")
        #        if previous_method == "Theme":
        #            runcmd("crontab -l | sed '/.update_tool/d' | crontab")

        #    set_config_value('CONFIG_ITEMS', 'display_notification', tag)
        #    d.msgbox('Display Notification ' + tag + '!\n\n Reboot to apply changes')
    else:
        d.msgbox('To use this feature make sure to install the tool.')
    return
 

def is_update_applied(key: str, modified_timestamp: str):
    if os.path.exists(tool_ini) == False:
        return False

    mega_config,mega_ini = retrieve_mega_config(True)
    if mega_config.has_option("INSTALLED_UPDATES", key):
        return mega_config["INSTALLED_UPDATES"][key] == str(modified_timestamp)

    return False


def uninstall():
    git_repo = get_git_repo()
    git_branch = get_git_branch()
    runcmd(f"bash <(curl '{git_repo}/{git_branch}/install.sh' -s -N) -remove")
    return


def update():
    git_repo = get_git_repo()
    git_branch = get_git_branch()
    runcmd(f"bash <(curl '{git_repo}/{git_branch}/install.sh' -s -N) -update")
    return


def install():
    git_repo = get_git_repo()
    git_branch = get_git_branch()
    megadrive = check_drive()
    runcmd(f"bash <(curl '{git_repo}/{git_branch}/install.sh' -s -N) {megadrive}")
    return


def status_bar(total_size: float, current_size: float, start_time: datetime, complete=False, start_char="\t"):
    current_time = datetime.datetime.utcnow()
    percent_complete = round((current_size / total_size) * 100)
    if percent_complete > 99 and not complete:
        percent_complete = 99
    kbs = return_bps(current_size, (current_time - start_time).total_seconds())
    pad = (12 - len(kbs))

    if not complete:
        print(f"{start_char}{percent_complete if percent_complete < 100 else 99}% complete: [{'='*percent_complete}>{' '*(99 - percent_complete)}] ({kbs}) (total elapsed time: {str(current_time - start_time)[:-7]}){' '*pad}", end = "\r")
    else:
        print(f"{start_char}100% complete: [{'='*100}] ({kbs}) (total elapsed time: {str(current_time - start_time)[:-7]}){' '*pad}")

    return


def return_bps(bytes: float, seconds: float):
    retval = ""
    units = ["B", "KB", "MB", "GB"]
    unit = "B"
    count = 0
    filesize = bytes / seconds
    while (filesize) >= 1000:
        count += 1
        filesize /= 1024

    if count == 0:
        retval = "%0.2f" % filesize + " " + unit + "/s"
    else:
        retval = "%0.2f" % filesize + " " + units[count] + "/s"

    return retval    


def download_file(file_handle,
                  file_key,
                  file_data,
                  dest_path,
                  dest_filename=None):
    k = (file_key[0] ^ file_key[4], file_key[1] ^ file_key[5],
         file_key[2] ^ file_key[6], file_key[3] ^ file_key[7])
    iv = file_key[4:6] + (0, 0)
    meta_mac = file_key[6:8]

    start_time = datetime.datetime.utcnow()

    # Seems to happens sometime... When this occurs, files are
    # inaccessible also in the official also in the official web app.
    # Strangely, files can come back later.
    if 'g' not in file_data:
        raise RequestError('File not accessible anymore')
    file_url = file_data['g']
    file_size = file_data['s']
    attribs = base64_url_decode(file_data['at'])
    attribs = decrypt_attr(attribs, k)
    print(f"\t{0}% complete: [>{' '*99}]", end = "\r")
    file_name = attribs['n']

    input_file = requests.get(file_url, stream=True).raw

    if dest_path is None:
        dest_path = ''
    else:
        dest_path += '/'

    with tempfile.NamedTemporaryFile(mode='w+b',
                                     prefix='megapy_',
                                     delete=False) as temp_output_file:
        k_str = a32_to_str(k)
        counter = Counter.new(128,
                              initial_value=((iv[0] << 32) + iv[1]) << 64)
        aes = AES.new(k_str, AES.MODE_CTR, counter=counter)

        mac_str = '\0' * 16
        mac_encryptor = AES.new(k_str, AES.MODE_CBC,
                                mac_str.encode("utf8"))
        iv_str = a32_to_str([iv[0], iv[1], iv[0], iv[1]])
        i = None
        for chunk_start, chunk_size in get_chunks(file_size):
            #percent_complete = round(((chunk_start + chunk_size) / file_size) * 100)
            #print(f"\t{percent_complete if percent_complete < 100 else 99}% complete: [{'='*percent_complete}>{' '*(99 - percent_complete)}]", end = "\r")
            status_bar(file_size, (chunk_start + chunk_size), start_time)

            chunk = input_file.read(chunk_size)
            chunk = aes.decrypt(chunk)
            temp_output_file.write(chunk)

            encryptor = AES.new(k_str, AES.MODE_CBC, iv_str)
            for i in range(0, len(chunk) - 16, 16):
                block = chunk[i:i + 16]
                encryptor.encrypt(block)

            # fix for mega limit
            if i is None:
                return None

            # fix for files under 16 bytes failing
            if file_size > 16:
                i += 16
            else:
                i = 0

            block = chunk[i:i + 16]
            if len(block) % 16:
                block += b'\0' * (16 - (len(block) % 16))
            mac_str = mac_encryptor.encrypt(encryptor.encrypt(block))

            file_info = os.stat(temp_output_file.name)
            logger.info('%s of %s downloaded', file_info.st_size,
                        file_size)
        file_mac = str_to_a32(mac_str)
        # check mac integrity
        if (file_mac[0] ^ file_mac[1],
                file_mac[2] ^ file_mac[3]) != meta_mac:
            raise ValueError('Mismatched mac')
        output_path = Path(dest_path + file_name)
    #print(f"\t100% complete: [{'='*100}]")
    status_bar(file_size, file_size, start_time, complete=True)
    shutil.move(temp_output_file.name, output_path)
    return output_path


def get_file_data(file_id: str, root_folder: str):
    data = [{'a': 'g', 'g': 1, 'n': file_id}]
    response = requests.post(
        "https://g.api.mega.co.nz/cs",
        params={'id': 0,  # self.sequence_num
                'n': root_folder},
        data=json.dumps(data)
    )
    json_resp = response.json()
    return json_resp[0]


# def get_nodes_in_shared_folder(root_folder: str) -> dict:
def get_nodes_in_shared_folder(root_folder: str):
    data = [{"a": "f", "c": 1, "ca": 1, "r": 1}]
    response = requests.post(
        "https://g.api.mega.co.nz/cs",
        params={'id': 0,  # self.sequence_num
                'n': root_folder},
        data=json.dumps(data)
    )
    json_resp = response.json()
    return json_resp[0]["f"]


# def parse_folder_url(url: str) -> Tuple[str, str]:
def parse_folder_url(url: str):
    "Returns (public_handle, key) if valid. If not returns None."
    REGEXP1 = re.compile(
        r"mega.[^/]+/folder/([0-z-_]+)#([0-z-_]+)(?:/folder/([0-z-_]+))*")
    REGEXP2 = re.compile(
        r"mega.[^/]+/#F!([0-z-_]+)[!#]([0-z-_]+)(?:/folder/([0-z-_]+))*")
    m = re.search(REGEXP1, url)
    if not m:
        m = re.search(REGEXP2, url)
    if not m:
        print("Not a valid URL")
        return None
    root_folder = m.group(1)
    key = m.group(2)
    # You may want to use m.groups()[-1]
    # to get the id of the subfolder
    return (root_folder, key)


# def decrypt_node_key(key_str: str, shared_key: str) -> Tuple[int, ...]:
def decrypt_node_key(key_str: str, shared_key: str):
    encrypted_key = base64_to_a32(key_str.split(":")[1])
    return decrypt_key(encrypted_key, shared_key)


def convert_filesize(file_size: str):
    retval = ""
    filesize = float(file_size)
    units = ["KB", "MB", "GB"]
    unit = "B"
    count = 0
    while (filesize) >= 1000:
        count += 1
        filesize /= 1024

    if count == 0:
        retval = str(round(filesize)) + " " + unit
    elif count == 1:
        retval = str(round(filesize)) + " " + units[count - 1]
    else:
        retval = str(round(filesize, count - 1)) + " " + units[count - 1]

    return retval


def get_available_updates(megadrive: str, status=False):
    if status == True:
        print()
        print("Finding available updates...")
    (root_folder, shared_enc_key) = parse_folder_url(megadrive)
    shared_key = base64_to_a32(shared_enc_key)
    nodes = get_nodes_in_shared_folder(root_folder)
    available_updates = []
    for node in nodes:
        key = decrypt_node_key(node["k"], shared_key)
        if node["t"] == 0:  # Is a file
            k = (key[0] ^ key[4], key[1] ^ key[5],
                 key[2] ^ key[6], key[3] ^ key[7])
        elif node["t"] == 1:  # Is a folder
            k = key
        attrs = decrypt_attr(base64_url_decode(node["a"]), k)
        file_name = attrs["n"]
        file_id = node["h"]
        modified_date = node["ts"]
        if node["t"] == 0:
            file_size = convert_filesize(node["s"])
            available_updates.append([file_name, file_id, modified_date, file_size, node["s"]])
    return available_updates


def download_update(ID, destdir, megadrive, size):
    (root_folder, shared_enc_key) = parse_folder_url(megadrive)
    shared_key = base64_to_a32(shared_enc_key)
    nodes = get_nodes_in_shared_folder(root_folder)
    for node in nodes:
        key = decrypt_node_key(node["k"], shared_key)
        if node["t"] == 0:  # Is a file
            k = (key[0] ^ key[4], key[1] ^ key[5],
                 key[2] ^ key[6], key[3] ^ key[7])
        elif node["t"] == 1:  # Is a folder
            k = key
        attrs = decrypt_attr(base64_url_decode(node["a"]), k)
        file_id = node["h"]
        if file_id == ID:
            print(f"Downloading: {attrs['n']} ({size})...")
            file_data = get_file_data(file_id, root_folder)
            file_path = download_file(file_id, key, file_data, str(destdir))

    return file_path


def cls():
    os.system('cls' if os.name == 'nt' else 'clear')


def runcmd(command):
    code = subprocess.check_output(["/bin/bash","-c",command])
    return str(code, "UTF-8")
    #return os.popen(command).read()


def copyfile(localpath, filepath):
    shutil.copy(localpath, filepath)


def copydir(source_path, target_path):
    #copy_tree(source_path, target_path)
    distutils.dir_util._path_created = {}
    distutils.dir_util.copy_tree(source_path, target_path)


def fix_permissions():
    runcmd('sudo chown -R pi:pi ~/RetroPie/roms/ && sudo chown -R pi:pi ~/.emulationstation/')
    d.msgbox("Done! Permissions have been reset!")
    main_dialog()


def permissions_dialog():
    code = d.yesno('Your permissions seem to be wrong, which is a known bug in this image.\nThis might prevent you from '
            'saving configurations, gamestates and metadata.\nDo you want this script to fix this issue for you?\n')

    if code == d.OK:
        fix_permissions()

    return


def check_wrong_permissions():
    output = runcmd("find /home/pi/RetroPie/roms -user root")
#    output = runcmd('ls -la /home/pi/RetroPie/ | grep roms | cut -d \' \' -f3,4')
#    if output.rstrip() != 'pi pi':
    if len(output) > 0:
        permissions_dialog()
    else:
        output = runcmd('ls -la /home/pi/.emulationstation/gamelists/retropie | grep " gamelist.xml$" | cut -d \' \' -f3,4')
        if "pi" not in output.rstrip():
            permissions_dialog()


def get_node(element: ET.Element, name: str, return_none=False):
    ret_val = None if return_none == True else ""
    src_node = element.find(name)
    if src_node is not None:
        if src_node.text is not None:
            return str(src_node.text)

    return ret_val


def clear_do_not_overwrite_tags(gamelist: str):
    org_gamelist = gamelist + "-pre"

    if os.path.isfile(gamelist):
        os.rename(gamelist, org_gamelist)
        if os.path.isfile(org_gamelist):
            runcmd(f"grep -e \<lastplayed\> -e \<playcount\> -e \<favorite\> -v {org_gamelist} > {gamelist}")
            if os.path.isfile(gamelist):
                os.remove(org_gamelist)

    return


def clean_recent(collection: str):
    paths = []

    if os.path.exists(collection):
        with open(collection, 'r', encoding='utf-8') as file:
            lines = file.readlines()

        for line in lines:
            line = line.strip()
            if line + "\n" not in paths and os.path.isfile(line):
                paths.append(line + "\n")

        paths.sort()

        with open(collection, 'w', encoding='utf-8') as file:
            file.writelines(paths)

    return


def write_all_roms(gamelist: str, full_path: str, collection: str):
    paths = []
    src_tree = ET.parse(gamelist)
    src_root = src_tree.getroot()

    for src_game in src_root.iter("game"):
        path = get_node(src_game, "path", return_none=True).strip()
        if path is not None:
            paths.append(os.path.join(full_path, os.path.basename(path)) + "\n")

    paths.sort()

    with open(collection, 'a', encoding='utf-8') as file:
        file.writelines(paths)

    return


def write_origins(gamelist: str, origin: str):
    paths = []
    src_tree = ET.parse(gamelist)
    src_root = src_tree.getroot()

    for src_game in src_root.iter("game"):
        path = get_node(src_game, "path", return_none=True).strip()
        if path is not None:
            paths.append(path + "\n")

    paths.sort()

    with open(origin, 'w', encoding='utf-8') as file:
        file.writelines(paths)

    return


def clean_emulators_cfg(items: dict, log_file: str, check=False):
    cleaned = {}
    last_system = ""
    system_dir = ""
    system_roms = []
    bad_entries = 0

    for item in sorted(items.keys()):
        parts = item.split("_")
        if len(parts) == 0 or len(parts[0]) == 0:
            continue
        if parts[0] != last_system:
            system_roms = []
            last_system = parts[0]
            system_dir = os.path.join("/home/pi/RetroPie/roms", parts[0])
            if not os.path.isdir(system_dir):
                bad_entries += 1
                if check == False:
                    log_this(log_file, f"Removed Entry: \"{item}\" (invalid directory \"{system_dir}\")")
                else:
                    log_this(log_file, f"Invalid Entry: \"{item}\" (invalid directory \"{system_dir}\")")

                continue
            for file in os.scandir(system_dir):
                if os.path.isfile(file.path):
                    pos = file.path.rfind(".")
                    emulator_cfg_name = get_emulators_cfg_filename(file.path[:pos].strip().replace(system_dir + "/", ""))
                    system_roms.append(emulator_cfg_name)
        if item[len(parts[0]) + 1:] in system_roms:
            cleaned[item] = items[item]
        else:
            bad_entries += 1
            if check == False:
                log_this(log_file, f"Removed Entry: \"{item}\" (rom for \"{item[len(parts[0]) + 1:]}\" does not exist)")
            else:
                log_this(log_file, f"Invalid Entry: \"{item}\" (rom for \"{item[len(parts[0]) + 1:]}\" does not exist)")

    return cleaned, bad_entries


def filter_official_emulators_cfg(items: list):
    filtered = {}
    last_system = ""
    origins = []
    system_dir = ""
    origin = get_config_value("CONFIG_ITEMS", "origin_file")

    for item in sorted(items.keys()):
        parts = item.split("_")
        if parts[0] != last_system:
            last_system = parts[0]
            system_dir = os.path.join("/home/pi/RetroPie/roms", parts[0])
            if origin is not None:
                origins = get_official_emulators_origins(os.path.join(system_dir, origin))
        if item[len(parts[0]) + 1:].replace("./", "") not in origins:
            filtered[item] = items[item]

    return filtered


def merge_emulators_cfg(directory):
    emulators_cfg = os.path.join(str(directory), "opt/retropie/configs/all/emulators.cfg")
    override_cfg = "/home/pi/.update_tool/override_emulators.cfg"

    if not os.path.isfile(emulators_cfg):
        return
    
    items, duplicate_counter = get_emulators_cfg()
    items = filter_official_emulators_cfg(items)

    with open(emulators_cfg, 'r') as configfile:
        lines_in = configfile.readlines()
        for line in lines_in:
            parts = line.split("=")
            if len(parts) == 2:
                items[parts[0].strip()] = parts[1].strip()    

    # apply overrides
    if os.path.isfile(override_cfg):
        with open(override_cfg, 'r') as configfile:
            lines_in = configfile.readlines()
            for line in lines_in:
                parts = line.split("=")
                if len(parts) == 2:
                    items[parts[0].strip()] = parts[1].strip()    

    game_counter = write_sorted_emulators_cfg(items)
    
    os.remove(emulators_cfg)
    
    return


def datetime_valid(dt: str):
    try:
        datetime.datetime.fromisoformat(dt)
    except:
        return False
    return True


def get_package_date(file: str):
    with open(file, 'r') as configfile:
        lines_in = configfile.readlines()
        for line in lines_in:
            parts = line.split("=")
            if parts[0].strip() == "pkg_date":
                if datetime_valid(parts[1].replace("\"", "").replace("'", "").strip()):
                    return datetime.datetime.fromisoformat(parts[1].replace("\"", "").replace("'", "").strip())

    return datetime.datetime.fromisoformat("1900-01-01T00:00:00")


def get_retropie_cores():
    cores = []
    found = False
    val = subprocess.check_output(["/bin/bash", "-c", "sudo /home/pi/RetroPie-Setup/retropie_packages.sh | less"])
    lines = val.decode("utf-8").split(str("\n"))
    for line in lines:
        if not found:
            if line[0:10:] == "----------":
                found = True
        else:
            parts = line.split(":")
            if len(parts) == 3:
                cores.append(parts[0].strip())

    return cores


def install_emulators(directory):
    if len(list(Path(directory).rglob('retropie.pkg'))) == 0:
        return
    # get official cores
    cores = get_retropie_cores()
    # check if retropie.pkg files exist
    for package in Path(directory).rglob('retropie.pkg'):
        package_dir = os.path.dirname(package)
        if "/opt/retropie/libretrocores" in package_dir:
            if os.path.basename(package_dir) not in cores:
                # I took this out of check_root
                if not os.path.isdir(f"/opt/retropie/libretrocores/{os.path.basename(package_dir)}"):
                    os.system(f"sudo mkdir /opt/retropie/libretrocores/{os.path.basename(package_dir)} > /tmp/test")
                os.system(f"sudo chown -R pi:pi /opt/retropie/libretrocores/{os.path.basename(package_dir)} > /tmp/test")
                return
        os.system(f"sudo chown -R pi:pi {os.path.dirname(package)} > /tmp/test")
        local_package = str(package).replace(str(directory), "")
        if os.path.isfile(local_package):
            if get_package_date(str(package)) <= get_package_date(local_package):
                os.remove(str(package))
                continue

        # get the core
        dirs = str(package).split("/")
        core = dirs[len(dirs) - 2]
        print(f"Now installing {core} from bin...")
        runcmd(f"sudo /home/pi/RetroPie-Setup/retropie_packages.sh {core} depends")
        runcmd(f"sudo /home/pi/RetroPie-Setup/retropie_packages.sh {core} install_bin")
        os.remove(str(package))

    return


def merge_gamelist(directory: str, official: bool):
    # get origin file
    origin = get_config_value("CONFIG_ITEMS", "origin_file")
    print_status = True
    
    # check if gamelist.xml has been updated
    for gamelist in Path(directory).rglob('gamelist.xml'):
        # better statusing
        if print_status:
            print("Merging gamelists...")
            print_status = False
        clear_do_not_overwrite_tags(str(gamelist))
        # find corresponding xmls
        corr = gamelist.parts
        corr = corr[corr.index('extracted')+1:]
        corr = Path("/", *corr)
        if official and origin is not None:
            write_origins(str(gamelist), str(gamelist).replace("gamelist.xml", origin))
        if os.path.isfile(corr):
            if "/home/pi/RetroPie/roms/" in str(corr):
                merge_xml(str(gamelist), str(corr), "/opt/retropie/configs/all/emulationstation/collections/custom-zzz-recent.cfg")
            else:
                merge_xml(str(gamelist), str(corr))
            
            os.remove(str(gamelist))
        else:
            write_all_roms(str(gamelist), str(corr).replace("gamelist.xml", ""), "/opt/retropie/configs/all/emulationstation/collections/custom-zzz-recent.cfg")

    return

def indent(tree, space="  ", level=0):
    # Reduce the memory consumption by reusing indentation strings.
    indentations = ["\n" + level * space]

    def _indent_children(elem, level):
        # Start a new indentation level for the first child.
        child_level = level + 1
        try:
            child_indentation = indentations[child_level]
        except IndexError:
            child_indentation = indentations[level] + space
            indentations.append(child_indentation)

        if not elem.text or not elem.text.strip():
            elem.text = child_indentation

        for child in elem:
            if len(child):
                _indent_children(child, child_level)
            if not child.tail or not child.tail.strip():
                child.tail = child_indentation
            if child == elem[len(elem) - 1]:
                child.tail = indentations[level]

    _indent_children(tree, 0)
    

def merge_xml(src_xml: str, dest_xml: str, collection=None):
    file_time = datetime.datetime.utcnow().strftime("%Y%m%d-%H%M%S")

    do_not_overwrite = ["favorite", "lastplayed", "playcount"]
    src_tree = ET.parse(src_xml)
    src_root = src_tree.getroot()
    dest_tree = ET.parse(dest_xml)
    dest_root = dest_tree.getroot()

    for src_game in src_root:
        if src_game.tag != "game":
            continue

        src_path = src_game.find("path")
        if src_path is not None:
            if src_path.text is None:
                continue
            
            parents = dest_tree.findall(f".//game[path=\"{src_path.text}\"]")
            if len(parents) == 0:
                # add the new game to the recently added collection if it is passed
                if collection is not None:
                    with open(collection, 'a', encoding='utf-8') as additions:
                        additions.write(str(dest_xml).replace("gamelist.xml", str(src_path.text).replace("./", "")) + "\n")
                    
                dest_root.append(ET.fromstring("<game></game>"))
                parent = dest_root[len(dest_root) -1]
                for src_node in src_game:
                    if src_node.tag not in do_not_overwrite:
                        child = ET.SubElement(parent, src_node.tag)
                        child.text = src_node.text
            else:
                for parent in parents:
                    for src_node in src_game:
                        if src_node.tag not in do_not_overwrite:
                            dest_node = parent.find(src_node.tag)
                            if dest_node is None:
                                child = ET.SubElement(parent, src_node.tag)
                                child.text = src_node.text
                            else:
                                dest_node.text = src_node.text

    safe_write_backup(src_xml, file_time)
    dest_tree = ET.ElementTree(dest_root)
    
    # ET.indent(dest_tree, space="\t", level=0)
    indent(dest_root, space="\t", level=0)
    with open(dest_xml, "wb") as fh:
        dest_tree.write(fh, "utf-8")

    safe_write_check(src_xml, file_time)

    return


def make_deletions(directory):
    directory = directory / "read me do this first!.txt"
    if os.path.isfile(directory):
        f = open(directory, 'r' )
        for lines in f:
            if os.path.islink(lines.rstrip()):
                os.unlink(lines.rstrip())
            elif os.path.isfile(lines.rstrip()):
                os.remove(lines.rstrip())
            elif os.path.isdir(lines.rstrip()):
                shutil.rmtree(lines.rstrip())
        f.close()
        os.remove(directory)

def prepare_script(directory, script_name):
    actual_script = ""
    directory = directory / script_name
    if os.path.isfile(directory):
        actual_script = f"/tmp/{script_name}"
        shutil.move(directory, actual_script)

    return actual_script

def execute_script(script_name, update_name):
    if os.path.isfile(script_name):
        os.system(f"dos2unix 'f{script_name}' > /tmp/test")
        print("Executing ...", script_name)
        result = subprocess.run(["/bin/bash",script_name], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        err_text = result.stderr.decode('utf-8')
        if err_text != "":
            log_this("/home/pi/.update_tool/exception.log", f"*****\nDate: {datetime.datetime.utcnow()}\nstderr from {script_name} of {update_name}\n\n{err_text}\n\n")
            cls()
            code = d.msgbox(f"\n{err_text}\nLogged to /home/pi/.update_tool/exception.log\n", title = f"Error(s) reported from '{os.path.basename(script_name)}' of '{os.path.basename(update_name)}'", extra_button=True, extra_label="Abort and Exit")
            cls()

            if code == d.EXTRA:
                exit(0)
        
def check_internet():
    url = "http://www.google.com/"
    try:
        resp = requests.get(url)
    except requests.exceptions.RequestException as e:
        return False

    return True

def update_available():
    url = "https://api.github.com/repos/h3xp/RickDangerousUpdate/releases/latest"
    try:
        resp = requests.get(url)
        latest_tag = resp.json().get('tag_name').replace("v","")
    except requests.exceptions.RequestException as e:
        return "no connection"
    if os.path.isfile(tool_ini):
        config = configparser.ConfigParser()
        config.read(tool_ini)
        git_branch = config["CONFIG_ITEMS"]["git_branch"]
        if git_branch == "main":
            current_tag = config["CONFIG_ITEMS"]["tool_ver"].replace("v","")
            if version.parse(latest_tag) > version.parse(current_tag):
                return "update available"
            else:
                return "no update available"
        else:
            return "alt branch"
            
    return False

def check_update():
    title = ""

    if os.path.isfile(tool_ini):
        config = configparser.ConfigParser()
        config.read(tool_ini)
        title = "Version " + config["CONFIG_ITEMS"]["tool_ver"] + " (latest)"
    else:
        title = "not installed"
    if update_available_result == "update available":
        title = "UPDATE AVAILABLE! Please update!"
    if update_available_result == "no connection":
        title = "no internet connection"
    if update_available_result == "alt branch":
        title = "Version " + config["CONFIG_ITEMS"]["tool_ver"] + " (pointing to " + config["CONFIG_ITEMS"]["git_branch"] + ")"

    return title


def handheld_dialog():
    code, tag = d.menu("Handheld mode",
                       choices=[("1", "Enable handheld mode"),
                                ("2", "Disable handheld mode")],
                       cancel_label=" Cancel ")

    if code == d.OK:
        if tag == "1":
            handheld_confirm_dialog("enable")
        elif tag == "2":
            handheld_confirm_dialog("disable")

    if code == d.CANCEL:
        cls()
        main_dialog()

    return


def handheld_confirm_dialog(mode):
    code = d.yesno(text="Are you sure you want to " + mode + "handheld mode?\nThis will make changes to the "
                                                             "retroarch.cfgs of these systems:\n- atarylynx\n- "
                                                             "gamegear\n- gb\n- gba\n- gbc\n- ngpc\n- "
                                                             "wonderswancolor\n")

    if code == d.OK:
        do_handheld(mode)

    if code == d.CANCEL:
        main_dialog()

    return


def do_handheld(mode):
    if mode == "enable":
        configzip = "handheld_configs.zip"
    else:
        configzip = "handheld_configs_reset.zip"
    localpath = Path("/", "tmp")
    urllib.request.urlretrieve("https://raw.githubusercontent.com/h3xp/RickDangerousUpdate/main/configs/" + configzip,
                               localpath / configzip)
    f = os.path.join(localpath, configzip)
    if os.path.isfile(f):
        with zipfile.ZipFile(f, 'r') as zip_ref:
            zip_ref.extractall(localpath / "handheld_configs")
        copydir(localpath / "handheld_configs/", "/opt/retropie/configs/")
        try:
            shutil.rmtree(localpath / "handheld_configs")
        except OSError as e:
            print("Error: %s : %s" % (localpath / "handheld_configs", e.strerror))
        os.remove(localpath / configzip)
    cls()


def log_this(log_file: str, log_text: str, overwrite=False):
    if log_file is None:
        return

    if not os.path.isdir(os.path.dirname(log_file)):
        os.makedirs(os.path.dirname(log_file))

    if overwrite == True or not os.path.isfile(log_file):
        with open(log_file, 'w', encoding='utf-8') as logfile:
            logfile.write(log_text.strip() + "\n")
    else:
        with open(log_file, 'a', encoding='utf-8') as logfile:
            logfile.write(log_text.strip() + "\n")

    return


def get_system_extentions(system: str):
    systems_config = "/opt/retropie/configs/all/emulationstation/es_systems.cfg"

    extensions = []
    src_tree = ET.parse(systems_config)
    src_root = src_tree.getroot()

    parents = src_tree.findall(f".//system[name=\"{system}\"]")
    for parent in parents:
        src_node = parent.find("extension")
        if src_node is not None:
            tmp_extensions = src_node.text.split(" ")
            for extension in tmp_extensions:
                if extension not in extensions:
                    extensions.append(extension)

    return extensions


def get_all_systems_from_cfg():
    do_not_scan = ["kodi"]
    systems_config = "/opt/retropie/configs/all/emulationstation/es_systems.cfg"
    rom_dir = "/home/pi/RetroPie/roms"
    systems = []

    src_tree = ET.parse(systems_config)
    src_root = src_tree.getroot()

    for src_system in src_root.iter("system"):
        src_node = src_system.find("name")
        if src_node is not None:
            if src_node.text is not None:
                if src_node.text in do_not_scan:
                    continue
                system_path = os.path.join(rom_dir, src_node.text)
                gamelist_path = os.path.join(system_path, "gamelist.xml")
                if os.path.isfile(gamelist_path):
                    if os.path.getsize(gamelist_path) > 0:
                        if src_node.text not in systems:
                            systems.append(src_node.text)

    systems.sort()
    return systems

def get_all_systems_from_dirs():
    do_not_scan = ["kodi"]
    rom_dir = "/home/pi/RetroPie/roms"
    systems = []
    link = {}

    for item in os.scandir(rom_dir):
        if item.name in do_not_scan:
            continue

        if os.path.isdir(item.path):
            system_path = os.path.join(rom_dir, item.name)
            gamelist_path = os.path.join(system_path, "gamelist.xml")
            if os.path.isfile(gamelist_path):
                if os.path.getsize(gamelist_path) > 0:
                    if os.path.islink(item.path):
                        system = os.path.realpath(gamelist_path).replace("gamelist.xml", "")
                        system = system.replace(rom_dir, "")
                        system = system.replace("/", "")
                        links = []
                        if system in link:
                            links = link[system]
                        if system not in links:
                            links.append(system)
                        if item.name not in links:
                            links.append(item.name)
                        link[system] = links
                        if system in systems:
                            index = systems.index(system)
                            del systems[index]
                    else:
                        if item.name not in link:
                            systems.append(item.name)
    
    for key, val in link.items():
        val.sort()
        system = ""
        for item in val:
            if len(system) > 0:
                system += "/"
            system += item
        systems.append(system)

    systems.sort()
    return systems


def look_for_supporting_files(rom_file: str, dir: str, file_types: str):
    for file_type in file_types:
        file_name = os.path.splitext(rom_file)[0] + file_type
        if os.path.exists(os.path.join(dir, file_name)):
            #return file_name
            return os.path.join(dir, file_name)

    return ""


def parse_cue_file(cue_file: str):
    cue_files = []

    base_path = os.path.dirname(cue_file)
    with open(cue_file, 'r') as cuefile:
        for line in cuefile:
            if len(line.strip()) == 0:
                continue            
            match = re.match('^FILE .(.*). (.*)$', line)
            if match:
                cue_base = match.group(1)
                if cue_base is not None:
                    cue_files.append(os.path.join(base_path, cue_base))

    return cue_files

    
def process_cue_file(cue_file: str, src_game: ET.Element, src_tree: ET.ElementTree, system_rom_directory: str, cue_files: list, log_file: str, m3u_file=""):
    bad_files = []
    good_files = []

    cue_entries = parse_cue_file(cue_file)
    for cue_path in cue_entries:
        cue_base = os.path.basename(cue_path)
        if not os.path.exists(cue_path):
            bad_files.append(cue_base)
        else:
            good_files.append(cue_base)

    if len(bad_files) > 0:
        bad_files.sort()
        for file in bad_files:
            if len(m3u_file) > 0:
                log_this(log_file, f"-cue entry \"{file}\" not found for cue file \"{os.path.basename(cue_file)}\" from within m3u file \"{m3u_file}\"")
            else:
                log_this(log_file, f"-cue entry \"{file}\" not found for cue file \"{os.path.basename(cue_file)}\"")

        return False
    else:
        for file in good_files:
            if file in cue_files:
                index = cue_files.index(os.path.basename(file))
                del cue_files[index]    

    return True


def get_recursive_m3u_files(m3u_file: str, system_rom_directory: str):
    # this function get's all files, including .cue files contents, of an .m3u file
    files = []
    files = parse_m3u_file(m3u_file, system_rom_directory)

    for file in files:
        if os.path.splitext(file)[1] == ".cue":
            cue_files = parse_cue_file(file)
            if len(cue_files) > 0:
                files.extend(cue_files)

    return files


def parse_m3u_file(m3u_file: str, system_rom_directory: str):
    files = []
    with open(m3u_file, 'r') as m3ufile:
        for line in m3ufile:
            if len(line.strip()) == 0:
                continue
            if line.strip()[0:1] == "#":
                continue
            files.append(os.path.join(system_rom_directory, line.strip()))

    return files


def process_m3u_file(m3u_file: str, src_game: ET.Element, src_tree: ET.ElementTree, system_rom_directory: str, m3u_files: list, log_file: str):
    bad_files = []
    good_files = []

    m3u_entries = parse_m3u_file(m3u_file, system_rom_directory)
    for m3u_entry in m3u_entries:
        m3u_disk = os.path.join(system_rom_directory, m3u_entry.strip())
        m3u_base = os.path.basename(m3u_disk)        
        if not os.path.exists(m3u_disk):
            bad_files.append(m3u_base)
        else:
            keep_rom = True
            if os.path.splitext(m3u_disk)[1] == ".cue":
                keep_rom = process_cue_file(m3u_disk, src_game, src_tree, system_rom_directory, m3u_files, log_file, m3u_base)
            if keep_rom == True:
                good_files.append(m3u_base)
            else:
                bad_files.append(m3u_base)

    if len(bad_files) > 0:
        bad_files.sort()
        for file in bad_files:
            log_this(log_file, f"-m3u entry \"{file}\" not found for m3u file \"{os.path.basename(m3u_file)}\"")
    else:
        for file in good_files:
            if file in m3u_files:
                index = m3u_files.index(os.path.basename(file))
                del m3u_files[index]

    return bad_files


def process_supporting_files(src_game: ET.Element, src_name: str, subelement_name: str, system_roms: str, rom_file: str, supporting_files_dir_name: str, supporting_files_dir: str, supporting_files_types: list, supporting_files: list, found_files: list, log_file: str, clean=False):
    def _new_element(src_game: ET.Element, subelement_name: str, log_file: str):
        indent(src_game, "\t")
        log_this(log_file, f"-{subelement_name} element will now be:")
        log_this(log_file, ET.tostring(src_game).decode())

    file = ""
    # check if subelement exists
    src_node = src_game.find(subelement_name)
    if src_node is not None:
        if src_node.text is not None:
            # validate file exists
            #relative_file = src_node.text.replace("./", "")
            #file = relative_file.replace(f"{supporting_files_dir_name}/", "")
            file = os.path.basename(src_node.text)
            #path = os.path.join(supporting_files_dir, file)
            path = src_node.text.replace("./", system_roms + "/")
            if src_node.text[0:1] == "/":
                path = src_node.text

            if not os.path.isfile(path):
                log_this(log_file, f"-{subelement_name} file \"{file}\" (full path \"{path}\") does not exist for rom \"{rom_file}\" ({src_name})")
                # remove bad reference
                if clean == True:
                    src_node.text = None
                else:
                    log_this(log_file, f"-clean would remove reference to {subelement_name} file")
                # look for file based on rom name
                file = look_for_supporting_files(rom_file, supporting_files_dir, supporting_files_types)
                if len(file) > 0:
                    log_this(log_file, f"-{subelement_name} file found: \"{file}\" for rom \"{rom_file}\"")
                    if clean == True:
                        #src_node.text = file
                        src_node.text = file.replace(system_roms, ".")
                        _new_element(src_node, subelement_name, log_file)
                    else:
                        log_this(log_file, f"-clean would add new reference to {subelement_name} tag")
        else:
            # look for file based on rom name
            log_this(log_file, f"-no {subelement_name} defined for rom \"{rom_file}\" ({src_name})")
            file = look_for_supporting_files(rom_file, supporting_files_dir, supporting_files_types)
            if len(file) > 0:
                log_this(log_file, f"-{subelement_name} file found: \"{file}\" for rom \"{rom_file}\"")
                if clean == True:
                    #src_node.text = file
                    src_node.text = file.replace(system_roms, ".")
                    _new_element(src_node, subelement_name, log_file)
                else:
                    log_this(log_file, f"-clean would add new reference to {subelement_name} tag")
    else:
        # look for file based on rom name and add to element tree if it exists
        log_this(log_file, f"-no {subelement_name} element defined in gamelist.xml for rom \"{rom_file}\"")
        file = look_for_supporting_files(rom_file, supporting_files_dir, supporting_files_types)
        if len(file) > 0:
            log_this(log_file, f"-{subelement_name} file found: \"{file}\" for rom \"{rom_file}\"")
            if clean == True:
                child = ET.SubElement(src_game, subelement_name)
                #child.text = f"./{supporting_files_dir}/{file}"
                child.text = file.replace(system_roms, ".")
                _new_element(child, subelement_name, log_file)
            else:
                log_this(log_file, f"-clean would add new reference to {subelement_name} tag")

    # delete validated files
    file = os.path.basename(file)
    if len(file) > 0:
        if file not in found_files:
            found_files.append(file)
        if file in supporting_files:
            index = supporting_files.index(file)
            del supporting_files[index]

    return


def get_parent_dir(filename: str):
    parent_dir = ""

    parts = filename.split("/")
    while "" in parts:
        index = parts.index("")
        del parts[index]

    if len(parts) == 1:
        return "/"
    
    for i in range(len(parts) - 1):
        parent_dir += "/" + parts[i]
    
    return parent_dir


def process_orphaned_extra_files(system: str, orphaned_files: list, backup_dir: str, log_file: str, clean=False):
    # this exists because extra files were an afterthough, and are fully pathed
    # this should probably be what the entire check/clean should be like, but for now we just leave it as is
    orphaned_directories = []
    do_not_move = ["/home/pi/RetroPie/roms/scummvm/.bugged", "/home/pi/RetroPie/roms/scummvm/.Other_Langs"]

    orphaned_files.sort()
    process = "DELETING" if clean == True else "IDENTIFIED"

    # this is a HACK, because atari800 multidisk sucks
    # we ned to brute force he remainder of .multidisk files to find ophans..
    if system == "atari800":
        multidisk_files = []
        for file in orphaned_files:
            if "/home/pi/RetroPie/roms/atari800/.multidisk/" in file:
                multidisk_files.append(file)
        for file in multidisk_files:
            # first parse the files were looking for
            parsed_files = []
            if os.path.isfile(file):
                with open(file, 'r') as md_file:
                    for line in md_file:
                        if line.strip()[:1] == "#":
                            continue
                        if not "/home/pi/RetroPie/roms/atari800" in line:
                            continue
                        parsed_files.append(line.strip())      
            count = 0
            file_name = os.path.basename(file)
            file_match = ""
            while count < len(file_name):
                if not file_name[count].isalnum():
                    break
                file_match += file_name[count]
                count += 1
            for rom_file in Path("/home/pi/RetroPie/roms/atari800").glob(file_match + "*"):
                process_file = True
                if os.path.splitext(rom_file)[1] == ".zip":
                    with zipfile.ZipFile(rom_file, 'r') as zip_ref:
                        for file_listing in zip_ref.infolist():
                            file_found = False
                            for parsed_file in parsed_files:
                                if file_listing.filename in parsed_file:
                                    file_found = True
                                    break
                            process_file &= file_found
                            if process_file:
                                break
                if process_file:
                    log_this(log_file, f"-\"{file}\" please consider renaming this or change the gamelist \"name\" entry to match the filename...")
                    if file in orphaned_files:
                        index = orphaned_files.index(file)
                        del orphaned_files[index]
                    for parsed_file in parsed_files:
                        if parsed_file in orphaned_files:
                            index = orphaned_files.index(parsed_file)
                            del orphaned_files[index]

    # now back to the story...
    for orphaned_file in orphaned_files:
        if os.path.isdir(orphaned_file):
            orphaned_directories.append(orphaned_file)
            continue
        if not os.path.isfile(orphaned_file):
            continue
        backup_file = orphaned_file.replace("/home/pi/RetroPie/roms", backup_dir)
        log_this(log_file, f"-{process} orphaned extra file: \"{orphaned_file}\"")
        if clean == True:
            #os.remove(file_path)
            if not os.path.exists(os.path.dirname(backup_file)):
                os.makedirs(os.path.dirname(backup_file))
            shutil.move(orphaned_file, os.path.dirname(backup_file))

    for orphaned_directory in orphaned_directories:
        if orphaned_directory in do_not_move:
            continue
        backup_directory = orphaned_directory.replace("/home/pi/RetroPie/roms", backup_dir)
        if system == "atari800":
            if not os.listdir(orphaned_directory):
                log_this(log_file, f"-{process} orphaned extra directory because it is empty: \"{orphaned_directory}\"")
                if clean == True:
                    shutil.rmtree(orphaned_directory)
        else:
            log_this(log_file, f"-{process} orphaned extra directory: \"{orphaned_directory}\"")
            if clean == True:
                if not os.path.isdir(get_parent_dir(backup_directory)):
                    os.makedirs(get_parent_dir(backup_directory))
                if os.path.isdir(backup_directory):
                    shutil.rmtree(backup_directory)
                shutil.copytree(orphaned_directory, backup_directory)
                shutil.rmtree(orphaned_directory)

    return


def process_orphaned_files(orphaned_files: list, dir: str, log_file: str, dir_backup: str, file_type: str, clean=False):
    orphaned_files.sort()
    process = "DELETING" if clean == True else "IDENTIFIED"
    for orphaned_file in orphaned_files:
        file_path = os.path.join(dir, orphaned_file)
        if os.path.exists(file_path):
            log_this(log_file, f"-{process} orphaned {file_type} file: \"{file_path}\"")
            if clean == True:
                #os.remove(file_path)
                if not os.path.exists(dir_backup):
                    os.makedirs(dir_backup)
                shutil.move(file_path, dir_backup)

    return


def delete_gamelist_entry_dialog(rom: str):
    code = d.yesno(f"Gamelist entry for \"{rom}\" has invalid rom entries (rom files or multi disk files defined in .m3u or .cue file can not be found).\nWould you like to remove it from your gamelist.xml?")

    if code == d.OK:
        return True

    return False


def remove_validated_file(file_name: str, files_list: list):
    if file_name in files_list:
        index = files_list.index(os.path.basename(file_name))
        del files_list[index]

    return


def override_bad_rom(src_game: ET.Element, src_tree: ET.ElementTree, system_rom_directory: str, art_files: list, snap_files: list, rom_files: list, m3u_files: list):
    cue_files = []
    src_path = src_game.find("path")
    if src_path is not None:
        src_path = os.path.basename(src_path)
        remove_validated_file(src_path, rom_files)

        if os.path.splitext(src_path)[1] == ".cue":
            remove_validated_file(src_path, rom_files)
            files = parse_cue_file(src_path, system_rom_directory)
            for file in files:
                remove_validated_file(file, rom_files)
        if os.path.splitext(src_path)[1] == ".m3u":
            files = parse_m3u_file(src_path, system_rom_directory)
            for file in files:
                remove_validated_file(file, m3u_files)
                if os.path.splitext(file)[1] == ".cue":
                    cue_files = parse_cue_file(file)
                    if cue_files is not None:
                        if len(cue_files) > 0:
                            files.extend(cue_files)

        parents = src_tree.findall(f".//game[path=\"./{os.path.basename(src_path)}\"]")
        for parent in parents:
            file = parent.find("video")
            if file is not None:
                remove_validated_file(file, snap_files)
            
            file = parent.find("image")
            if file is not None:
                remove_validated_file(file, art_files)

    return


def remove_duplicate_gamelist_entries(src_xml: str, log_file: str):
    # i assume the 1st entry in gamelist .xml is the good one, because it should be Rick's original
    roms = []
    src_tree = ET.parse(src_xml)
    src_root = src_tree.getroot()

    for src_game in src_root.iter("game"):
        path = src_game.find("path")
        if path is not None:
            if path.text is not None:
                if path.text not in roms:
                    roms.append(path.text)

    for rom in roms:
        parents = src_tree.findall(f".//game[path=\"{rom}\"]")
        if parents is not None:
            done = False
            for parent in parents:
                if done == True:
                    indent(parent)
                    log_this(log_file, f"-removing duplicate gamelist.xml entry for {os.path.basename(rom)}")
                    log_this(log_file, ET.tostring(parent).decode())
                    src_root.remove(parent)
                done = True

    # write file
    file_time = safe_write_backup(src_xml)
    
    indent(src_root, space="\t", level=0)
    with open(src_xml, "wb") as fh:
        src_tree.write(fh, "utf-8")

    if safe_write_check(src_xml, file_time) == False:
        log_this(log_file, f"-writing to {src_xml} FAILED")

    return


def kill_origins(src_xml: str, log_file: str):
    # origin tags sucked, they did not work.
    # this cleans that mess.
    src_tree = ET.parse(src_xml)
    src_root = src_tree.getroot()

    parents = src_tree.findall(".//game[origin]")
    for parent in parents:
        origin = parent.find("origin")
        if origin is not None:
            parent.remove(origin)

    # write file
    file_time = safe_write_backup(src_xml)
    
    indent(src_root, space="\t", level=0)
    with open(src_xml, "wb") as fh:
        src_tree.write(fh, "utf-8")

    if safe_write_check(src_xml, file_time) == False:
        log_this(log_file, f"-writing to {src_xml} FAILED")

    return


def get_extra_files(system: str, system_roms: str):
    # these are sort of hacks I think that are pretty specific to Rick's build, unsure really...
    extra_files = []
    keep_rom_dirs = ["boxart", "snaps"]
    if system == "atari800":
            # atar800 has a fle in .multidisk, with a matching directory in .data
            # I could parse the file in .multidisk, but I think this is good enough?
            for item in os.scandir(system_roms + "/.multidisk"):
                if not os.path.isfile(item.path):
                    continue
                extra_files.append(item.path)
            for item in os.scandir(system_roms + "/.data"):
                if not os.path.isdir(item.path):
                    continue
                extra_files.append(item.path)
                for file in os.scandir(item.path):
                    if os.path.isfile(file.path):
                        extra_files.append(file.path)
    if system == "scummvm":
        for item in os.scandir(system_roms):
            if os.path.isdir(item.path):
                if item.name not in keep_rom_dirs:
                    extra_files.append(item.path)
    if system == "snesmsu1":
        # this has a om irectory that is in each .sh file
        # I am just getting all dirs hre, minus boxart/snaps
        for item in os.scandir(system_roms):
            if os.path.isdir(item.path):
                if item.name not in keep_rom_dirs:
                    extra_files.append(item.path)

    return extra_files


def process_extra_files(system:str, system_roms: str, rom_path: str, rom_name: str, extra_files: list):
    if system == "atari800":
        # i am looking for an entry in .multidisk folder, with a matching directory in .data folder
        # i will only keep entry in .data folder if file is found in .multidisk folder
        multidisk_file = os.path.join(system_roms, ".multidisk", rom_name)
        if os.path.isfile(multidisk_file):
            with open(multidisk_file, 'r') as file:
                for line in file:
                    if line.strip()[:1] == "#":
                        continue
                    if not system_roms in line:
                        continue
                    if os.path.isfile(line.strip()):
                        if line.strip() in extra_files:
                            index = extra_files.index(line.strip())
                            del extra_files[index]
            if multidisk_file in extra_files:
                index = extra_files.index(multidisk_file)
                del extra_files[index]
                multidisk_folder = os.path.join(system_roms, ".data", rom_name)
    if system == "scummvm":
        # directoy is stored in "/opt/retropie/configs/scummvm/scummvm.ini"
        rom_path_name = os.path.splitext(os.path.basename(rom_path))[0]
        files_dir = get_ini_value("/opt/retropie/configs/scummvm/scummvm.ini", rom_path_name, "path")
        if files_dir is not None:
            index = extra_files.index(files_dir)
            del extra_files[index]
    if system == "snesmsu1":
        if os.path.isfile(rom_path):
            # directory is parsed out of .sh file
            with open(rom_path, 'r') as file:
                for line in file:
                    if line.strip()[:1] == "#":
                        continue
                    if not "/home/pi/RetroPie/roms/snesmsu1/" in line:
                        continue
                    index = line.find("/home/pi/RetroPie/roms/snesmsu1/")
                    if index < 0:
                        continue
                    file_name = line[index:].strip()
                    if file_name[-1] == '"' or file_name[-1] == "'":
                        file_name = file_name[0:len(file_name) -1]
                    parts = file_name.split("/")
                    files_dir = ""
                    for part in parts:
                        if len(part.strip()) == 0:
                            continue
                        if os.path.isdir(files_dir + "/" + part):
                            files_dir += "/" + part
                        else:
                            break
                    if files_dir in extra_files:
                        index = extra_files.index(files_dir)
                        del extra_files[index]                

    return


def process_gamelist(system: str, gamelist_roms_dir: str, log_file: str, backup_dir: str, del_roms=False, del_art=False, del_snaps=False, del_m3u=False, del_extra=False, clean=False, auto_clean=False):
    file_time = datetime.datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    rom_dir = "/home/pi/RetroPie/roms"
    art_dir = "boxart"
    snaps_dir = "snaps"
    m3u_dir = ".data"
    art_types = [".png", ".jpg"]
    snaps_types = [".mp4"]
    do_not_delete = ["neogeo.zip"]
    no_m3u_spport = ["atari800"]
    bad_m3us = {}

    if clean == True and not gamelist_roms_dir == rom_dir:
        d.msgbox("We do not clean from alternate gamelist.xml files")
        cls()
        gamelist_utilities_dialog()

    system_gamelists = os.path.join(gamelist_roms_dir, system)
    system_roms = os.path.join(rom_dir, system)
    system_art = os.path.join(system_roms, art_dir)
    system_snaps = os.path.join(system_roms, snaps_dir)
    system_m3u = os.path.join(system_roms, m3u_dir)

    # NEW backups
    backup_roms = os.path.join(backup_dir, system)
    backup_art = os.path.join(backup_roms, art_dir)
    backup_snaps = os.path.join(backup_roms, snaps_dir)
    backup_m3u = os.path.join(backup_roms, m3u_dir)


    # we are going to DELETE files still in these lists after the reconciliation
    art_files = []
    snaps_files = []
    rom_files = []
    m3u_files = []
    extra_fles = []
    bad_roms = []
    remove_entries = []

    # if len(extensions) == 0 then directory is not in es_systems.cfg
    # when there is a link to a directory which name is in the es_systems.cfg?
    # this now no longer cares...
    extensions = get_system_extentions(system)
    if len(extensions) == 0:
        return

    process = "cleaning" if clean == True else "checking"
    log_this(log_file, f"now {process}: {system} for rom extensions {extensions}")
    print(f"now {process}: {system} for rom extensions {extensions}")
    
    # get rom files
    for item in os.scandir(system_roms):
        if os.path.isfile(item.path):
            if item.name in do_not_delete:
                continue
            if Path(item.path).suffix in extensions:
                rom_files.append(item.name)
            
    # get boxart files
    for item in os.scandir(system_art):
        if os.path.isfile(item.path):
            art_files.append(item.name)

    # get movie files
    for item in os.scandir(system_snaps):
        if os.path.isfile(item.path):
            snaps_files.append(item.name)

    # get m3u files
    if os.path.exists(system_m3u):
        if os.path.isdir(system_m3u):
            for item in os.scandir(system_m3u):
                if os.path.isfile(item.path):
                    m3u_files.append(item.name)

    # get exta files
    extra_files = get_extra_files(system, system_roms)

    src_xml = os.path.join(system_gamelists, "gamelist.xml")
    if not os.path.exists(src_xml):
        log_this(log_file, "ERROR: gamelist.xml does not exist!")

    if clean == True:
        if not os.path.exists(backup_roms):
            os.mkdir(backup_roms)
    
        # copy gamelist.xml
        shutil.copy2(os.path.join(system_roms, "gamelist.xml"), os.path.join(backup_dir, system))

    # remove duplicate gamelist entries
    # this will always happen now because I do not want to deal with multiple entries
    #if clean == True:
    #    remove_duplicate_gamelist_entries(src_xml, log_file)
    remove_duplicate_gamelist_entries(src_xml, log_file)
    kill_origins(src_xml, log_file)
    # start scanning gamelist.xml
    src_tree = ET.parse(src_xml)
    src_root = src_tree.getroot()

    for src_game in src_root.iter("game"):
        src_name = ""
        rom_file = ""
        src_name_node = src_game.find("name")
        if src_name_node is not None:        
            if src_name_node.text is not None:
                src_name = src_name_node.text
                print(src_name)
            else:
                continue

        # get rom file
        src_node = src_game.find("path")
        if src_node is not None:
            if src_node.text is not None:
                found_files = []
                rom_file = os.path.basename(src_node.text)
                #rom_path = os.path.join(system_roms, rom_file)
                rom_path = src_node.text.replace("./", system_roms + "/")
                
                if src_node.text[0:1] == "/":
                    rom_path = src_node.text
                
                if os.path.exists(rom_path):
                    found_files.append(rom_file)
                    if rom_file in rom_files:
                        keep_rom = True
                        if os.path.splitext(rom_file)[1] == ".m3u":
                            bad_files = process_m3u_file(rom_path, src_game, src_tree, system_roms, m3u_files, log_file)
                            if len(bad_files) > 0:
                                keep_rom = False
                                bad_m3us[rom_file] = bad_files
                        if os.path.splitext(rom_file)[1] == ".cue":
                            keep_rom &= process_cue_file(rom_path, src_game, src_tree, system_roms, rom_files, log_file)
                        if keep_rom == True:
                            if rom_file in rom_files:
                                index = rom_files.index(rom_file)
                                del rom_files[index]
                        else:
                            bad_roms.append(rom_file)
                else:
                    log_this(log_file, f"-rom \"{rom_file}\" (full path \"{rom_path}\") does not exist")
                    if rom_file not in bad_roms:
                        bad_roms.append(rom_file)
                    #continue

                # check if art exists
                process_supporting_files(src_game, src_name, "image", system_roms, rom_file, art_dir, system_art, art_types, art_files, found_files, log_file, clean=clean)

                # check if snap exists
                process_supporting_files(src_game, src_name, "video", system_roms, rom_file, snaps_dir, system_snaps, snaps_types, snaps_files, found_files, log_file, clean=clean)

                # deal with extra files
                process_extra_files(system, system_roms, rom_path, src_name, extra_files)

            # check for auto gamelist removal
            if len(found_files) == 0:
                if rom_file not in remove_entries:
                    remove_entries.append(rom_file)

    # remove entry that shouldn't be there
    for entry in remove_entries:
        parents = src_tree.findall(f".//game[path=\"./{entry}\"]")
        for parent in parents:
            if entry in bad_roms:
                index = bad_roms.index(entry)
                del bad_roms[index]   
            indent(parent, "\t")
            if clean == True:
                log_this(log_file, f"-auto removing gamelist.xml entry for {entry} because it has 0 rom, image, or video files")
            else:
                log_this(log_file, f"-clean would auto remove gamelist.xml entry for {entry} because it has 0 rom, image, or video files")
            log_this(log_file, ET.tostring(parent).decode())
            if clean == True:
                src_root.remove(parent)

    # clean out bad roms from gamelist
    for rom_file in bad_roms:
        parents = src_tree.findall(f".//game[path=\"./{rom_file}\"]")
        for parent in parents:
            if clean == True:
                if auto_clean == True or delete_gamelist_entry_dialog(rom_file) == True:
                    log_this(log_file, f"-removing gamelist.xml entry for {rom_file}")
                    log_this(log_file, ET.tostring(parent).decode())
                    src_root.remove(parent)
                else:
                    log_this(log_file, f"-overridden: removing gamelist.xml entry for {rom_file}")
                    log_this(log_file, ET.tostring(parent).decode())
                    #remove good files in bad m3u file from orphans
                    if rom_file in bad_m3us:
                        bad_files = bad_m3us[rom_file]
                        for bad_file in bad_files:
                            if bad_file in m3u_files:
                                index = m3u_files.index(os.path.basename(bad_file))
                                del m3u_files[index]
            else:
                indent(parent, "\t")
                log_this(log_file, f"-clean would potentially (unless overridden) remove gamelist.xml entry for {rom_file}")
                log_this(log_file, ET.tostring(parent).decode())
                
    if clean == True:
        safe_write_backup(src_xml, file_time)
        
        indent(src_root, space="\t", level=0)
        with open(src_xml, "wb") as fh:
            src_tree.write(fh, "utf-8")

        if safe_write_check(src_xml, file_time) == False:
            log_this(log_file, f"-writing to {src_xml} FAILED")

    # clean orphans
    process = "DELETING" if clean == True else "INDENTIFYING"
    # clean roms
    if del_roms == True:
        process_orphaned_files(rom_files, system_roms, log_file, backup_roms, "rom", clean=clean)

    # clean art
    if del_art == True:
        process_orphaned_files(art_files, system_art, log_file, backup_art, "image", clean=clean)

    # clean snaps
    if del_snaps == True:
        process_orphaned_files(snaps_files, system_snaps, log_file, backup_snaps, "video", clean=clean)

    # clean m3u
    if del_m3u == True:
        if system not in no_m3u_spport:
            process_orphaned_files(m3u_files, system_m3u, log_file, backup_m3u, "m3u disk", clean=clean)

    if del_extra == True:
        process_orphaned_extra_files(system, extra_files, backup_dir, log_file, clean=clean)
    
    return


def do_process_gamelists(systems: list, del_roms=False, del_art=False, del_snaps=False, del_m3u=False, del_extra=False, clean=False, log_file="", auto_clean=False):
    cls()
    file_time = datetime.datetime.utcnow()
    process_type = "clean" if clean == True else "check"
    gamelist_roms_dir = "/home/pi/RetroPie/roms"
    check_gamelist_roms_dir = get_config_value("CONFIG_ITEMS", "check_gamelists_roms_dir")
    if check_gamelist_roms_dir is not None:
        gamelist_roms_dir = check_gamelist_roms_dir

    if not os.path.exists("/home/pi/.update_tool/gamelist_logs"):
        os.mkdir("/home/pi/.update_tool/gamelist_logs")

    if log_file == "":
        log_file = f"/home/pi/.update_tool/gamelist_logs/{process_type}_gamelists-{file_time.strftime('%Y%m%d-%H%M%S')}.log"
    backup_dir = f"/home/pi/.update_tool/gamelist_logs/{os.path.splitext(os.path.basename(log_file))[0]}"
    if clean == True:
        if not os.path.exists(backup_dir):
            os.mkdir(backup_dir)

    log_this(log_file, f"{process_type.upper()}ING GAMELISTS: started at {file_time}")
    log_this(log_file, "")
    log_this(log_file, f"RUNNING: gamelist.xml files from {gamelist_roms_dir}")
    if clean == True:
        if del_roms == True:
            log_this(log_file, "WARNING: deleting roms")
        if del_art == True:
            log_this(log_file, "WARNING: deleting art files")
        if del_snaps == True:
            log_this(log_file, "WARNING: deleting video snaps")
        if del_m3u == True:
            log_this(log_file, "WARNING: deleting m3u disk files")

    log_this(log_file, "\n")

    for system in systems:
        for single_system in system.split("/"):
            print("")
            print(f"Now processing {single_system}...")
            process_gamelist(single_system, gamelist_roms_dir, log_file, backup_dir, del_roms=del_roms, del_art=del_art, del_snaps=del_snaps, del_m3u=del_m3u, del_extra=del_extra, clean=clean, auto_clean=auto_clean)

    log_this(log_file, "\n")
    log_this(log_file, f"{process_type.upper()}ING GAMELISTS: ended at {datetime.datetime.utcnow()}")
    cls()
    d.textbox(log_file, title=f"Contents of {log_file}")

    if auto_clean == False:
        cls()
        main_dialog()

    return


def gamelists_orphan_dialog(systems, clean: bool):
    menu_text = ""
    if clean == True:
        menu_text = ("Clean Orphaned Files"
                    "\n\nThis will clean your gamelist.xml files and optionally remove orphaned roms, artwork,  video snapshots, and multiple disk (m3u) files according to your choices below."
                    "\n\nThe results of this procedure can be viewed in the \"/home/pi/.update_tool/gamelist_logs\" folder, it will be called \"clean_gamelists-[date]-[time].log\"."
                    "\n\nRemoving orphaned files will DELETE them by moving them to a folder that corresponds to the gamelist log called \"clean_gamelists-[date]-[time]\"."
                    "\nYou can reverse this operation using the \"Restore Clean Game List Logs\" function and selecting the appropriate log file."
                    "\n\nRemove orphaned:")
    else:
        menu_text = ("Check Orphaned Files"
                    "\n\nThis will check your gamelist.xml files and optionally check for orphaned roms, artwork, video snapshots, and multiple disk (m3u) files according to your choices below."
                    "\n\nThe results of this procedure can be viewed in the \"/home/pi/.update_tool/gamelist_logs\" folder, it will be called \"check_gamelists-[date]-[time].log\""
                    "\n\nCheck orphaned:")

    code, tags = d.checklist(text=menu_text, 
                            choices=[("Roms", "", False), ("Artwork", "", False), ("Snapshots", "", False), ("M3U Disk Files", "", False), ("Extra Files", "", False)])

    if code == d.OK:
        del_roms = True if "Roms" in tags else False
        del_art = True if "Artwork" in tags else False
        del_snaps = True if "Snapshots" in tags else False
        del_m3u = True if "M3U Disk Files" in tags else False
        del_extra = True if "Extra Files" in tags else False

        do_process_gamelists(systems, del_roms=del_roms, del_art=del_art, del_snaps=del_snaps, del_m3u=del_m3u, del_extra=del_extra, clean=clean)

    cls()
    gamelists_dialog("Clean" if clean == True else "Check")

    return


def gamelist_genres_dialog(system: str, game: dict, elem: ET.Element):
    dialog_text = ""
    menu_choices = []
    system_genres = []

    for key in genres.keys():
        system_genres.append(key)

    system_genres.sort()
    for genre in system_genres:
        menu_choices.append((genre, "", False if len(menu_choices) > 0 else True))

    dialog_text = f"System:\t{system}"

    if "name" in game.keys():
        dialog_text += f"\n\nGame:\t{game['name']}"

    if "genre" in game.keys():
        dialog_text += f"\n\nGenre:\t{game['genre']}"

    if "path" in game.keys():
        dialog_text += f"\n\nRom:\t{game['path'].replace('./', '')}"

    if "desc" in game.keys():
        dialog_text += "\n\n" if len(dialog_text) > 0 else ""
        dialog_text += f"Description:\t{game['desc']}"

    dialog_text += "\n\nSelect Genre:"

    code, tag = d.radiolist(text=dialog_text,
                             choices=menu_choices,
                             extra_button=True, 
                             extra_label="Skip", 
                             title="Manually Select Genres")

    if code == d.EXTRA:
        return True

    if code == d.OK:
        genre = elem.find("genre")
        if genre is not None:
            genre.text = tag
        else:
            elem.append(ET.fromstring(f"<genre>{tag}</genre>"))

        genre_collection = genres[tag]
        lines = []
        cfg_file = os.path.join("/opt/retropie/configs/all/emulationstation/collections", genre_collection)
        with open(cfg_file, 'r', encoding='utf-8') as f:
            lines = f.readlines()
            if game["path"] not in lines:
                system_roms = f"/home/pi/RetroPie/roms/{system}/"
                lines.append(game["path"].replace("./", system_roms) + "\n")
                lines.sort()
        
                # write cfg
                file_time = safe_write_backup(cfg_file)
                
                with open(cfg_file, 'w', encoding='utf-8') as f:
                    f.writelines(lines)

                safe_write_check(cfg_file, file_time)


    if code == d.CANCEL:
        return False

    return True


def check_for_genres():
    if len(genres.keys()) == 0:
        d.msgbox("You need to install the tool to run this utility.")
        cls()
        gamelist_utilities_dialog()
    
    return


def do_gamelist_genres(systems: list):
    def _process_entry(elem: ET.Element):
        genre = elem.find("genre")
        if genre is not None:
            if genre.text is not None:
                return genre.text not in genres.keys()

        return True

    check_for_genres()
    continue_processing = True
    file_time = datetime.datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    rom_dir = "/home/pi/RetroPie/roms"
    fields = ["name", "path", "desc", "genre"]

    for system in systems:
        if not continue_processing:
            break

        for single_system in system.split("/"):
            system_roms = os.path.join(rom_dir, single_system)

            # start scanning gamelist.xml
            src_xml = os.path.join(system_roms, "gamelist.xml")
            src_tree = ET.parse(src_xml)
            src_root = src_tree.getroot()

            for src_game in src_root.iter("game"):
                src_fields = {}

                if _process_entry(src_game) == False:
                    continue

                for item in src_game:
                    if item.tag in fields:
                        src_fields[item.tag] = item.text if item.text else ""

                continue_processing = gamelist_genres_dialog(single_system, src_fields, src_game)
                if continue_processing:
                    file_time = safe_write_backup(src_xml)
                    
                    # ET.indent(dest_tree, space="\t", level=0)
                    indent(src_root, space="\t", level=0)
                    with open(src_xml, "wb") as fh:
                        src_tree.write(fh, "utf-8")

                    safe_write_check(src_xml, file_time)
                else:
                    break

    cls()
    gamelists_dialog("Genre")

    return


def get_emulators_cfg_filename(filename: str):
    # this will return only number, letter, and - or _ characters
    # this seems to be the logic...
    parts = list([val for val in filename if val.isalnum() or val == '-' or val == '_' ])
 
    return "".join(parts)


def get_official_emulators_origins(origin: str):
    origins = []
    if os.path.isfile(origin):
        with open(origin, 'r', encoding='utf-8') as f:
            lines = f.readlines()
            for line in lines:
                if len(line.strip()) > 0:
                    pos = line.rfind(".")
                    emulator_cfg_name = get_emulators_cfg_filename(line.strip()[:pos])
                    origins.append(emulator_cfg_name)

    return origins


def get_official_origins(origin: str):
    origins = []
    if os.path.isfile(origin):
        with open(origin, 'r', encoding='utf-8') as f:
            lines = f.readlines()
            for line in lines:
                if len(line.strip()) > 0:
                    origins.append(line.strip())

    return origins


def is_game_official(game: str, origins=[]):
    return game in origins


def count_games(system: str, games: list, official_only = True, additional_columns = []):
    count = 0
    official_count = 0
    unofficial_count = 0
    counts = []
    games_list = []
    system_dir = os.path.join("/home/pi/RetroPie/roms", system)
    src_xml = os.path.join(system_dir, "gamelist.xml")
    #games = []

    src_tree = ET.parse(src_xml)
    src_root = src_tree.getroot()
    origins = []
    origin = get_config_value("CONFIG_ITEMS", "origin_file")
    if origin is not None:
        origins = get_official_origins(os.path.join(system_dir, origin))

    for src_game in src_root.iter("game"):
        game_list = []
        game = src_game.find("name")
        if game.text is not None:
            path = src_game.find("path")
            if path.text is not None:
                game_path = path.text.replace("./", system_dir + "/").strip()
                official = is_game_official(path.text, origins)
                if official:
                    official_count += 1
                else:
                    unofficial_count += 1
                if official_only == True:
                    #if not os.path.dirname(game_path) == system_dir:
                    if not official:
                        continue
                game_size = 0
                if os.path.isfile(game_path):
                    game_size = os.path.getsize(game_path)
                
                origin_text = ""
                origin = src_game.find("origin")
                if origin is not None:
                    if origin.text is not None:
                        origin_text = origin.text

                game_list = [game.text.strip(), game_path.replace(system_dir + "/", ""), convert_filesize(str(game_size)), "OFFICIAL" if official == True else "unofficial", origin_text]
                #if game.text.strip() in games:
                #    d.msgbox(system + " - " + game.text.strip())
                #games.append(game.text.strip())
                count += 1
            for additional_column in additional_columns:
                column_text = ""
                column = src_game.find(additional_column)
                if column is not None:
                    if column.text is not None:
                        column_text = column.text
                game_list.append(column_text)
            games_list.append(tuple(game_list))

    games_list.sort()
    for list_game in games_list:
        new_list = list(list_game)
        new_list.insert(0, system)
        games.append(tuple(new_list))
        #games.append((system, list_game[0], list_game[1], list_game[2], list_game[3], list_game[4]))

    counts.append(count)
    counts.append(official_count)
    counts.append(unofficial_count)
    return counts


def gamelist_counts_dialog(systems: list, all_systems=False):
    official_only = (get_config_value("CONFIG_ITEMS", "count_official_only") == "True")
    systems.sort()
    systems_text = ""
    total_count = 0
    official_count = 0
    unofficial_count = 0
    games = []
    games_text = f"Count offical only is {'on' if official_only == True else 'off'}.\n\nsystem\tgame\tpath\tsize\tofficial\torigin"
    additional_gameslist_columns = get_config_value("CONFIG_ITEMS", "additional_gameslist_columns")
    if additional_gameslist_columns is None:
        additional_gameslist_columns = ""
    #additional_columns = [column.strip() for column in additional_gameslist_columns.split(',')]
    additional_columns = []
    for additional_column in additional_gameslist_columns.split(','):
        if len(additional_column.strip()) > 0:
            additional_columns.append(additional_column.strip())
    for additional_column in additional_columns:
        games_text += "\t" + additional_column
    games_text += "\n"
    for system in systems:
        for single_system in system.split("/"):
            system_count = count_games(single_system, games, official_only=official_only, additional_columns=additional_columns)
            total_count += system_count[0]
            official_count += system_count[1]
            unofficial_count += system_count[2]
            systems_text += f"\n-{single_system}:\t{str(system_count[0])}"
            if official_only == False:
                systems_text += f"\t{str(system_count[1])}\t{str(system_count[2])}"

    systems_counted = "All" if all_systems == True else "Selected"
    systems_header = f"Count official only is {'on' if official_only == True else 'off'}\n\nTOTAL: {total_count}"
    if official_only == False:
        systems_header += f"\tOfficial: {official_count}\tUnofficial: {unofficial_count}"
    systems_header += f"\n\n{systems_counted} Systems:"
    systems_text = systems_header + systems_text

    display_text = systems_text
    if all_systems == True:
        display_count = "all games" if official_only == False else "official games only"
        display_text = ("This utility only counts systems defined in es_systems.cfg.\n"
                        "At the time of the creation of this utility Kodi and Steam were the only two items that weren't.\n"
                        "To match your EmulationStation game count add 2 (1 for Kodi, 1 for Steam) to the total.\n"
                        "This utility is currently set to count " + display_count + ".\n"
                        "Because you have chosen to count all systems:\n"
                        "\t-a compiled list af all games, by system, is located in /home/pi/.update_tool/games_list.txt for your reference.\n"
#                        "\t-a a list of games added or removed, by system, is located in /home/pi/.update_tool/games_list_changes.txt for your reference.\n"
                        "\t-a copy of this count is located in /home/pi/.update_tool/counts.txt for your reference.\n\n" + display_text)
        with open("/home/pi/.update_tool/counts.txt", 'w', encoding='utf-8') as f:
            f.write(systems_text)

        games_list_file = "/home/pi/.update_tool/games_list.txt"
#        games_list_previous = "/tmp/games_list.previous"
#        
#        if os.path.exists(games_list_file):
#            shutil.copy2(games_list_file, games_list_previous)
            
        for game in games:
            line_text = ""
            #game_list = list(game)
            for game_text in game:
                #line_text += "\t" if len(games_text) > 0 else ""
                line_text += game_text + "\t"
            games_text += line_text[:-1] + "\n"
            #games_text += f"{game[0]}\t{game[1]}\t{game[2]}\t{game[3]}\t{game[4]}\t{game[5]}\n"
        with open(games_list_file, 'w', encoding='utf-8') as f:
            f.write(games_text)

#        if os.path.exists(games_list_previous):
#            runcmd(f"( echo \"System\tGame\n\"; diff --suppress-common-lines -y {games_list_previous} {games_list_file} | sed -e 's/</- Removed/' -e 's/^[\t ]*>\t\(.*\)/\\1 - Added/' ) >/home/pi/.update_tool/games_list_changes.txt")

    d.msgbox(display_text)

    cls()
    gamelist_utilities_dialog()

    return 
    

def remove_system_genres(system: str, cfg_file: str):
    new_lines = []

    with open(cfg_file, 'r', encoding='utf-8') as f:
        lines = f.readlines()
        for line in lines:
            if line.find(f"/{system}/") < 0:
                new_lines.append(line)
        
    with open(cfg_file, 'w', encoding='utf-8') as f:
        f.writelines(new_lines)

    return


def system_genre_realignment(system: str):
    collections_dir = "/opt/retropie/configs/all/emulationstation/collections"
    rom_dir = "/home/pi/RetroPie/roms"
    genre_roms = {}

    for key, val in genres.items():
        collection_cfg = os.path.join(collections_dir, val)
        remove_system_genres(system, collection_cfg)

    system_roms = os.path.join(rom_dir, system)

    # start scanning gamelist.xml
    src_xml = os.path.join(system_roms, "gamelist.xml")
    if os.path.exists(src_xml):
        if not os.path.isfile(src_xml):
            return

    src_tree = ET.parse(src_xml)
    src_root = src_tree.getroot()

    for src_game in src_root.iter("game"):
        path = src_game.find("path")
        if path is None:
            continue
        if path.text is None:
            continue
        
        genre = src_game.find("genre")
        if genre is None:
            continue
        if genre.text is None:
            continue

        if genre.text not in genre_roms.keys():
            genre_roms[genre.text] = []

        roms = genre_roms[genre.text]
        system_rom = os.path.join(system_roms, path.text.replace("./", ""))
        roms.append(system_rom.strip() + "\n")
        
    for key, val in genre_roms.items():
        if key in genres.keys():
            collection_cfg = os.path.join(collections_dir, genres[key])
            if os.path.exists(collection_cfg):
                if os.path.isfile(collection_cfg):
                    lines = []
                    with open(collection_cfg, 'r', encoding='utf-8') as f:
                        lines = f.readlines()

                    lines.extend(val)
                    lines.sort()
                    with open(collection_cfg, 'w', encoding='utf-8') as f:
                        f.writelines(lines)

    return


def do_genre_realignment(systems: list, overwrite=False):
    check_for_genres()
    collections_dir = "/opt/retropie/configs/all/emulationstation/collections"
    if overwrite == True:
        for key, val in genres.items():
            collection_cfg = os.path.join(collections_dir, val)
            with open(collection_cfg, 'w', encoding='utf-8') as f:
                f.write("")

    for system in systems:
        system_genre_realignment(system)
    d.msgbox('Genre realignment done!')

    return


def sort_gamelist(system: str):
    games_list = {}
    games = []
    system_dir = os.path.join("/home/pi/RetroPie/roms", system)
    src_xml = os.path.join(system_dir, "gamelist.xml")

    src_tree = ET.parse(src_xml)
    src_root = src_tree.getroot()

    for src_game in src_root.iter("game"):
        game = src_game.find("name")
        path = src_game.find("path")
        if game.text is not None:
            if path.text is not None:
                games_list[game.text.lower() + "-" + path.text.lower()] = ET.tostring(src_game)
                games.append(src_game)

    for game in games:
        src_root.remove(game)

    for game in sorted(games_list.keys()):
        src_root.append(ET.fromstring(games_list[game]))

    file_time = safe_write_backup(src_xml)
    
    # ET.indent(dest_tree, space="\t", level=0)
    indent(src_root, space="\t", level=0)
    with open(src_xml, "wb") as fh:
        src_tree.write(fh, "utf-8")

    safe_write_check(src_xml, file_time)

    return len(games)


def do_sort_gamelists(systems: list):
    total_games = 0
    total_systems = 0
    start_time = datetime.datetime.utcnow()

    print("")
    for system in systems:
        total_systems += 1
        print(f"Now sorting: {system}")
        total_games += sort_gamelist(system)
        
    d.msgbox(f"Sorted {total_games} games, in {total_systems} systems.\n\nTime to process: {str(datetime.datetime.utcnow() - start_time)[:-7]}")

    return


def return_invalid_files(files: list):
    invalid_files = []
    for file in files:
        if not os.path.isfile(file):
            invalid_files.append(file)

    return invalid_files


def do_process_unofficial_package(selected_items: list, name: str):
    start_time = datetime.datetime.utcnow()
    tmp_dir = Path("/", "tmp", "package")
    rom_dir = "/home/pi/RetroPie/roms"
    do_not_overwrite = ["favorite", "lastplayed", "playcount"]
    total_size = 0
    game_number = 0
    counter = 0
    systems = []
    no_m3u_support = ["atari800"]

    packaging_options = get_config_value("CONFIG_ITEMS", "packaging_options",return_none=False).strip().split(",")
    print(f"Packaging {len(selected_items)} games into {name}.zip")
    if "FULL_GAMELIST" in packaging_options:
        print("Including full gammelist.xml files")
    
    if os.path.isdir(str(tmp_dir)):
        shutil.rmtree(str(tmp_dir))

    for selected_item in selected_items:
        game_size = 0
        system = selected_item[0]
        rom_file = selected_item[1]
        img_file = ""
        snap_file = ""
        counter += 1

        if system not in systems:
            systems.append(system)
        gamelist = f"{rom_dir}/{system}/gamelist.xml"
        system_dir = f"{rom_dir}/{system}/"
        if not os.path.isfile(gamelist):
            continue

        print(f"Now Packaging Game {counter} of {len(selected_items)}: [{system}]\t{selected_item[2]}\t({rom_file})")
        src_tree = ET.parse(gamelist)
        src_root = src_tree.getroot()

        parent = src_tree.find(f".//game[path=\"./{rom_file}\"]")
        if parent is not None:
            node = parent.find("image")
            if node is not None:
                if node.text is not None:
                    img_file = node.text
            node = parent.find("video")
            if node is not None:
                if node.text is not None:
                    snap_file = node.text

            # do the intial check to see if the elements exist in the xml file
            if len(img_file) == 0:
                print("-no image file defined, not processing...")
                continue
            elif len(snap_file) == 0:
                print("-no snap file defined, not processing...")
                continue

            rom_file = system_dir + rom_file
            img_file = img_file.replace("./", system_dir)
            snap_file = snap_file.replace("./", system_dir)
            # do final check
            if not os.path.isfile(rom_file):
                print(f"-missing rom file \"{rom_file}\", not procesing...")
                continue
            elif not os.path.isfile(img_file):
                print(f"-missing image file \"{img_file}\", not procesing...")
                continue
            elif not os.path.isfile(snap_file):
                print(f"-missing snap file \"{snap_file}\", not procesing...")
                continue

            # deal with .cue and .m3u files...
            if os.path.splitext(rom_file)[1] == ".cue":
                cue_files = parse_cue_file(rom_file)
                if len(return_invalid_files(cue_files)) > 0:
                    print("-cue file has invalid entries, not processing...")
                    continue
                for cue_file in cue_files:
                    if os.path.isfile(cue_file):
                        os.makedirs(str(tmp_dir) + os.path.dirname(cue_file), exist_ok=True)
                        file_size = os.path.getsize(cue_file)
                        total_size += file_size
                        print(f"-now copying: {cue_file} ({convert_filesize(str(file_size))})")
                        shutil.copyfile(cue_file, str(tmp_dir) + cue_file)                        
            if os.path.splitext(rom_file)[1] == ".m3u":
                m3u_files = get_recursive_m3u_files(rom_file, os.path.dirname(rom_file))
                if len(return_invalid_files(m3u_files)) > 0:
                    print("-m3u file has invalid entries, not processing...")
                    continue
                for m3u_file in m3u_files:
                    if os.path.isfile(m3u_file):
                        os.makedirs(str(tmp_dir) + os.path.dirname(m3u_file), exist_ok=True)
                        file_size = os.path.getsize(m3u_file)
                        total_size += file_size
                        print(f"-now copying: {m3u_file} ({convert_filesize(str(file_size))})")
                        shutil.copyfile(m3u_file, str(tmp_dir) + m3u_file)                        

            # deal with no m3u support <- this is a hack that Rick does
            if system in no_m3u_support:
                data_dir = Path(f"{rom_dir}/{system}/.data/{os.path.basename(rom_file)}").with_suffix("")
                if os.path.isdir(data_dir):
                    for file in os.scandir(data_dir):
                        if os.path.isfile(file.path):
                            os.makedirs(str(tmp_dir) + os.path.dirname(file.path), exist_ok=True)
                            file_size = os.path.getsize(file)
                            total_size == file_size
                            print(f"-now copying: {file.path} ({convert_filesize(str(file_size))})")
                            shutil.copyfile(file.path, str(tmp_dir) + file.path)
                #shutil.copytree(data_dir, str(tmp_dir) + data_dir)
                data_file = Path(f"{rom_dir}/{system}/.multidisk/{os.path.basename(rom_file)}").with_suffix("")
                if os.path.isfile(data_file):
                    os.makedirs(str(tmp_dir) + os.path.dirname(str(data_file)), exist_ok=True)
                    file_size = os.path.getsize(file)
                    total_size == file_size
                    print(f"-now copying: {str(data_file)} ({convert_filesize(str(file_size))})")
                    shutil.copyfile(str(data_file), str(tmp_dir) + str(data_file))
                #data_file = f"{rom_dir}/{system}/.data/{os.path.basename(rom_file)}"
                #if os.path.isdir(Path(data_file).with_suffix("")):
                #    data_dir = str(Path(data_file).with_suffix(""))
                #    if os.path.isdir(str(tmp_dir) + data_dir):
                #        shutil.rmtree(str(tmp_dir) + data_dir)
                #    shutil.copytree(data_dir, str(tmp_dir) + data_dir)


            os.makedirs(str(tmp_dir) + os.path.dirname(rom_file), exist_ok=True)
            file_size = os.path.getsize(rom_file)
            total_size += file_size
            print(f"-now copying: {rom_file} ({convert_filesize(str(file_size))})")
            shutil.copyfile(rom_file, str(tmp_dir) + rom_file)

            os.makedirs(str(tmp_dir) + os.path.dirname(img_file), exist_ok=True)
            file_size = os.path.getsize(img_file)
            total_size += file_size
            print(f"-now copying: {img_file} ({convert_filesize(str(file_size))})")
            shutil.copyfile(img_file, str(tmp_dir) + img_file)

            os.makedirs(str(tmp_dir) + os.path.dirname(snap_file), exist_ok=True)
            file_size = os.path.getsize(snap_file)
            total_size += file_size
            print(f"-now copying: {snap_file} ({convert_filesize(str(file_size))})")
            shutil.copyfile(snap_file, str(tmp_dir) + snap_file)

            if not os.path.isfile(str(tmp_dir) + gamelist):
                with open(str(tmp_dir) + gamelist, 'wb') as file:
                    file.write(bytes("<gamelist></gamelist>", 'utf-8'))

            #merge_xml(gamelist, str(tmp_dir) + gamelist)
            dest_tree = ET.parse(str(tmp_dir) + gamelist)
            dest_root = dest_tree.getroot()
            
            print("-adding to gamelist.xml")
            dest_root.append(ET.fromstring("<game></game>"))
            dest_parent = dest_root[len(dest_root) - 1]
            for src_node in parent:
                if src_node.tag not in do_not_overwrite:
                    child = ET.SubElement(dest_parent, src_node.tag)
                    child.text = src_node.text

            indent(dest_root, space="\t", level=0)
            with open(str(tmp_dir) + gamelist, "wb") as fh:
                dest_tree.write(fh, "utf-8")

            game_number += 1

    if "FULL_GAMELIST" not in packaging_options:
        for gamelist_file in tmp_dir.rglob('gamelist.xml'):
            total_size += os.path.getsize(gamelist_file)
    else:
        for system in systems:
            gamelist = f"{rom_dir}/{system}/gamelist.xml"
            shutil.copyfile(gamelist, str(tmp_dir) + gamelist)

    zip_file = f"/home/pi/.update_tool/unofficial_packages/{name}.zip"
    os.makedirs(os.path.dirname(zip_file), exist_ok=True)

    print(f"-compressing {convert_filesize(str(total_size))} into {name}.zip")
    with zipfile.ZipFile(zip_file,'w') as zip:
        # writing each file one by one
        for file in tmp_dir.glob('**/*'):
            if str(file) == zip_file:
                continue
            zip.write(file, arcname=file.relative_to(tmp_dir), compress_type=zipfile.ZIP_DEFLATED)        

    shutil.rmtree(str(tmp_dir))

    d.msgbox(f"Complete!\n\nPackaged {game_number} of {len(selected_items)} games ({convert_filesize(str(total_size))}) in {str(datetime.datetime.utcnow() - start_time)[:-7]}.\n\nYour file is located at:\n{zip_file}")

    return


def package_unofficial_update_name_dialog():
    code, string = d.inputbox("What would you like to name your update package?")
    if code == d.OK:
        return string
    
    return None


def unofficial_update_dialog(systems: list, dialog_title: str):
    rom_dir = "/home/pi/RetroPie/roms"
    menu_choices = []
    all_roms = {}
    selected_items = []

    for system in systems:
        official_roms = []
        gamelist = f"{rom_dir}/{system}/gamelist.xml"

        rickdangerous_file = f"{rom_dir}/{system}/.RickDangerous"
        if os.path.isfile(rickdangerous_file):
            with open(rickdangerous_file, 'r') as file:
                official_roms = file.readlines()

        src_tree = ET.parse(gamelist)
        src_root = src_tree.getroot()

        for src_game in src_root.iter("game"):
            rom_file = ""
            name = ""

            # get rom file
            src_node = src_game.find("path")
            if src_node is not None:
                if src_node.text is not None:
                    rom_file = os.path.basename(src_node.text)
                # get rom file
            src_node = src_game.find("name")
            if src_node is not None:
                if src_node.text is not None:
                    name = src_node.text

            # just to be sure that name or path is not empty
            if len(rom_file) == 0 or len(name) == 0:
                continue

            # check if rom is official
            if "./" + rom_file + "\n" in official_roms:
                continue

            menu_choice = f"[{system}]\t{name}\t({rom_file})"
            menu_choices.append((menu_choice, "", False))
            all_roms[menu_choice] = (system, rom_file, name)

    if len(menu_choices) == 0:
        d.msgbox("No unofficial roms found!")
        return []

    menu_choices.sort()
    code, tags = d.checklist(text="Select Games",
                choices=menu_choices,
                ok_label="Add Selected", 
                extra_button=True, 
                extra_label="Add All", 
                title=dialog_title)
    
    if code == d.OK:
        for tag in tags:
            selected_items.append(all_roms[tag])

    if code == d.EXTRA:
        for selected_item in all_roms.keys():
            selected_items.append(all_roms[selected_item])

    return selected_items


def gamelists_dialog(function: str):
    rom_dir = "/home/pi/RetroPie/roms"
    art_dir = "boxart"
    snaps_dir = "snaps"

    dialog_title = ""
    if function == "Check":
        dialog_title = "Check Game Lists"
        button_text = function
    elif function == "Clean":
        dialog_title = "Clean Game Lists"
        button_text = function
    elif function == "Genre":
        dialog_title = "Manually Select Genres"
        button_text = "Process"
    elif function == "Realign":
        dialog_title = "Realign Genre Collections"
        button_text = "Process"
    elif function == "Sort":
        dialog_title = "Sort Game Lists"
        button_text = "Process"
    elif function == "Count":
        dialog_title = "Count of Games"
        button_text = "Count"
    elif function == "Package":
        dialog_title = "Package Unofficial Update"
        button_text = "Select"
    elif function == "Package":
        dialog_title = "Remove Unofficial Roms"
        button_text = "Select"

    systems = get_all_systems_from_cfg()
    menu_choices = []

    for system in systems:
        menu_choices.append((system, "", False))

    button_text = "Process" if function == "Genre" else function
    code, tags = d.checklist(text="Available Systems",
                            choices=menu_choices,
                            ok_label=f"{button_text} Selected", 
                            extra_button=True, 
                            extra_label=f"{button_text} All", 
                            title=dialog_title)

    if code == d.OK:
        if function == "Genre":
            do_gamelist_genres(tags)
        elif function == "Count":
            gamelist_counts_dialog(tags)
        elif function == "Realign":
            do_genre_realignment(tags)
        elif function == "Sort":
            do_sort_gamelists(tags)
        elif function == "Package":
            return tags
            #unofficial_update_dialog(tags)
        elif function == "Remove":
            return tags
        else:
            gamelists_orphan_dialog(tags, function == "Clean")

    if code == d.EXTRA:
        if function == "Genre":
            do_gamelist_genres(systems)
        elif function == "Count":
            gamelist_counts_dialog(systems, True)
        elif function == "Realign":
            do_genre_realignment(systems, True)
        elif function == "Sort":
            do_sort_gamelists(systems)
        elif function == "Package":
            return systems
            #unofficial_update_dialog(systems)
        elif function == "Remove":
            return systems
        else:
            gamelists_orphan_dialog(systems, function == "Clean")        

    if code == d.CANCEL:
        cls()
        gamelist_utilities_dialog()

    cls()
    gamelists_dialog(function)

    return


def do_remove_logs(logs: list, logsdir: str):
    for log in logs:
        log_file = os.path.join(f"/home/pi/.update_tool/{logsdir}", log)
        log_dir = os.path.splitext(log_file)[0]
        if os.path.exists(log_file):
            if os.path.isfile(log_file):
                os.remove(log_file)
        if os.path.exists(log_dir):
            if os.path.isdir(log_dir):
                shutil.rmtree(log_dir)            
    d.msgbox('Done!')

    return


def do_restore_logs(logs: list):
    for log in logs:
        log_file = os.path.join("/home/pi/.update_tool/gamelist_logs", log)
        log_dir = os.path.splitext(log_file)[0]
        if os.path.exists(log_dir):
            if os.path.isdir(log_dir):
                copydir(log_dir, "/home/pi/RetroPie/roms")
    d.msgbox('Done!')

    return


def get_total_path_size(dir: str):
    if os.path.exists(dir):
        process = subprocess.run(['du', '-sb', dir], capture_output=True, text=True)
        size = process.stdout.split()[0]
        #print(size)
        return size

    return None


def get_log_size(log: str, subdir: str):
    log_file = os.path.join(f"/home/pi/.update_tool/{subdir}", log)
    log_dir = os.path.splitext(log_file)[0]

    if os.path.exists(log_file):
        if not os.path.isfile(log_file):
            return None

    log_size = int(get_total_path_size(log_file))
    if os.path.exists(log_dir):
        if os.path.isdir(log_dir):
            log_size += int(get_total_path_size(log_dir))

    return log_size


def logs_dialog(logsdir: str, function: str, title: str, patterns: list, multi=True):
    menu_choices = []
    logs = []
    total_size = 0

    for pattern in patterns:
        for log in Path(f"/home/pi/.update_tool/{logsdir}").glob(pattern):
            if os.path.exists(log):
                if os.path.isfile(log):
                    logs.append(os.path.basename(log))

    if len(logs) == 0:
        d.msgbox(f"There are no logs to {function.lower()}!")
        #cls()
        #gamelist_utilities_dialog()
        return
        
    logs.sort(reverse=True)
    for menu_choice in logs:
        log_size = get_log_size(menu_choice, logsdir)
        total_size += log_size
        menu_choices.append((menu_choice + f" ({convert_filesize(str(log_size))})", "", False))

    dlg_text = f"Log Files in \"/home/pi/.update_tool/{logsdir}\" ({convert_filesize(str(total_size))}):"
    if multi == True:
        code, tags = d.checklist(text=dlg_text,
                                choices=menu_choices,
                                ok_label=f"{function} Selected", 
                                extra_button=True, 
                                extra_label=f"{function} All", 
                                title=title)
    else:
        code, tags = d.radiolist(text=dlg_text,
                                choices=menu_choices,
                                ok_label=f"{function} Selected", 
                                title=title)

    selected_logs = []
    selected_items = []
    if code == d.CANCEL:
        return

    if code == d.OK:
        selected_items = tags

    if code == d.EXTRA:
        selected_items = logs

    if len(selected_items) > 0:
        if "'str'" in str(type(selected_items)):
            selected_logs.append(selected_items.split(" ")[0])
        else:
            for selected_item in selected_items:
                selected_logs.append(selected_item.split(" ")[0])

        if function == "Remove":
            do_remove_logs(selected_logs, logsdir)
        elif function == "Restore":
            do_restore_logs(selected_logs)

    #cls()
    #gamelist_utilities_dialog()

    return


def get_emulators_cfg(log_file="", check=False):
    emulator_cfg = "/opt/retropie/configs/all/emulators.cfg"
    items = {}
    duplicate_counter = 0

    if not os.path.exists(emulator_cfg):
        return items, duplicate_counter

    with open(emulator_cfg, 'r') as configfile:
        lines_in = configfile.readlines()
        for line in lines_in:
            parts = line.split("=")
            if parts[0].strip() in items.keys():
                if len(log_file) > 0:
                    log_this(log_file, f"-{'Identified' if check == True else 'Removed'} duplicate entry for \"{parts[0].strip()}\"")
                duplicate_counter += 1
            if len(parts) == 2:
                items[parts[0].strip()] = parts[1].strip()

    return items, duplicate_counter


def write_sorted_emulators_cfg(items: dict):
    emulator_cfg = "/opt/retropie/configs/all/emulators.cfg"
    lines_out = ""
    game_counter = 0
    
    
    for item in sorted(items.keys()):
        lines_out += f"{item} = {items[item]}\n"
        game_counter += 1

    file_time = safe_write_backup(emulator_cfg)

    with open(emulator_cfg, 'w') as configfile:
        configfile.write(lines_out)

    safe_write_check(emulator_cfg, file_time)

    return game_counter


def do_clean_emulators_cfg(check=False, auto_clean=False):
    items = {}
    game_counter = 0
    duplicate_counter = 0
    file_time = datetime.datetime.utcnow()
    results = ""
    process_type = "clean"
    if check == True:
        process_type = "check"
    elif auto_clean == True:
        process_type = "auto_clean"

    log_file = f"/home/pi/.update_tool/emulators_logs/{process_type}_emulators-{file_time.strftime('%Y%m%d-%H%M%S')}.log"

    if auto_clean == True:
        log_this(log_file, "AUTO ")
    log_this(log_file, f"{'CHECK' if check == True else 'CLEAN'}ING emulators.cfg: started at {file_time.strftime('%Y%m%d-%H%M%S')}\n\n")
    log_this(log_file, "\n")
    
    items, duplicate_counter = get_emulators_cfg(log_file=log_file, check=check)
    items, bad_entries = clean_emulators_cfg(items, log_file, check=check)
    if check == False:
        game_counter = write_sorted_emulators_cfg(items)

    if check == True:
        results = f"Clean would sort {len(items)} game entries.\nIdentified {duplicate_counter} duplicate entries.\nIdentified {bad_entries} bad entries."
    else:
        results = f"Sorted {len(items)} game entries.\nRemoved {duplicate_counter} duplicate entries.\nRemoved {bad_entries} bad entries."

    log_this(log_file, "\n")
    log_this(log_file, results)
    log_this(log_file, "\n")
    if auto_clean == True:
        log_this(log_file, "AUTO ")
    log_this(log_file, f"{'CHECK' if check == True else 'CLEAN'}ING emulators.cfg: ended at {datetime.datetime.utcnow().strftime('%Y%m%d-%H%M%S')}")

    d.msgbox(results)

    return


def check_clean_emulators_dialog():
    code, tag = d.menu("Main Menu", 
                    choices=[("1", "Check Emulators Config"), 
                             ("2", "Clean Emulators Config"), 
                             ("3", "Remove Check/Clean Emulators Config Logs")],
                    title="Check/Clean Emulators Config Utilities")
    
    if code == d.OK:
        if tag == "1":
            do_clean_emulators_cfg(check=True)
        elif tag == "2":
            do_clean_emulators_cfg()
        elif tag == "3":
            logs_dialog("emulators_logs", "Remove", "Remove Check/Clean Emulators Config Logs", ["check_emulators*", "clean_emulators*", "auto_clean_emulators*"], multi=True)

    return


def do_clean_unofficial_roms(selected_items: list):
    for selected_item in selected_items:
        system = selected_item[0]
        rom_file = selected_item[1]

        gamelist = f"/home/pi/RetroPie/roms/{system}/gamelist.xml"
        if not os.path.isfile(gamelist):
            continue

        src_tree = ET.parse(gamelist)
        src_root = src_tree.getroot()

        parents = src_tree.findall(f".//game[path=\"./{rom_file}\"]")
        for parent in parents:
            src_root.remove(parent)
            
        with open(gamelist, "wb") as fh:
            src_tree.write(fh, "utf-8")

    clean_unofficial_roms(selected_items)

    return


def check_clean_utilities_dialog():
    code, tag = d.menu("Main Menu", 
                    choices=[("1", "Check Game Lists"), 
                             ("2", "Clean Game Lists"), 
                             ("3", "Restore Clean Game List Logs"), 
                             ("4", "Remove Check/Clean Game List Logs"), 
                             ("5", "Clean Unoffical Roms")],
                    title="Check/Clean Game List Utilities")
    
    if code == d.OK:
        if tag == "1":
            gamelists_dialog("Check")
        elif tag == "2":
            gamelists_dialog("Clean")
        elif tag == "3":
            logs_dialog("gamelist_logs", "Restore", "Restore Clean Game List Logs", ["clean_gamelists*", "auto_clean_gamelists*"], multi=False)
        elif tag == "4":
            logs_dialog("gamelist_logs", "Remove", "Remove Check/Clean Game List Logs", ["check_gamelists*", "clean_gamelists*", "auto_clean_gamelists*", "clean_unofficial_roms*"], multi=True)
        elif tag == "5":
            systems = None
            systems = gamelists_dialog("Remove")
            if systems is not None:
                selected_items = unofficial_update_dialog(systems, "Clean Unoffical Roms")
                if len(selected_items) > 0:
                    do_clean_unofficial_roms(selected_items)

    if code == d.CANCEL:
        cls()
        main_dialog()

    return


def genre_utilities_dialog():
    code, tag = d.menu("Main Menu", 
                    choices=[("1", "Manually Select Genres"),
                             ("2", "Realign Genre Collections"),
                             ("3", "Clear Recent Additions Collection")],
                    title="Genre Utilities")
    
    if code == d.OK:
        if tag == "1":
            gamelists_dialog("Genre")
        elif tag == "2":
            gamelists_dialog("Realign")
        elif tag == "3":
            clear_recently_added_collection()

    if code == d.CANCEL:
        cls()
        main_dialog()

    return


def gamelist_utilities_dialog():
    code, tag = d.menu("Main Menu", 
                    choices=[("1", "Check/Clean Game List Utilities"), 
                             ("2", "Genre Utilities"), 
                             ("3", "Sort Game Lists"), 
                             ("4", "Check/Clean Emulators Config Utilities"), 
                             ("5", "Count of Games")],
                    title="Gamelist (Etc) Utilities")
    
    if code == d.OK:
        if tag == "1":
            check_clean_utilities_dialog()
        elif tag == "2":
            genre_utilities_dialog()
        elif tag == "3":
            gamelists_dialog("Sort")
        elif tag == "4":
            check_clean_emulators_dialog()
        elif tag == "5":
            gamelists_dialog("Count")

    if code == d.CANCEL:
        cls()
        main_dialog()

    cls()
    gamelist_utilities_dialog()

    return


def get_zip_files(path: str):
    files = []
    if os.path.isfile(path) == True:
        if os.path.splitext(path)[1] == ".zip":
            files.append(path)

    if os.path.isdir(path):
        for file in os.listdir(path):
            if os.path.splitext(file)[1] == ".zip":
                files.append(os.path.join(path, file))

    return files


def get_manual_updates(path: str, available_updates: list, good=True):
    manual_updates = []
    files = get_zip_files(path)
    base_path = os.path.dirname(path) + "/"

    files.sort()
    for update in available_updates:
        if base_path + update[0] in files:
            index = files.index(base_path + update[0])
            if (os.path.getsize(files[index]) == update[4]) == good:
                manual_updates.append(update)

    return manual_updates


def clean_unofficial_roms(selected_items: list):
    file_time = datetime.datetime.utcnow()
    log_file = f"/home/pi/.update_tool/gamelist_logs/clean_unofficial_roms-{file_time.strftime('%Y%m%d-%H%M%S')}.log"
    systems = []
    if len(selected_items) > 0:
        log_this(log_file, "CLEANING UNOFFICIAL ROMS:", overwrite=True)
        for selected_item in selected_items:
            system = selected_item[0]
            rom = selected_item[1]
            name = selected_item[2]

            if selected_item[0] == None or selected_item[1] == None or selected_item[2] == None:
                continue

            log_this(log_file, f"-[{system}]\t{name}\t({rom})")
            if system not in systems:
                systems.append(system)

        log_this(log_file, "")
        log_this(log_file, "\nSYSTEMS CLEANED:")
        systems.sort()
        for system in systems:
            log_this(log_file, f"-{system}")
        log_this(log_file, "")
        log_this(log_file, "")

        do_process_gamelists(systems, del_roms=True, del_art=True, del_snaps=True, del_m3u=True, clean=True, log_file=log_file, auto_clean=True)
    
    return


def auto_clean_gamelists(installed_updates: list, manual=False, official=True):
    if len(installed_updates) > 0:
        systems = get_all_systems_from_cfg()
        type = "" if manual == False else "MANUAL "

        file_time = datetime.datetime.utcnow()

        if not os.path.exists("/home/pi/.update_tool/gamelist_logs"):
            os.mkdir("/home/pi/.update_tool/gamelist_logs")

        log_file = f"/home/pi/.update_tool/gamelist_logs/auto_clean_gamelists-{file_time.strftime('%Y%m%d-%H%M%S')}.log"
        log_this(log_file, f"AUTO CLEANING {'' if official else 'UNOFFICIAL'}{type}UPDATES INSTALLED:")
        for installed_update in installed_updates:
            log_this(log_file, f"-{installed_update}")
        log_this(log_file, "")
        log_this(log_file, "")

        do_process_gamelists(systems, del_roms=True, del_art=True, del_snaps=True, del_m3u=True, clean=True, log_file=log_file, auto_clean=True)
    
    return
    

def clear_recently_added_collection():
    if d.yesno(text="Are you sure you want to clear the Recent Additions collection?") == d.OK:
        runcmd("cat /dev/null > /opt/retropie/configs/all/emulationstation/collections/custom-zzz-recent.cfg")
    
    return


def process_unofficial_manual_updates(path: str, updates: list, delete=False, auto_clean=False):
    cls()
    start_time = datetime.datetime.utcnow()
    extracted = Path("/", "tmp", "extracted")
    log_file = "/home/pi/.update_tool/process_manual_updates.log"

    installed_updates = []
    for update in updates:
        if os.path.isdir(path):
            file = os.path.join(path, update)
            if not os.path.isfile(file):
                log_this(log_file, "Filename " + file + " can't be located, search for same filename without double spaces")
                file = re.sub(' +', ' ', file)
        else:
            # singular file selected so no need to add filename again
            file = path
        if not os.path.isfile(file):
            log_this(log_file, "Filename " + file + " can't be located, skip update for this")
        else:
            print(f"Now preparing unoffical update {os.path.basename(update)}")
            if validate_unofficial_update(update):
                if process_improvement(file, extracted, auto_clean=True, official=False) == True:
                    if delete == True:
                        os.remove(file)

            installed_updates.append(update)

    if auto_clean == True:
        auto_clean_gamelists(installed_updates, manual=True, official=False)
        #do_clean_emulators_cfg(check=False, auto_clean=True)
        do_genre_realignment(get_all_systems_from_cfg(), True)
        clean_recent("/opt/retropie/configs/all/emulationstation/collections/custom-zzz-recent.cfg")

    d.msgbox(f"{len(installed_updates)} of {len(updates)} selected unofficial manual updates installed.\n\nTotal time to process: {str(datetime.datetime.utcnow() - start_time)[:-7]}")
    reboot_msg = "\nReboot required for these changes to take effect. Rebooting now.!\n"
    reboot_dialog(reboot_msg)

    return

def process_manual_updates(path: str, updates: list, delete=False, auto_clean=False):
    cls()
    start_time = datetime.datetime.utcnow()
    extracted = Path("/", "tmp", "extracted")
    log_file = "/home/pi/.update_tool/process_manual_updates.log"

    installed_updates = []
    for update in updates:
        if os.path.isdir(path):
            file = os.path.join(path, update[0])
            if not os.path.isfile(file):
                log_this(log_file, "Filename " + file + " can't be located, search for same filename without double spaces")
                file = re.sub(' +', ' ', file)
        else:
            # singular file selected so no need to add filename again
            file = path
        if not os.path.isfile(file):
            log_this(log_file, "Filename " + file + " can't be located, skip update for this")
        elif process_improvement(file, extracted) == True:
            if delete == True:
                os.remove(file)

            set_mega_config_value("INSTALLED_UPDATES", update[0], str(update[2]))
            installed_updates.append(update[0])

    if auto_clean == True:
        auto_clean_gamelists(installed_updates, manual=True)
        do_clean_emulators_cfg(check=False, auto_clean=True)
        do_genre_realignment(get_all_systems_from_cfg(), True)
        clean_recent("/opt/retropie/configs/all/emulationstation/collections/custom-zzz-recent.cfg")

#    if os.path.isdir(path):
#        if delete == True:
#            if len(os.listdir(path)) == 0:
#                shutil.rmtree(path)

    d.msgbox(f"{len(installed_updates)} of {len(updates)} selected manual updates installed.\n\nTotal time to process: {str(datetime.datetime.utcnow() - start_time)[:-7]}")
    reboot_msg = "\nReboot required for these changes to take effect. Rebooting now.!\n"
    reboot_dialog(reboot_msg)

    return


def get_valid_path_portion(path: str):
    return_path = "/"
    parts = path.split("/")
    for part in parts:
        if len(part) > 0:
            if os.path.isdir(os.path.join(return_path, part)) == True:
                return_path = os.path.join(return_path, part)

    #will add the trailing slash if it's not already there.
    return_path = os.path.join(return_path, '')

    return return_path


def manual_updates_dialog(init_path: str, delete: bool, official=True):
    path = None
    help_text = ("Type the path to directory or file directly into the text entry window."
                  "\nAs you type the directory or file will be highlighted, at this point you can press [Space] to add the highlighted item to the path."
                  "\n\nIf you are adding a directory to the text entry window, and the path ends with a \"/\", the files in that directory will automatically show in the \"Files\" window."
                  "\nYou can use also cycle through the windows with [Tab] or [Arrow] keys.")
    code, path = d.fselect(init_path, height=10, width=60, help_button=True)

    if code == d.OK:
        keep_moving = True
        if not official:
            official_update_dir = get_config_value("CONFIG_ITEMS", "update_dir")
            keep_moving = not (path == official_update_dir)
        if keep_moving and (os.path.isdir(path) or os.path.isfile(path)):
            if official:
                set_config_value("CONFIG_ITEMS", "update_dir", get_valid_path_portion(path))
            else:
                set_config_value("CONFIG_ITEMS", "unofficial_update_dir", get_valid_path_portion(path))
            #official_improvements_dialog(path, delete)
        else:
            d.msgbox("Invalid path " + path)
            path = get_valid_path_portion(path)
            path = "/" if len(path) == 0 else path
            d.msgbox("Path is now set to " + path)
            cls()
            manual_updates_dialog(path, delete, official)
    elif code == d.HELP:
        d.msgbox(help_text)
        path = get_valid_path_portion(path)
        path = "/" if len(path) == 0 else path
        cls()
        manual_updates_dialog(path, delete, official)
    elif code == d.CANCEL:
        cls()
        main_dialog()

    return path


def get_default_update_dir(official=True):
    if os.path.exists(tool_ini):
        if official:
            update_dir = get_config_value("CONFIG_ITEMS", "update_dir")
        else:
            update_dir = get_config_value("CONFIG_ITEMS", "unofficial_update_dir")
        if update_dir is not None and os.path.exists(update_dir):
            if update_dir[-1] != "/":
                update_dir = update_dir + "/"
            return update_dir
        else:
            if update_dir is not None:
                d.msgbox("Invalid saved update_dir " + update_dir + ", resetting to /")                

    return "/"


def downloaded_update_question_dialog(official=True):
    message_text = ("You will be asked to choose a .zip file to load, or a directory where multiple .zip files are located."
                    "\nThis will process the .zip file(s)?"
                    "\n\nIf the name of a .zip file is identified as a valid official update, it will be processed as an official update package.")
    if not official:
        message_text = ("You are now processing unofficial updates, these files will be processed in a manner that prioritizes the official build image."
                        "\nYou will not overwrite official roms and assets.")
                        
    code = d.yesno(text=message_text + "\n\nSelecting \"Keep\" will keep the .zip files once the process is complete."
                        "\nSelecting \"Delete\" will delete the .zip files once the process is complete."
                        "\n\nWould you like to remove .zip files?", yes_label="Keep", no_label="Delete")

    return code


def check_update_status_dialog(available_updates=[]):
    megadrive = check_drive()
    check_wrong_permissions()

    if len(available_updates) == 0:
        available_updates = get_available_updates(megadrive, status=True)

    if len(available_updates) == 0:
        d.msgbox("No updates available.")
        return

    available_updates = sort_official_updates(available_updates)

    if len(available_updates) == 0:
        d.msgbox("There are 0 available updates!")
        return

    show_all_updates = (get_config_value("CONFIG_ITEMS", "show_all_updates") == "True")
    extra_label = "Show All" if show_all_updates == False else "Show Needed"

    updates_status = ""
    all_updates = []
    update_needed = False
    needed_updates = []
    recommended_updates = []
    for update in available_updates:
        update_applied = is_update_applied(update[0], update[2])
        if update_applied == False:
            needed_updates.append(update)
        update_needed = (update_needed == True or update_applied == False)
        if update_needed == True:
            recommended_updates.append(update)
        if show_all_updates == True or update_needed == True:
            #TO DO: check if update has been installed from config and make True
            all_updates.append(update)
            if len(updates_status) > 0:
                updates_status += "\n"

            update_status = "NEEDED"
            if update_applied == True:
                update_status = "applied"
                if update_needed == True:
                    update_status = "recommended"
            
            updates_status += f"{update[0]} ({update[3]}) [{update_status}]"

    if len(all_updates) == 0:
        set_config_value("CONFIG_ITEMS", "show_all_updates", "True")
        d.msgbox("No updates are needed.")
        check_update_status_dialog(available_updates=available_updates)
        return

    update_totals = f"Show All Updates is {'on' if show_all_updates == True else 'off'}\n\nNumber of available updates: {len(available_updates)} ({get_total_size_of_updates(available_updates)})\nNumber of updates needed: {len(needed_updates)} ({get_total_size_of_updates(needed_updates)})\nRecommended number of updates: {len(recommended_updates)} ({get_total_size_of_updates(recommended_updates)})\n\n"
    code = d.msgbox(update_totals + updates_status, title="Update Status", extra_button=True, extra_label=extra_label)

    if code == d.EXTRA:
        set_config_value("CONFIG_ITEMS", "show_all_updates", str(not show_all_updates))
        check_update_status_dialog(available_updates=available_updates)
        return

    return


def space_warning():
    d.msgbox(
        'Content can only be added if you have adequate storage space.' +
        '\n\nBe sure you have enough space before proceeding with updates.' +
        '\n\nYou MUST keep some space free for correct operation of your system.' +
        '\n\nCurrent free disk space on your root filesystem is' +
        runcmd("df -h --output=avail / | tail -1"), 11, 72)
    
    return


def validate_manual_updates():
    dlg_text = ""

    valid_list = []
    invalid_list = []

    megadrive = check_drive()

    update_dir = get_valid_path_portion(get_default_update_dir())
    update_dir = manual_updates_dialog(update_dir, False)
    update_dir = get_config_value("CONFIG_ITEMS", "update_dir")

    available_updates = get_available_updates(megadrive, status=True)
    if len(available_updates) == 0:
        d.msgbox("No available updates!")
        return

    if update_dir is None:
        d.msgbox("No update directory!")
        return
    
    valid_updates = get_manual_updates(update_dir, available_updates, good=True)
    invalid_updates = get_manual_updates(update_dir, available_updates, good=False)
    valid_updates = sort_official_updates(valid_updates)
    invalid_updates = sort_official_updates(invalid_updates)

    all_files = get_zip_files(update_dir)
    if len(all_files) == 0:
        d.msgbox("No files in dirctory!")
        return

    for update in valid_updates:
        full_path = os.path.join(update_dir, update[0])
        if full_path in all_files:
            valid_list.append(update[0])
            index = all_files.index(full_path)
            del all_files[index]
    for update in invalid_updates:
        full_path = os.path.join(update_dir, update[0])
        if full_path in all_files:
            invalid_list.append(update[0])
            index = all_files.index(full_path)
            del all_files[index]

    dlg_text += f"Total Files: {len(valid_list) + len(invalid_list) + len(all_files)}\n"
    dlg_text += f"Valid Files: {len(valid_list)}\n"
    dlg_text += "\n"
    dlg_text += f"Invalid File Sizes: {len(invalid_list)}\n"
    dlg_text += f"Invalid File Names: {len(all_files)}\n"
    dlg_text += "\n\n"

    if len(invalid_list) > 0:
        dlg_text += "*****************\nInvalid File Size\n*****************\n"
        for item in invalid_list:
            dlg_text += item + "\n"
        dlg_text += "\n"

    if len(all_files) > 0:
        all_files.sort()
        dlg_text += "*****************\nInvalid File Name\n*****************\n"
        for item in all_files:
            dlg_text += os.path.basename(item) + "\n"
        dlg_text += "\n"

    if len(valid_list) > 0:
        dlg_text += "***********\nValid Files\n***********\n"
        for item in valid_list:
            dlg_text += item + "\n"
        dlg_text += "\n"
        
    d.msgbox(dlg_text, title=f"Results From {update_dir}")

    return


def improvements_dialog():
    code, tag = d.menu("Select Option", 
                    choices=[("1", "Download and Install Updates"),
                             ("2", "Manually Install Downloaded Updates"), 
                             ("3", "Manually Install Downloaded Unofficial Updates"), 
                             ("4", "Package Unofficial Update"), 
                             ("5", "Update Status"), 
                             ("6", "Validate Downloaded Updates"), 
                             ("7", "Manual Updates Story")],
                    title="Improvements")

    if code == d.OK:
        if tag == "1":
            if not check_internet():
                d.msgbox("You need to be connected to the internet for this.")
                improvements_dialog()
            else:
                space_warning()
                official_improvements_dialog()
        elif tag == "2":
            space_warning()
            update_dir = get_default_update_dir()
            update_dir = get_valid_path_portion(update_dir)
            code = downloaded_update_question_dialog()
            update_dir = manual_updates_dialog(update_dir, delete=False if code == d.OK else True, official=True)
            if update_dir is not None:
                official_improvements_dialog(update_dir, delete=False if code == d.OK else True)
        elif tag == "3":
            update_dir = get_default_update_dir(official=False)
            update_dir = get_valid_path_portion(update_dir)
            code = downloaded_update_question_dialog(official=False)
            update_dir = manual_updates_dialog(update_dir, False, official=False)
            if update_dir is not None:
                unofficial_improvements_dialog(update_dir=update_dir, delete=False if code == d.OK else True)
        elif tag == "4":
            systems = None
            systems = gamelists_dialog("Package")
            if systems is not None:
                selected_items = unofficial_update_dialog(systems, "Package Unofficial Update")
                if len(selected_items) > 0:
                    name = package_unofficial_update_name_dialog()
                    if name is not None and len(name) > 0:
                        do_process_unofficial_package(selected_items, name)
        elif tag == "5":
            check_update_status_dialog()
        elif tag == "6":
            validate_manual_updates()
        elif tag == "7":
            get_manual_updates_story()

        cls()
        improvements_dialog()

    return


def misc_menu():
    code, tag = d.menu("Select Option",
                    choices=[("1", "Gamelist (Etc) Utilities"), 
                             ("2", "System Overlays"),
                             ("3", "Handheld Mode"),
                             ("4", "Reset Permissions")],
                    title="System Tools and Utilities")

    if code == d.OK:
        if tag == "1":
            gamelist_utilities_dialog()
        elif tag == "2":
            if not check_internet():
                d.msgbox("You need to be connected to the internet for this.")
                misc_menu()
            else:
                overlays_dialog()
        elif tag == "3":
            if not check_internet():
                d.msgbox("You need to be connected to the internet for this.")
                misc_menu()
            else:
                handheld_dialog()
        elif tag == "4":
            fix_permissions()

        cls()
        misc_menu()

    return


def support_dialog():
    d.msgbox("Rick Dangerous's Discord server is https://discord.gg/H3FdEanPmv"
             "\n\nThe Insanium Update Guide channel can be found here"
             "\n\nhttps://discord.com/channels/857515631422603286/1059484786302922842"
             "\n\nDocumentation for this Update Tool can be found here"
             "\n\nhttps://github.com/h3xp/RickDangerousUpdate"
             "\n\nPlease use Google Lens to grab these links to avoid typing mistakes.")

    return


def settings_dialog():
    if not os.path.exists(tool_ini):
        d.msgbox("Tool is not installed, you can not set configurations!")
        return

    update_notification = get_config_value('CONFIG_ITEMS', 'display_notification', return_none=False)
    auto_clean = get_config_value('CONFIG_ITEMS', 'auto_clean', return_none=False)
    count_official_only = get_config_value('CONFIG_ITEMS', 'count_official_only', return_none=False)

    code, tag = d.radiolist("Choose which notification method you want to use",
                choices=[("Select Update Notification", update_notification, True),
                            ("Toggle Auto Clean", auto_clean, False),
                            ("Toggle Count Official Only", count_official_only, False)],
                title="Settings")

    if code == d.OK:
        if tag == "Select Update Notification":
            select_notification()
        elif tag == "Toggle Auto Clean":
            toggle_autoclean()
        elif tag == "Toggle Count Official Only":
            toggle_countofficialonly()

        cls()
        #settings_dialog()

    return


def main_dialog():
    global update_available_result
    if update_available_result == "no connection":
        update_available_result = update_available()

    code, tag = d.menu("Main Menu", 
                    choices=[("1", "Improvements"),    
                             ("2", "System Tools and Utilities"),
                             ("3", "Installation"),
                             ("4", "Settings"), 
                             ("5", "Support")],
                             
                    title=check_update(),
                    backtitle="Rick Dangerous Update Tool",
                    cancel_label=" Exit ")
    
    if code == d.OK:
        if tag == "1":
            # official_improvements_dialog() is for always forcing downloading
            # improvements_dialog() is for allowing manual side loadinbg
            #official_improvements_dialog()
            improvements_dialog()
        elif tag == "2":
            misc_menu()
        elif tag == "3":
            if not check_internet():
                d.msgbox("You need to be connected to the internet for this.")
                main_dialog()
            else:
                installation_dialog()
        elif tag == "4":
            settings_dialog()
        elif tag == "5":
            support_dialog()
    if code == d.CANCEL:
        cls()
        exit(0)

    main_dialog()

    return


def check_drive():
    if os.environ.get('RickDangerousUpdateTests') is not None:
       return "https://mega.nz/folder/tQpwhD7a#WA1sJBgOKJzQ4ybG4ozezQ"
    else:
        if os.path.exists(tool_ini):
            config = configparser.ConfigParser()
            config.read(tool_ini)
            if config.has_option("CONFIG_ITEMS", "mega_dir"):
                return config["CONFIG_ITEMS"]["mega_dir"]

        if len(sys.argv) > 1:
            #pattern = re.compile("^https://mega\.nz/((folder|file)/([^#]+)#(.+)|#(F?)!([^!]+)!(.+))$")
            #if pattern.match(str(sys.argv[1])):
            if is_valid_mega_link(str(sys.argv[1])):
                return str(sys.argv[1])

        print("You didnt provide a link to the mega drive.")
        exit(1)


def check_root(directory):
    for files in os.listdir(directory):
        if os.path.exists(directory / "etc" / "emulationstation"):
            return True
        #if os.path.exists(directory / "opt" / "retropie" / "libretrocores"):
        #    return True
        
    return False


def sort_official_updates(updates: list):
    dict_updates = {}
    retval = []

    for update in updates:
        segments = update[0].split(" ")
        for segment in segments:
            if segment.isdigit():
                dict_updates[int(segment)] = update
                break

    for dict_update in sorted(dict_updates.keys()):
        retval.append(dict_updates[dict_update])

    return retval


def get_total_size_of_unofficial_updates(updates: list):
    total_size = 0

    for update in updates:
        if os.path.isfile(update):
            total_size += os.path.getsize(update)

    return convert_filesize(str(total_size))


def get_total_size_of_updates(updates: list):
    total_size = 0

    for update in updates:
        total_size += int(update[4])

    return convert_filesize(str(total_size))


def unofficial_improvements_dialog(update_dir=None, delete=False, available_updates=[], process_improvements=True):
    selected_updates = []
    title_msg  = "Manually Install Unofficial Updates"
    if len(available_updates) == 0:
        available_updates = get_zip_files(update_dir)

    if len(available_updates) == 0:
        d.msgbox("No unofficial updates available.")
        return

    available_updates.sort()

    auto_clean = get_config_value("CONFIG_ITEMS", "auto_clean")
    auto_clean = False if auto_clean is None else auto_clean == "True"

    menu_choices = []
    for update in available_updates:
        menu_choices.append((f"{os.path.basename(update)} ({get_total_size_of_unofficial_updates([update])})", "", False))

    code, tags = d.checklist(text=f"Auto Clean is {'on' if auto_clean == True else 'off'}\n\n\nNumber of available updates: {len(available_updates)} ({get_total_size_of_unofficial_updates(available_updates)})\n\nAvailable Updates",
                             choices=menu_choices,
                             ok_label="Apply Selected", 
                             extra_button=True, 
                             extra_label="Apply All", 
                             title=title_msg)

    if code == d.OK:
        for tag in tags:
            for update in available_updates:
                if f"{os.path.basename(update)} ({get_total_size_of_unofficial_updates([update])})" == tag:
                    selected_updates.append(update)
                    break        
    if code == d.EXTRA:
        selected_updates = available_updates
    
    if len(selected_updates) > 0:
        process_unofficial_manual_updates(update_dir, selected_updates, delete=delete, auto_clean=auto_clean)

    return


def official_improvements_dialog(update_dir=None, delete=False, available_updates=[], process_improvements=True):
    megadrive = check_drive()
    check_wrong_permissions()

    reboot_msg = "Updates installed:"
    title_msg  = "Download and Install Official Updates"
    if update_dir is not None:
        title_msg  = "Manually Install Official Updates"
    if process_improvements == False:
        title_msg  = "Generate Manual Updates Story"

    if len(available_updates) == 0:
        available_updates = get_available_updates(megadrive, status=True)
        if update_dir is not None:
            available_updates = get_manual_updates(update_dir, available_updates)

    if len(available_updates) == 0:
        d.msgbox("No updates available.")
        return
        #cls()
        #main_dialog()
        
    #available_updates.sort()
    available_updates = sort_official_updates(available_updates)

    if len(available_updates) == 0:
        d.msgbox("There are 0 available updates!")
        return

    auto_clean = get_config_value("CONFIG_ITEMS", "auto_clean")
    auto_clean = False if auto_clean is None else auto_clean == "True"

    show_all_updates = get_config_value("CONFIG_ITEMS", "show_all_updates")
    if show_all_updates == None:
        set_config_value("CONFIG_ITEMS", "show_all_updates", "True")
        show_all_updates = True
    show_all_updates = (show_all_updates == "True")
    help_label = "Show All" if show_all_updates == False else "Show Needed"

    menu_choices = []
    all_updates = []
    update_needed = False
    needed_updates = []
    recommended_updates = []
    for update in available_updates:
        update_applied = is_update_applied(update[0], update[2])
        if update_applied == False:
            needed_updates.append(update)
        update_needed = (update_needed == True or update_applied == False)
        if update_needed == True:
            recommended_updates.append(update)
        if show_all_updates == True or update_needed == True:
            #TO DO: check if update has been installed from config and make True
            all_updates.append(update)
            menu_choices.append((f"{update[0]} ({update[3]})", "", not update_applied))

    if len(all_updates) == 0:
        set_config_value("CONFIG_ITEMS", "show_all_updates", "True")
        d.msgbox("No updates are needed.")
        official_improvements_dialog(update_dir, delete, available_updates)
        return

    update_text = "Available" if show_all_updates == True else "Recommended"
    code, tags = d.checklist(text=f"Auto Clean is {'on' if auto_clean == True else 'off'}\nShow All Updates is {'on' if show_all_updates == True else 'off'}\n\nNumber of available updates: {len(available_updates)} ({get_total_size_of_updates(available_updates)})\nNumber of updates needed: {len(needed_updates)} ({get_total_size_of_updates(needed_updates)})\nRecommended number of updates: {len(recommended_updates)} ({get_total_size_of_updates(recommended_updates)})\n\n{update_text} Updates",
                             choices=menu_choices,
                             ok_label="Apply Selected", 
                             extra_button=True, 
                             extra_label="Apply All", 
                             help_button=True, 
                             help_label=help_label, 
                             title=title_msg)

    selected_updates = []
    if code == d.OK:
        for tag in tags:
            for update in available_updates:
                if f"{update[0]} ({update[3]})" == tag:
                    reboot_msg += "\n" + tag
                    selected_updates.append(update)
                    break

    if code == d.EXTRA:
        if process_improvements == True:
            if d.yesno(text="Are you sure you want to apply all available updates?") == d.OK:
                selected_updates = all_updates
        else:
            selected_updates = all_updates

    if code == d.CANCEL:
        selected_updates = []
        return

    if code == d.HELP:
        set_config_value("CONFIG_ITEMS", "show_all_updates", str(not show_all_updates))
        official_improvements_dialog(update_dir, delete, available_updates)
        return

    if len(selected_updates) == 0:
        d.msgbox("No updates selected!")
        official_improvements_dialog(update_dir, delete, available_updates)
    else:
        if process_improvements == False:
            return selected_updates

        print()
        if update_dir is None:
            do_improvements(selected_updates, megadrive, auto_clean=auto_clean)
        else:
            process_manual_updates(update_dir, selected_updates, delete, auto_clean=auto_clean)
        #reboot_msg += "\n\n" + "Rebooting in 5 seconds!"

    return


def update_config(extracted: str):
    tmp_config = Path(extracted, "home", "pi", ".update_tool", "update_tool.ini")
    if not os.path.exists(tmp_config):
        return
    if not os.path.exists(tool_ini):
        return

    new_config = configparser.ConfigParser()
    new_config.optionxform = str
    config = configparser.ConfigParser()
    config.optionxform = str

    new_config.read(tmp_config)
    config.read(tool_ini)

    for section in new_config.sections():
        if len(new_config[section]) > 0:
            if config.has_section(section):
                config.remove_section(section)

            config.add_section(section)
            for key in new_config[section]:
                config[section][key] = str(new_config[section][key]).strip()

    with open(tool_ini, 'w') as configfile:
        config.write(configfile)

    os.remove(tmp_config)

    return


def validate_unofficial_update(update):
    with zipfile.ZipFile(update, 'r') as zip_ref:
        for file_listing in zip_ref.infolist():
            file = "/" + file_listing.filename
            if os.path.isdir(file):
                continue
            if "/home/pi/RetroPie/roms" not in file:
                return False

    return True


def is_unofficial_media_official(system: str, media: str, tag: str, media_dir: str):
    rickdangerous_file = f"/home/pi/RetroPie/roms/{system}/.RickDangerous"
    gamelist = f"/home/pi/RetroPie/roms/{system}/gamelist.xml"
    official_roms = []

    if not os.path.isfile(gamelist):
        return False

    if os.path.isfile(rickdangerous_file):
        with open(rickdangerous_file, 'r') as file:
            official_roms = file.readlines()

    src_tree = ET.parse(gamelist)
    src_root = src_tree.getroot()

    parents = src_tree.findall(f".//game[{tag}=\"./{media_dir}/{media}\"]")
    for parent in parents:
        rom_file = ""
        # get rom file
        src_node = parent.find("path")
        if src_node is not None:
            if src_node.text is not None:
                rom_file = os.path.basename(src_node.text)        
                # check if rom is in official roms
                if "./" + rom_file + "\n" in official_roms:
                    return True
                
    return False


def prepare_unofficial_update(directory):
    roms_dir = "/home/pi/RetroPie/roms/"
    tmp_roms_dir = str(directory) + roms_dir
    bad_roms = []
    all_files = []
    no_m3u_support = ["atari800"]

    print("Preparing...")
    
    for file in directory.glob('**/*'):
        if os.path.isfile(str(file)) and "/home/pi/RetroPie/roms/" in str(file):
            if not os.path.basename(file) == "gamelist.xml":
                all_files.append(str(file))

    #for system in no_m3u_support:
    #    data_dir = f"/home/pi/RetroPie/roms/{system}/.data/"
    #    indices = [position for position, phrase in enumerate(all_files) if data_dir in phrase]
    #    indices.sort(reverse=True)
    #    for index in indices:
    #        del all_files[index]

    # check if gamelist.xml has been updated
    for gamelist in Path(directory).rglob('gamelist.xml'):
        system = ""
        offical_roms = []
        parts = str(gamelist).split("/")
        if len(parts) > 1:
            system = parts[len(parts) - 2]

        if len(system) == 0:
            continue

        rickdangerous_file = f"{roms_dir}/{system}/.RickDangerous"
        if os.path.isfile(rickdangerous_file):
            with open(rickdangerous_file, 'r') as file:
                official_roms = file.readlines()

        src_tree = ET.parse(gamelist)
        src_root = src_tree.getroot()

        for src_game in src_root.iter("game"):
            rom_file = ""
            img_file = ""
            snap_file = ""

            # get rom file
            src_node = src_game.find("path")
            if src_node is not None:
                if src_node.text is not None:
                    rom_file = os.path.basename(src_node.text)
                    # keep rom files
                    tmp_rom_file = str(directory) + src_node.text.replace("./", roms_dir + system + "/")
                    if tmp_rom_file in all_files:
                        all_files.remove(tmp_rom_file)
                    # deal with .cue files
                    if os.path.splitext(tmp_rom_file)[1] == ".cue":
                        cue_files = parse_cue_file(tmp_rom_file)
                        for cue_file in cue_files:
                            if cue_file in all_files:
                                all_files.remove(cue_file)
                    # deal with .m3u files
                    if os.path.splitext(tmp_rom_file)[1] == ".m3u":
                        m3u_files = get_recursive_m3u_files(tmp_rom_file, os.path.dirname(tmp_rom_file))
                        for m3u_file in m3u_files:
                            if m3u_file in all_files:
                                all_files.remove(m3u_file)
                    # deal with no m3u support
                    if system in no_m3u_support:
                        tmp_data_dir = os.path.dirname(str(directory) + src_node.text.replace("./", roms_dir + system + "/")) + "/.data/" + str(Path(rom_file).with_suffix(""))
                        if os.path.isdir(tmp_data_dir):
                            for file in os.scandir(tmp_data_dir):
                                if os.path.isfile(file.path):
                                    if file.path in all_files:
                                        all_files.remove(file.path)
                        tmp_data_file = os.path.dirname(str(directory) + src_node.text.replace("./", roms_dir + system + "/")) + "/.multidisk/" + str(Path(rom_file).with_suffix(""))
                        if os.path.isfile(str(tmp_data_file)):
                            if str(tmp_data_file) in all_files:
                                all_files.remove(str(tmp_data_file))
                    #tmp_data_dir = os.path.dirname(str(directory) + src_node.text.replace("./", roms_dir + system + "/")) + "/.data/" + str(Path(rom_file).with_suffix(""))
            # get img file
            src_node = src_game.find("image")
            if src_node is not None:
                if src_node.text is not None:
                    img_file = os.path.basename(src_node.text)
                    # keep img files
                    tmp_img_file = str(directory) + src_node.text.replace("./", roms_dir + system + "/")
                    if tmp_img_file in all_files:
                        all_files.remove(tmp_img_file)
            # get snap file
            src_node = src_game.find("video")
            if src_node is not None:
                if src_node.text is not None:
                    snap_file = os.path.basename(src_node.text)
                    # keep snap files
                    tmp_snap_file = str(directory) + src_node.text.replace("./", roms_dir + system + "/")
                    if tmp_snap_file in all_files:
                        all_files.remove(tmp_snap_file)

            # check if rom is in official roms
            if "./" + rom_file + "\n" in official_roms:
                bad_roms.append([tmp_rom_file, tmp_img_file, tmp_snap_file])

        # remove entry that shouldn't be there
        for rom in bad_roms:
            rom_file = rom[0]
            img_file = rom[1]
            snap_file = rom[2]
            m3u_files = []

            print(f"removing \"offical\" rom {rom}")
            parents = src_tree.findall(f".//game[path=\"./{rom_file}\"]")
            for parent in parents:
                src_root.remove(parent)

            # remove rom file
            #file = f"{directory}/{roms_dir}/{system}/{rom_file}"
            #file = file.replace("//", "/")
            if os.path.isfile(rom_file):
                # deal with .cue files
                if os.path.splitext(rom_file)[1] == ".cue":
                    cue_files = parse_cue_file(rom_file)
                    for cue_file in cue_files:
                        if os.path.isfile(cue_file):
                            os.remove(cue_file)
                # deal with .m3u files
                if os.path.splitext(rom_file)[1] == ".m3u":
                    m3u_files = get_recursive_m3u_files(rom_file, os.path.dirname(rom_file))
                    for m3u_file in m3u_files:
                        if os.path.isfile(m3u_file):
                            os.remove(m3u_file)
                os.remove(rom_file)
            # remove img file
            #file = f"{directory}/{roms_dir}/{system}/boxart/{img_file}"
            #file = file.replace("//", "/")
            if os.path.isfile(img_file):
                os.remove(img_file)
            # remove snaps file
            file = f"{directory}/{roms_dir}/{system}/snaps/{rom_file}"
            file = file.replace("//", "/")
            if os.path.isfile(snap_file):
                os.remove(snap_file)
            
        with open(gamelist, "wb") as file:
            src_tree.write(file, "utf-8")

        # kill all files that are not referenced in the gamelist.xml file
        for file in all_files:
            os.remove(file)

        # we will check all remaining image/video files...
        # check img files
        for img_file in os.listdir(os.path.dirname(str(gamelist)) + "/boxart"):
            if is_unofficial_media_official(system, os.path.basename(img_file), "image", "boxart"):
                os.remove(os.path.dirname(str(gamelist)) + "/boxart/" + img_file)
        # check snap files
        for snap_file in os.listdir(os.path.dirname(str(gamelist)) + "/snaps"):
            if is_unofficial_media_official(system, os.path.basename(snap_file), "video", "snaps"):
                os.remove(os.path.dirname(str(gamelist)) + "/snaps/" + snap_file)

    return


def extract_zipfile(zip_file:str, dir_name: str):
    start_time = datetime.datetime.utcnow()
    total_size = 0
    last_size = 0
    current_size = 0

    with zipfile.ZipFile(zip_file, 'r') as zip_ref:
        total_size = sum([zinfo.file_size for zinfo in zip_ref.filelist])

    if os.path.isdir(dir_name):
        os.system(f"sudo rm -rf {dir_name} > /tmp/test")
        #shutil.rmtree(dir_name)
    os.mkdir(dir_name)
    proc = subprocess.Popen(["/usr/bin/unzip", "-q", zip_file, "-d", dir_name])

    while proc.poll() == None:
        result = subprocess.run(["/usr/bin/du", "-sb", dir_name], stdout=subprocess.PIPE)
        current_size = int(result.stdout.split()[0])
        status_bar(total_size, current_size, start_time)
        time.sleep(.5)
        
    if proc.returncode > 1:
        text = f"Error unzipping file: {zip_file}\n\nWould you like to continue processing and skip this fie?"
        code = d.yesno(text=text, ok_label="Continue")
        if code == d.OK:
            return False
        return None
        
    #pids = [pid for pid in os.listdir('/proc') if pid.isdigit()]
    #while str(pid) in pids:
    #    result = subprocess.run(["/usr/bin/du", "-sb", dir_name], stdout=subprocess.PIPE)
    #    current_size = int(result.stdout.split()[0])
    #    status_bar(total_size, current_size, start_time)
    #    time.sleep(.5)
    #    pids = [pid for pid in os.listdir('/proc') if pid.isdigit()]

    status_bar(total_size, current_size, start_time, complete=True)

    return True


def process_improvement(file: str, extracted: str, status=True, auto_clean=False, official=True):
    global update_being_processed
    update_being_processed = file
    
    print(f"Processing {'un' if not official else ''}official update: {os.path.basename(file)} ({convert_filesize(os.path.getsize(file))})...")
    print("Extracting...")
    zip_return = extract_zipfile(file, extracted)
    if zip_return == None:
        exit(1)
    elif zip_return == False:
        if os.path.exists(extracted) and os.path.isdir(extracted):
            try:
                shutil.rmtree(extracted)
            except OSError as e:
                print("Error: %s : %s" % (extracted, e.strerror))
        update_being_processed = "None"
        return False
    #with zipfile.ZipFile(file, 'r') as zip_ref:
    #    zip_ref.extractall(extracted)

    os.system(f"sudo chmod -R +w {str(extracted)} > /tmp/test")

    if official:
        if check_root(extracted):
            os.system(f"sudo chown -R pi:pi {str(extracted)} > /tmp/test")
            os.system("sudo chown -R pi:pi /etc/emulationstation/ > /tmp/test")
            #os.system("sudo chown -R pi:pi /opt/retropie/libretrocores/ > /tmp/test")
        os.system("sudo chown -R pi:pi /opt/retropie/ports/ > /tmp/test")
        update_config(extracted)
        make_deletions(extracted)
        execute_script(prepare_script(extracted, "read me pre-process!.txt"), file)
        post_process_script = prepare_script(extracted, "read me post-process!.txt")
        install_emulators(extracted)
    else:
        prepare_unofficial_update(extracted)
    merge_gamelist(extracted, official)
    if official:
        merge_emulators_cfg(extracted)
    print("Performing copy...")
    copydir(extracted, "/")
    if official:
        if check_root(extracted):
            os.system("sudo chown -R root:root /etc/emulationstation/")
        os.system("sudo chown -R root:root /opt/retropie/libretrocores/")
        os.system("sudo chown -R root:root /opt/retropie/ports/")
        execute_script(post_process_script, file)

    try:
        shutil.rmtree(extracted)
    except OSError as e:
        print("Error: %s : %s" % (extracted, e.strerror))
        update_being_processed = "None"
        return False

    update_being_processed = "None"
    return True


def do_unofficial_improvements(selected_updates: list, auto_clean=True):
    cls()
    start_time = datetime.datetime.utcnow()
    improvements_dir = Path("/", "tmp", "improvements")
    os.makedirs(improvements_dir, exist_ok=True)
    extracted = improvements_dir / "extracted"

    remove_improvements = True
    installed_updates = []

    for update in selected_updates:
        improvement_passed = process_improvement(update, extracted)

    return


def do_improvements(selected_updates: list, megadrive: str, auto_clean=False):
    cls()
    start_time = datetime.datetime.utcnow()
    improvements_dir = Path("/", "tmp", "improvements")
    os.makedirs(improvements_dir, exist_ok=True)
    extracted = improvements_dir / "extracted"

    remove_improvements = True
    installed_updates = []
#    selected_updates.sort(reverse=True)
#    selected_updates.sort()
    for update in selected_updates:
        file_path = download_update(update[1], improvements_dir, megadrive, update[3])

        if file_path is None:
            d.msgbox("Unable to download from MEGA.\n\nThis site enforces a 5GB per day download limit.\nThe limit is based on your public IP address.\nYou may have reached this limit.\n\nPlease try again later...", 10, 60)
            break

        improvement_passed = process_improvement(file_path, extracted)
        if improvement_passed == True:
            set_mega_config_value("INSTALLED_UPDATES", update[0], str(update[2]))
            installed_updates.append(update[0])
    
        remove_improvements = remove_improvements & improvement_passed
    
        if os.path.exists(extracted):
            if os.path.isdir(extracted):
                try:
                    shutil.rmtree(extracted)
                except OSError as e:
                    print("Error: %s : %s" % (extracted, e.strerror))

    if auto_clean == True:
        auto_clean_gamelists(installed_updates, manual=False)
        do_clean_emulators_cfg(check=False, auto_clean=True)
        do_genre_realignment(get_all_systems_from_cfg(), True)
        clean_recent("/opt/retropie/configs/all/emulationstation/collections/custom-zzz-recent.cfg")

    if remove_improvements == True:
        try:
            shutil.rmtree(improvements_dir)
        except OSError as e:
            print("Error: %s : %s" % (improvements_dir, e.strerror))
    
    d.msgbox(f"{len(installed_updates)} of {len(selected_updates)} selected updates installed.\n\nTotal time to process: {str(datetime.datetime.utcnow() - start_time)[:-7]}")
    if len(installed_updates) > 0:
        reboot_msg = "\nReboot required for these changes to take effect. Rebooting now.!\n"
        reboot_dialog(reboot_msg)
    else:
        main_dialog()

    return


def clean_comments(line: str):
    line = line.strip()
    while True:
        if line[0:1] == "#" or line[0:1] == " ":
            line = line[1:]
        else:
            line += "\n"
            return line
    line += "\n"

    return line


def do_system_overlay(system: str, enable_disable = "Enable"):
    path = "/opt/retropie/configs"

    system = os.path.join(path, system)
    if os.path.isdir(system):
        if os.path.isfile(os.path.join(system, "retroarch.cfg")):
            lines_out = ""
            with open(os.path.join(system, "retroarch.cfg"), 'r') as configfile:
                lines_in = configfile.readlines()
                for line in lines_in:
                    if "input_overlay" in line:
                        line = clean_comments(line)
                        if enable_disable == "Disable":
                            line = "#" + line

                    lines_out += line

            file_time = safe_write_backup(os.path.join(system, "retroarch.cfg"))

            with open(os.path.join(system, "retroarch.cfg"), 'w') as configfile:
                configfile.write(lines_out)

            safe_write_check(os.path.join(system, "retroarch.cfg"), file_time)

    return


def no_overlays_dialog(enable_disable = "Enable"):
    d.msgbox(f"There are no system overlays to {enable_disable.lower()}.")

    overlays_dialog()
    return


def single_overlay_dialog(enable_disable = "Enable"):
    menu_choices = []
    system_overlays = get_overlay_systems()

    for system in system_overlays[0]:
        if enable_disable == "Enable":
            if system not in system_overlays[1]:
                menu_choices.append((system, "", False))
        else:
            if system in system_overlays[1]:
                menu_choices.append((system, "", False))

    if len(menu_choices) == 0:
        no_overlays_dialog()

    code, tag = d.radiolist(text="Available Systems",
                             choices=menu_choices,
                             ok_label=f"{enable_disable} Selected")    

    if code == d.OK:
        do_system_overlay(tag, enable_disable)

    cls()
    overlays_dialog()

    return


def multiple_overlays_dialog(enable_disable = "Enable"):
    menu_choices = []
    system_overlays = get_overlay_systems()

    for system in system_overlays[0]:
        if enable_disable == "Enable":
            if system not in system_overlays[1]:
                menu_choices.append((system, "", False))
        else:
            if system in system_overlays[1]:
                menu_choices.append((system, "", False))        

    if len(menu_choices) == 0:
        no_overlays_dialog()

    code, tags = d.checklist(text="Available Systems",
                             choices=menu_choices,
                             ok_label=f"{enable_disable} Selected", 
                             extra_button=True, 
                             extra_label=f"{enable_disable} All")

    if code == d.OK:
        for system in tags:
            do_system_overlay(system, enable_disable)


    if code == d.EXTRA:
        for menu_choice in menu_choices:
            do_system_overlay(menu_choice[0], enable_disable)

    cls()
    overlays_dialog()
                
    return


def overlays_dialog():
    code, tag = d.menu("Sytem Overlays", 
                    choices=[("1", "Enable System Overlays"),
                             ("2", "Disable System Overlays")],
                    cancel_label=" Cancel ")
    
    if code == d.OK:
        if tag == "1":
            multiple_overlays_dialog("Enable")
        elif tag == "2":
            multiple_overlays_dialog("Disable")

    if code == d.CANCEL:
        cls()
        main_dialog()

    return


#def bugs_dialog():
#    code, tag = d.menu("Bugs Menu", 
#                    choices=[("1", "Fix permissions")], 
#                    title="Fix Known Bugs")
#    
#    if code == d.OK:
#        if tag == "1":
#            fix_permissions()
#
#    if code == d.CANCEL:
#        main_dialog()
#
#    return
#
#
#def restore_retroarch_dialog():
#    code = d.yesno(text="Are you sure you want to reset all retroarch.cfgs?")
#
#    if code == d.OK:
#        do_retroarch_configs()
#
#    if code == d.CANCEL:
#        main_dialog()
#
#    return
#
#
#def do_retroarch_configs():
#    localpath = Path("/", "tmp")
#    urllib.request.urlretrieve("https://raw.githubusercontent.com/h3xp/RickDangerousUpdate/main/configs/retroarch_configs.zip", localpath / "retroarch_configs.zip")
#    f = os.path.join(localpath, "retroarch_configs.zip")
#    if os.path.isfile(f):
#        with zipfile.ZipFile(f, 'r') as zip_ref:
#            zip_ref.extractall(localpath / "retroarch_configs")
#        copydir(localpath / "retroarch_configs/", "/opt/retropie/configs/")
#        try:
#            shutil.rmtree(localpath / "retroarch_configs")
#        except OSError as e:
#            print("Error: %s : %s" % (localpath / "retroarch_configs", e.strerror))
#        os.remove(localpath / "retroarch_configs.zip")
#
#    return
#
#
#def reset_controls_dialog():
#    code = d.yesno(text="Are you sure you want to reset your emulationstation configs?")
#
#    if code == d.OK:
#        do_retroarch_configs()
#
#    if code == d.CANCEL:
#        main_dialog()
#
#    return
#
#
#def do_emulationstation_configs():
#    localpath = Path("/", "tmp")
#    urllib.request.urlretrieve(
#        "https://raw.githubusercontent.com/h3xp/RickDangerousUpdate/main/configs/emulationstation_configs.zip",
#        localpath / "emulationstation_configs.zip")
#    f = os.path.join(localpath, "emulationstation_configs.zip")
#    if os.path.isfile(f):
#        with zipfile.ZipFile(f, 'r') as zip_ref:
#            zip_ref.extractall(localpath / "emulationstation_configs")
#        copydir(localpath / "emulationstation_configs/", "/home/pi/.emulationstation/")
#        try:
#            shutil.rmtree(localpath / "emulationstation_configs")
#        except OSError as e:
#            print("Error: %s : %s" % (localpath / "emulationstation_configs", e.strerror))
#        os.remove(localpath / "emulationstation_configs.zip")
#
#    return


def install_dialog():
    code = d.yesno('Continue with installation?\n\nThis will add the tool to the Options menu, overwriting any previous installations.')

    if code == d.OK:
        install()
        reboot_msg = "\nUpdate tool has been installed, reboot required for these changes to take effect. Rebooting now.!\n"
        reboot_dialog(reboot_msg)
    return


def update_dialog():
    global update_available_result
    update_available_result = update_available()

    if update_available_result == "update available" or update_available_result == "alt branch":
        code = d.yesno('Continue with update?')

        if code == d.OK:
            update()
            reboot_msg = "\nUpdate tool has been updated, reboot required for these changes to take effect. Rebooting now.!\n"
            reboot_dialog(reboot_msg)
    elif update_available_result == "no update available":
        d.msgbox("You are already running the latest version.")
        main_dialog()
    else:
        d.msgbox("You are need to be connected to the internet for this.")
        main_dialog()

    return


def uninstall_dialog():
    code = d.yesno('Continue with uninstall?\n\nThis will remove the tool from the Options menu.')

    if code == d.OK:
        uninstall()
        reboot_msg = "\nUpdate tool has been uninstalled, reboot required for these changes to take effect. Rebooting now.!\n"
        reboot_dialog(reboot_msg)
    return


def installation_dialog():
    code, tag = d.menu("Select Option", 
                    choices=[("1", "Install"),
                             ("2", "Update"), 
                             ("3", "Uninstall")],
                    title="Installation",
                    cancel_label=" Cancel ")
    
    if code == d.OK:
        if tag == "1":
            if os.path.exists(tool_ini):
                update_dialog()
            else:
                install_dialog()
        elif tag == "2":
            update_dialog()
        elif tag == "3":
            uninstall_dialog()

    cls()
    main_dialog()

    return


def user_dialog():
    d.msgbox("This program needs to be run as 'pi' user.")
    return


def hostname_dialog():
    if platform.uname()[1] == "retropie":
        main_dialog()
    else:
        code = d.yesno(
            'Your hostname is not retropie? Did you change your hostname? If so you can just '
            'Continue. Do not continue if you are not running this on a retropie!')

        if code == d.OK:
            main_dialog()

        main_dialog

def reboot_dialog(reboot_msg):
    code = d.pause(reboot_msg, height=10, width=60)
    if code == d.CANCEL:
        main_dialog()
    else:
        restart_es()


def clean_failures():
    if os.path.exists("/tmp/improvements"):
        if os.path.isdir("/tmp/improvements"):
            #os.system("sudo chown -R pi:pi /tmp/improvements/")
            #shutil.rmtree("/tmp/improvements")
            os.system("sudo rm -rf /tmp/improvements/")
    if os.path.exists("/tmp/extracted"):
        if os.path.isdir("/tmp/extracted"):
            #os.system("sudo chown -R pi:pi /tmp/extracted/")
            #shutil.rmtree("/tmp/extracted")
            os.system("sudo rm -rf /tmp/extracted/")

    return


def check_for_updates():
    if not check_internet():
        return False; 
    needed_updates = 0
    available_updates = get_available_updates(check_drive(), False)
    for update in available_updates:
        update_applied = is_update_applied(update[0], update[2])
        if update_applied == False:
            needed_updates += 1
    if needed_updates > 0:
        return True
    else:
        return False


def fix_lame_update_dirs(key: str):
    ret_val = ""
    mounts = []

    mount_cmd = runcmd("mount")
    mount_points = mount_cmd.split("\n")
    for mount_point in mount_points:
        if " on " in mount_point and " type " in mount_point:
            start_index = mount_point.find(" on ") + 4
            end_index = mount_point.find(" type ")
            mount_dir = mount_point[start_index: end_index]
            if "/home/pi/" in mount_dir:
                mounts.append(mount_dir)

    update_dir = get_config_value("CONFIG_ITEMS", key, return_none=False)

    if len(update_dir.strip()) == 0:
        set_config_value("CONFIG_ITEMS", key, "")
        return

    for mount in mounts:
        if mount in update_dir.strip():
            return

    parts = update_dir.strip().split("/")
    while "" in parts:
        index = parts.index("")
        del parts[index]

    for part in parts:
        ret_val += "/" + part.strip()
        if os.path.ismount(ret_val):
            return
        if not os.path.isdir(ret_val):
            try:
                os.mkdir(ret_val)
            except:
                pass

    set_config_value("CONFIG_ITEMS", key, ret_val + "/")

    return


def main():
    global update_available_result
    update_available_result = update_available()
    if os.path.isfile(tool_ini):
        mega_ini_check()
        fix_lame_update_dirs("update_dir")
        fix_lame_update_dirs("unofficial_update_dir")

    if not os.path.isfile("/home/pi/.update_tool/override_emulators.cfg"):
        log_this("/home/pi/.update_tool/override_emulators.cfg", "# place emulators.cfg entries here that you ABSOLUTELY do not want to get overwritten")
        
    if len(sys.argv) > 2 and sys.argv[2] == "notify":
        if get_config_value('CONFIG_ITEMS', 'display_notification') not in ["Theme", "Tool"]:
            remove_notification()
            exit(0)

        if update_available_result == "update available":
            set_config_value("CONFIG_ITEMS", "upgrade_available", "True")
        else:
            set_config_value("CONFIG_ITEMS", "upgrade_available", "False")

        if check_for_updates():
            set_config_value("CONFIG_ITEMS", "update_available", "True")
            if get_config_value('CONFIG_ITEMS', 'display_notification') == "Tool":
                while runcmd("pidof omxplayer.bin | cat") != "":
                    time.sleep(2)
                if d.pause("Updates are available !\\n\\nProceed with Booting or Process Updates ?", height=11, seconds=5, ok_label="Boot", cancel_label="Update") == d.OK:
                    exit(0)
            else:
                exit(0)
        else:
            set_config_value("CONFIG_ITEMS", "update_available", "False")
            exit(0)

    clean_failures()
    
    if update_available_result == "update available":
        code = d.yesno('\nWe always recommend upgrading to the latest release of this tool.\n\nDo you want to upgrade now?\n', title="Newer Release Available" )
        
        if code == d.OK:
            update_dialog()

    global genres
    section = get_config_section("GENRE_MAPPINGS")
    if section is not None:
        for key, val in section:
            genres[key] = val

    if runcmd("id -u -n") == "pi\n":
        check_wrong_permissions()
        hostname_dialog()
    else:
        user_dialog()


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        #print("")
        #nothing = None
        pass
    except:
        # need to clean this up if we changed it
        os.system("sudo chown -R root:root /etc/emulationstation/")

        title_text = ""
        if os.path.exists(tool_ini):
            title_text = "A copy of this exception is logged in /home/pi/.update_tool/exception.log for your records\n\n"
            version = get_config_value("CONFIG_ITEMS", "tool_ver")
            if version is not None:
                title_text += "Version: " + version + "\n\n"
            if (update_being_processed is not None):
                title_text += "Update: " + update_being_processed + "\n\n"
            log_this("/home/pi/.update_tool/exception.log", f"*****\nDate: {datetime.datetime.utcnow()}\nVersion: {version}\nUpdate: {update_being_processed}\n\n{traceback.format_exc()}")
            log_this("/home/pi/.update_tool/exception.log", "\n\n")

        d.msgbox(title_text + traceback.format_exc(), title="Something has gone really bad...")
