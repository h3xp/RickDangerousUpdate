"""
Update Script for Rick Dangerous' Insanium/R.P Edition
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
config = configparser.ConfigParser()
config.optionxform = str
update_available_result = "no connection"
genres = {}

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
    if os.path.exists("/home/pi/.update_tool/update_tool.ini"):
        git_repo = get_config_value("CONFIG_ITEMS", "git_repo")
        if git_repo is not None:
            return git_repo

    return "https://raw.githubusercontent.com/h3xp/RickDangerousUpdate"


def get_git_branch():
    if os.path.exists("/home/pi/.update_tool/update_tool.ini"):
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


def read_config():
    if os.path.exists("/home/pi/.update_tool/update_tool.ini"):
        if os.path.isfile("/home/pi/.update_tool/update_tool.ini"):
            config_file = configparser.ConfigParser()
            config_file.optionxform = str
            config_file.read("/home/pi/.update_tool/update_tool.ini")
            return config_file
    return None
    
def get_config_section(section: str):
    config_file = read_config()
    if config_file is not None:
        if config_file.has_section(section):
            return config_file.items(section)

    return None


def get_config_value(section: str, key: str):
    config_file = read_config()
    if config_file is not None:
        if config_file.has_option(section, key):
            return config_file[section][key]

    return None


def retrieve_mega_config(read_config: bool):
    mega_dir = get_config_value("CONFIG_ITEMS","mega_dir")
    if mega_dir is not None:
        mega_config_content = configparser.ConfigParser()
        mega_config_content.optionxform = str
        mega_ini_file = "/home/pi/.update_tool/mega_{}.ini".format(mega_dir.split("/")[-1])
        if read_config:
            mega_config_content.read(mega_ini_file)
        return mega_config_content,mega_ini_file

    return None,None


def get_mega_config_section(section: str):
    mega_config_content,mega_ini_file = retrieve_mega_config(True)
    if mega_config_content is not None:
        if mega_config_content.has_section(section):
            return mega_config_content.items(section)

    return None


def get_mega_config_value(section: str, key: str):
    mega_config_content,mega_ini_file = retrieve_mega_config(True)
    if mega_config_content is not None:
        if mega_config_content.has_option(section, key):
            return mega_config_content[section][key]

    return None


def set_config_value(section: str, key: str, value: str):
    config_file = read_config()
    if config_file is not None:
        if config_file.has_section(section) == False:
            config_file.add_section(section)

        config_file[section][key] = value

        with open("/home/pi/.update_tool/update_tool.ini", 'w') as configfile:
            config_file.write(configfile)

        return True

    return False


def set_mega_config_value(section: str, key: str, value: str):
    mega_config_content,mega_ini_file = retrieve_mega_config(True)
    if mega_config_content is not None:
        if mega_config_content.has_section(section) == False:
            mega_config_content.add_section(section)

        mega_config_content[section][key] = value

        with open(mega_ini_file, 'w') as configfile:
            mega_config_content.write(configfile)

        return True

    return False


def mega_ini_check():
    mega_config_content,mega_ini_file = retrieve_mega_config(False)
    # check greater than 5 because of mega_ prefix
    if len(mega_ini_file) > 5:
        # if the mega ini files does not exist then initialize it
        if os.path.exists(mega_ini_file) == False:
            mega_config_content.add_section("INSTALLED_UPDATES")
            with open(mega_ini_file, 'w') as configfile:
                mega_config_content.write(configfile)
    
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
    if os.path.exists("/home/pi/.update_tool/update_tool.ini"):
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
    if os.path.exists("/home/pi/.update_tool/update_tool.ini"):
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
    if os.path.exists("/home/pi/.update_tool/update_tool.ini"):
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
    main_dialog()
 

def is_update_applied(key: str, modified_timestamp: str):
    if os.path.exists("/home/pi/.update_tool/update_tool.ini") == False:
        return False

    mega_config_content,mega_ini_file = retrieve_mega_config()
    if mega_config_content.has_option("INSTALLED_UPDATES", key):
        return mega_config_content["INSTALLED_UPDATES"][key] == str(modified_timestamp)

    return False


def uninstall():
    git_repo = get_git_repo()
    git_branch = get_git_branch()
    runcmd("bash <(curl '{}/{}/install.sh' -s -N) -remove".format(git_repo, git_branch))
    return


def update():
    git_repo = get_git_repo()
    git_branch = get_git_branch()
    runcmd("bash <(curl '{}/{}/install.sh' -s -N) -update".format(git_repo, git_branch))
    return


def install():
    git_repo = get_git_repo()
    git_branch = get_git_branch()
    megadrive = check_drive()
    runcmd("bash <(curl '{}/{}/install.sh' -s -N) {}".format(git_repo, git_branch, megadrive))
    return


def download_file(file_handle,
                  file_key,
                  file_data,
                  dest_path,
                  dest_filename=None):
    k = (file_key[0] ^ file_key[4], file_key[1] ^ file_key[5],
         file_key[2] ^ file_key[6], file_key[3] ^ file_key[7])
    iv = file_key[4:6] + (0, 0)
    meta_mac = file_key[6:8]

    # Seems to happens sometime... When this occurs, files are
    # inaccessible also in the official also in the official web app.
    # Strangely, files can come back later.
    if 'g' not in file_data:
        raise RequestError('File not accessible anymore')
    file_url = file_data['g']
    file_size = file_data['s']
    attribs = base64_url_decode(file_data['at'])
    attribs = decrypt_attr(attribs, k)
    print("\t{}% complete: [>{}]".format(0, " "*99), end = "\r")
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
            percent_complete = round(((chunk_start + chunk_size) / file_size) * 100)
            print("\t{}% complete: [{}>{}]".format(percent_complete if percent_complete < 100 else 99, "="*percent_complete, " "*(99 - percent_complete)), end = "\r")

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
    print("\t100% complete: [{}]".format("="*100))
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
    try:
        response = requests.post(
            "https://g.api.mega.co.nz/cs",
            params={'id': 0,  # self.sequence_num
                    'n': root_folder},
            data=json.dumps(data)
        )
    except requests.exceptions.RequestException as e:
        print(e)
    #print(response)
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
            print("Downloading: {} ({})...".format(attrs["n"], size))
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


def merge_gamelist(directory):
    # check if gamelist.xml has been updated
    for gamelist in Path(directory).rglob('gamelist.xml'):
        # find corresponding xmls
        corr = gamelist.parts
        corr = corr[corr.index('extracted')+1:]
        corr = Path("/", *corr)
        if os.path.isfile(corr):
            merge_xml(str(gamelist), str(corr))
            os.remove(str(gamelist))


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
    

def merge_xml(src_xml: str, dest_xml: str):
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
            
            parents = dest_tree.findall(".//game[path=\"{}\"]".format(src_path.text))
            if len(parents) == 0:
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
        next(f)
        for lines in f:
            if os.path.isfile(lines.rstrip()):
                os.remove(lines.rstrip())
            elif os.path.isdir(lines.rstrip()):
                shutil.rmtree(lines.rstrip())
        f.close()
        os.remove(directory)


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
    if os.path.isfile("/home/pi/.update_tool/update_tool.ini"):
        config = configparser.ConfigParser()
        config.read("/home/pi/.update_tool/update_tool.ini")
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

    if os.path.isfile("/home/pi/.update_tool/update_tool.ini"):
        config = configparser.ConfigParser()
        config.read("/home/pi/.update_tool/update_tool.ini")
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


def log_this(log_file: str, log_text: str):
    if log_file is None:
        return

    if not os.path.isfile(log_file):
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

    parents = src_tree.findall(".//system[name=\"{}\"]".format(system))
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
                log_this(log_file, "-cue entry \"{}\" not found for cue file \"{}\" from within m3u file \"{}\"".format(file, os.path.basename(cue_file), m3u_file))
            else:
                log_this(log_file, "-cue entry \"{}\" not found for cue file \"{}\"".format(file, os.path.basename(cue_file)))

        return False
    else:
        for file in good_files:
            if file in cue_files:
                index = cue_files.index(os.path.basename(file))
                del cue_files[index]    

    return True


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
            log_this(log_file, "-m3u entry \"{}\" not found for m3u file \"{}\"".format(file, os.path.basename(m3u_file)))
    else:
        for file in good_files:
            if file in m3u_files:
                index = m3u_files.index(os.path.basename(file))
                del m3u_files[index]

    return bad_files


def process_supporting_files(src_game: ET.Element, src_name: str, subelement_name: str, system_roms: str, rom_file: str, supporting_files_dir_name: str, supporting_files_dir: str, supporting_files_types: list, supporting_files: list, found_files: list, log_file: str, clean=False):
    def _new_element(src_game: ET.Element, subelement_name: str, log_file: str):
        indent(src_game, "\t")
        log_this(log_file, "-{} element will now be:".format(subelement_name))
        log_this(log_file, ET.tostring(src_game).decode())

    file = ""
    # check if subelement exists
    src_node = src_game.find(subelement_name)
    if src_node is not None:
        if src_node.text is not None:
            # validate file exists
            #relative_file = src_node.text.replace("./", "")
            #file = relative_file.replace("{}/".format(supporting_files_dir_name), "")
            file = os.path.basename(src_node.text)
            #path = os.path.join(supporting_files_dir, file)
            path = src_node.text.replace("./", system_roms + "/")
            if src_node.text[0:1] == "/":
                path = src_node.text

            if not os.path.isfile(path):
                log_this(log_file, "-{} file \"{}\" (full path \"{}\") does not exist for rom \"{}\" ({})".format(subelement_name, file, path, rom_file, src_name))
                # remove bad reference
                if clean == True:
                    src_node.text = None
                else:
                    log_this(log_file, "-clean would remove reference to {} file".format(subelement_name))
                # look for file based on rom name
                file = look_for_supporting_files(rom_file, supporting_files_dir, supporting_files_types)
                if len(file) > 0:
                    log_this(log_file, "-{} file found: \"{}\" for rom \"{}\"".format(subelement_name, file, rom_file))
                    if clean == True:
                        #src_node.text = file
                        src_node.text = file.replace(system_roms, ".")
                        _new_element(src_node, subelement_name, log_file)
                    else:
                        log_this(log_file, "-clean would add new reference to {} tag".format(subelement_name))
        else:
            # look for file based on rom name
            log_this(log_file, "-no {} defined for rom \"{}\" ({})".format(subelement_name, rom_file, src_name))
            file = look_for_supporting_files(rom_file, supporting_files_dir, supporting_files_types)
            if len(file) > 0:
                log_this(log_file, "-{} file found: \"{}\" for rom \"{}\"".format(subelement_name, file, rom_file))
                if clean == True:
                    #src_node.text = file
                    src_node.text = file.replace(system_roms, ".")
                    _new_element(src_node, subelement_name, log_file)
                else:
                    log_this(log_file, "-clean would add new reference to {} tag".format(subelement_name))
    else:
        # look for file based on rom name and add to element tree if it exists
        log_this(log_file, "-no {} element defined in gamelist.xml for rom \"{}\"".format(subelement_name, rom_file))
        file = look_for_supporting_files(rom_file, supporting_files_dir, supporting_files_types)
        if len(file) > 0:
            log_this(log_file, "-{} file found: \"{}\" for rom \"{}\"".format(subelement_name, file, rom_file))
            if clean == True:
                child = ET.SubElement(src_game, subelement_name)
                #child.text = "./{}/{}".format(supporting_files_dir, file)
                child.text = file.replace(system_roms, ".")
                _new_element(child, subelement_name, log_file)
            else:
                log_this(log_file, "-clean would add new reference to {} tag".format(subelement_name))

    # delete validated files
    file = os.path.basename(file)
    if len(file) > 0:
        if file not in found_files:
            found_files.append(file)
        if file in supporting_files:
            index = supporting_files.index(file)
            del supporting_files[index]

    return


def process_orphaned_files(orphaned_files: list, dir: str, log_file: str, dir_backup: str, file_type: str, clean=False):
    orphaned_files.sort()
    process = "DELETING" if clean == True else "IDENTIFIED"
    for orphaned_file in orphaned_files:
        file_path = os.path.join(dir, orphaned_file)
        if os.path.exists(file_path):
            log_this(log_file, "-{} orphaned {} file: \"{}\"".format(process, file_type, file_path))
            if clean == True:
                #os.remove(file_path)
                if not os.path.exists(dir_backup):
                    os.makedirs(dir_backup)
                shutil.move(file_path, dir_backup)

    return


def delete_gamelist_entry_dialog(rom: str):
    code = d.yesno("Gamelist entry for \"{}\" has invalid rom entries (rom files or multi disk files defined in .m3u or .cue file can not be found).\nWould you like to remove it from your gamelist.xml?".format(rom))

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

        parents = src_tree.findall(".//game[path=\"./{}\"]".format(os.path.basename(src_path)))
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
        parents = src_tree.findall(".//game[path=\"{}\"]".format(rom))
        if parents is not None:
            done = False
            for parent in parents:
                if done == True:
                    indent(parent)
                    log_this(log_file, "-removing duplicate gamelist.xml entry for {}".format(os.path.basename(rom)))
                    log_this(log_file, ET.tostring(parent).decode())
                    src_root.remove(parent)
                done = True

    # write file
    file_time = safe_write_backup(src_xml)
    
    indent(src_root, space="\t", level=0)
    with open(src_xml, "wb") as fh:
        src_tree.write(fh, "utf-8")

    if safe_write_check(src_xml, file_time) == False:
        log_this(log_file, "-writing to {} FAILED".format(src_xml))

    return


def process_gamelist(system: str, gamelist_roms_dir: str, log_file: str, backup_dir: str, del_roms=False, del_art=False, del_snaps=False, del_m3u=False, clean=False, auto_clean=False):
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
    bad_roms = []
    remove_entries = []

    # if len(extensions) == 0 then directory is not in es_systems.cfg
    # when there is a link to a directory which name is in the es_systems.cfg?
    # this now no longer cares...
    extensions = get_system_extentions(system)
    if len(extensions) == 0:
        return

    process = "cleaning" if clean == True else "checking"
    log_this(log_file, "now {}: {} for rom extensions {}".format(process, system, extensions))
    print("now {}: {} for rom extensions {}".format(process, system, extensions))
    
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

    # start scanning gamelist.xml
    src_tree = ET.parse(src_xml)
    src_root = src_tree.getroot()

    for src_game in src_root.iter("game"):
        src_name = ""
        rom_file = ""
        src_name_node = src_game.find("name")
        if src_name_node is not None:
            src_name = src_name_node.text
            print(src_name)

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
                    log_this(log_file, "-rom \"{}\" (full path \"{}\") does not exist".format(rom_file, rom_path))
                    if rom_file not in bad_roms:
                        bad_roms.append(rom_file)
                    #continue

                # check if art exists
                process_supporting_files(src_game, src_name, "image", system_roms, rom_file, art_dir, system_art, art_types, art_files, found_files, log_file, clean=clean)

                # check if snap exists
                process_supporting_files(src_game, src_name, "video", system_roms, rom_file, snaps_dir, system_snaps, snaps_types, snaps_files, found_files, log_file, clean=clean)

            # check for auto gamelist removal
            if len(found_files) == 0:
                if rom_file not in remove_entries:
                    remove_entries.append(rom_file)

    # remove entry that shouldn't be there
    for entry in remove_entries:
        parents = src_tree.findall(".//game[path=\"./{}\"]".format(entry))
        for parent in parents:
            if entry in bad_roms:
                index = bad_roms.index(entry)
                del bad_roms[index]   
            indent(parent, "\t")
            if clean == True:
                log_this(log_file, "-auto removing gamelist.xml entry for {} because it has 0 rom, image, or video files".format(entry))
            else:
                log_this(log_file, "-clean would auto remove gamelist.xml entry for {} because it has 0 rom, image, or video files".format(entry))
            log_this(log_file, ET.tostring(parent).decode())
            if clean == True:
                src_root.remove(parent)

    # clean out bad roms from gamelist
    for rom_file in bad_roms:
        parents = src_tree.findall(".//game[path=\"./{}\"]".format(rom_file))
        for parent in parents:
            if clean == True:
                if auto_clean == True or delete_gamelist_entry_dialog(rom_file) == True:
                    log_this(log_file, "-removing gamelist.xml entry for {}".format(rom_file))
                    log_this(log_file, ET.tostring(parent).decode())
                    src_root.remove(parent)
                else:
                    log_this(log_file, "-overridden: removing gamelist.xml entry for {}".format(rom_file))
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
                log_this(log_file, "-clean would potentially (unless overridden) remove gamelist.xml entry for {}".format(rom_file))
                log_this(log_file, ET.tostring(parent).decode())
                
    if clean == True:
        safe_write_backup(src_xml, file_time)
        
        indent(src_root, space="\t", level=0)
        with open(src_xml, "wb") as fh:
            src_tree.write(fh, "utf-8")

        if safe_write_check(src_xml, file_time) == False:
            log_this(log_file, "-writing to {} FAILED".format(src_xml))

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
        else:
            log_this(log_file, "-cannot process orphaned files from {} directory because m3u file is not supported for {}".format(m3u_dir, system))
    
    return


def do_process_gamelists(systems: list, del_roms=False, del_art=False, del_snaps=False, del_m3u=False, clean=False, log_file="", auto_clean=False):
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
        log_file = "/home/pi/.update_tool/gamelist_logs/{}_gamelists-{}.log".format(process_type, file_time.strftime("%Y%m%d-%H%M%S"))
    backup_dir = "/home/pi/.update_tool/gamelist_logs/{}".format(os.path.splitext(os.path.basename(log_file))[0])
    if clean == True:
        if not os.path.exists(backup_dir):
            os.mkdir(backup_dir)

    log_this(log_file, "{}ING GAMELISTS: started at {}".format(process_type.upper(), file_time))
    log_this(log_file, "")
    log_this(log_file, "RUNNING: gamelist.xml files from {}".format(gamelist_roms_dir))
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
            print("Now processing {}...".format(single_system))
            process_gamelist(single_system, gamelist_roms_dir, log_file, backup_dir, del_roms=del_roms, del_art=del_art, del_snaps=del_snaps, del_m3u=del_m3u, clean=clean, auto_clean=auto_clean)

    log_this(log_file, "\n")
    log_this(log_file, "{}ING GAMELISTS: ended at {}".format(process_type.upper(), datetime.datetime.utcnow()))
    cls()
    d.textbox(log_file, title="Contents of {0}".format(log_file))

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
                            choices=[("Roms", "", False), ("Artwork", "", False), ("Snapshots", "", False), ("M3U Disk Files", "", False)])

    if code == d.OK:
        del_roms = True if "Roms" in tags else False
        del_art = True if "Artwork" in tags else False
        del_snaps = True if "Snapshots" in tags else False
        del_m3u = True if "M3U Disk Files" in tags else False

        do_process_gamelists(systems, del_roms=del_roms, del_art=del_art, del_snaps=del_snaps, del_m3u=del_m3u, clean=clean)

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

    dialog_text = "System:\t{}".format(system)

    if "name" in game.keys():
        dialog_text += "\n\nGame:\t{}".format(game["name"])

    if "genre" in game.keys():
        dialog_text += "\n\nGenre:\t{}".format(game["genre"])

    if "path" in game.keys():
        dialog_text += "\n\nRom:\t{}".format(game["path"].replace("./", ""))

    if "desc" in game.keys():
        dialog_text += "\n\n" if len(dialog_text) > 0 else ""
        dialog_text += "Description:\t{}".format(game["desc"])

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
            elem.append(ET.fromstring("<genre>{}</genre>".format(tag)))

        genre_collection = genres[tag]
        lines = []
        cfg_file = os.path.join("/opt/retropie/configs/all/emulationstation/collections", genre_collection)
        with open(cfg_file, 'r', encoding='utf-8') as f:
            lines = f.readlines()
            if game["path"] not in lines:
                system_roms = "/home/pi/RetroPie/roms/{}/".format(system)
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


def get_official_origins():
    ret_val = []

    origins = get_config_value("CONFIG_ITEMS", "official_origin")
    for origin in origins.split(","):
        ret_val.append(origin.strip())

    return ret_val


def is_game_official(game: ET.Element, origins=[]):
    if len(origins) == 0:
        origins = get_official_origins()
    origin = game.find("origin")
    if origin is not None:
        if origin.text is not None:
            return origin.text in origins

    return False


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
    origins = get_official_origins()

    for src_game in src_root.iter("game"):
        game_list = []
        game = src_game.find("name")
        if game.text is not None:
            path = src_game.find("path")
            if path.text is not None:
                game_path = path.text.replace("./", system_dir + "/").strip()
                official = is_game_official(src_game, origins)
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
    games_text = "Count offical only is {}.\n\nsystem\tgame\tpath\tsize\tofficial\torigin".format("on" if official_only == True else "off")
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
            systems_text += "\n-{}:\t{}".format(single_system, str(system_count[0]))
            if official_only == False:
                systems_text += "\t{}\t{}".format(str(system_count[1]), str(system_count[2]))

    systems_counted = "All" if all_systems == True else "Selected"
    systems_header = "Count official only is {}\n\nTOTAL: {}".format("on" if official_only == True else "off", total_count)
    if official_only == False:
        systems_header += "\tOfficial: {}\tUnofficial: {}".format(official_count, unofficial_count)
    systems_header += "\n\n{} Systems:".format(systems_counted)
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
                        "\t-a copy of this count is located in /home/pi/.update_tool/counts.txt for your reference.\n\n" + display_text)
        with open("/home/pi/.update_tool/counts.txt", 'w', encoding='utf-8') as f:
            f.write(systems_text)

        for game in games:
            line_text = ""
            #game_list = list(game)
            for game_text in game:
                #line_text += "\t" if len(games_text) > 0 else ""
                line_text += game_text + "\t"
            games_text += line_text[:-1] + "\n"
            #games_text += "{}\t{}\t{}\t{}\t{}\t{}\n".format(game[0], game[1], game[2], game[3], game[4], game[5])
        with open("/home/pi/.update_tool/games_list.txt", 'w', encoding='utf-8') as f:
            f.write(games_text)

    d.msgbox(display_text)

    cls()
    gamelist_utilities_dialog()

    return 
    

def remove_system_genres(system: str, cfg_file: str):
    new_lines = []

    with open(cfg_file, 'r', encoding='utf-8') as f:
        lines = f.readlines()
        for line in lines:
            if line.find("/{}/".format(system)) < 0:
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
    d.msgbox('done!')
    main_dialog()

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
        print("Now sorting: {}".format(system))
        total_games += sort_gamelist(system)
        
    d.msgbox("Sorted {} games, in {} systems.\n\nTime to process: {}".format(total_games, total_systems, str(datetime.datetime.utcnow() - start_time)[:-7]))

    return


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

    systems = get_all_systems_from_cfg()
    menu_choices = []

    for system in systems:
        menu_choices.append((system, "", False))

    button_text = "Process" if function == "Genre" else function
    code, tags = d.checklist(text="Available Systems",
                            choices=menu_choices,
                            ok_label="{} Selected".format(button_text), 
                            extra_button=True, 
                            extra_label="{} All".format(button_text), 
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
        else:
            gamelists_orphan_dialog(systems, function == "Clean")        

    if code == d.CANCEL:
        cls()
        gamelist_utilities_dialog()

    cls()
    gamelists_dialog(function)

    return


def do_remove_logs(logs: list):
    for log in logs:
        log_file = os.path.join("/home/pi/.update_tool/gamelist_logs", log)
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


def get_log_size(log: str):
    log_file = os.path.join("/home/pi/.update_tool/gamelist_logs", log)
    log_dir = os.path.splitext(log_file)[0]

    if os.path.exists(log_file):
        if not os.path.isfile(log_file):
            return None

    log_size = int(get_total_path_size(log_file))
    if os.path.exists(log_dir):
        if os.path.isdir(log_dir):
            log_size += int(get_total_path_size(log_dir))

    return log_size


def logs_dialog(function: str, title: str, patterns: list, multi=True):
    menu_choices = []
    logs = []
    total_size = 0

    for pattern in patterns:
        for log in Path("/home/pi/.update_tool/gamelist_logs").glob(pattern):
            if os.path.exists(log):
                if os.path.isfile(log):
                    logs.append(os.path.basename(log))

    if len(logs) == 0:
        d.msgbox("There are no logs to {}!".format(function.lower()))
        cls()
        gamelist_utilities_dialog()
        
    logs.sort(reverse=True)
    for menu_choice in logs:
        log_size = get_log_size(menu_choice)
        total_size += log_size
        menu_choices.append((menu_choice + " ({})".format(convert_filesize(str(log_size))), "", False))

    dlg_text = "Log Files in \"/home/pi/.update_tool/gamelist_logs\" ({}):".format(convert_filesize(str(total_size)))
    if multi == True:
        code, tags = d.checklist(text=dlg_text,
                                choices=menu_choices,
                                ok_label="{} Selected".format(function), 
                                extra_button=True, 
                                extra_label="{} All".format(function), 
                                title=title)
    else:
        code, tags = d.radiolist(text=dlg_text,
                                choices=menu_choices,
                                ok_label="{} Selected".format(function), 
                                title=title)

    selected_logs = []
    selected_items = []
    if code == d.CANCEL:
        cls()
        gamelist_utilities_dialog()

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
            do_remove_logs(selected_logs)
        elif function == "Restore":
            do_restore_logs(selected_logs)

    cls()
    gamelist_utilities_dialog()

    return


def do_clean_emulators_cfg():
    emulator_cfg = "/opt/retropie/configs/all/emulators.cfg"
    items = {}
    lines_out = ""
    game_counter = 0
    duplicate_counter = 0

    if not os.path.exists(emulator_cfg):
        return

    with open(emulator_cfg, 'r') as configfile:
        lines_in = configfile.readlines()
        for line in lines_in:
            parts = line.split("=")
            if parts[0].strip() in items.keys():
                duplicate_counter += 1
            items[parts[0].strip()] = parts[1].strip()

        for item in sorted(items.keys()):
            lines_out += "{} = {}\n".format(item, items[item])
            game_counter += 1

    file_time = safe_write_backup(emulator_cfg)

    with open(emulator_cfg, 'w') as configfile:
        configfile.write(lines_out)

    safe_write_check(emulator_cfg, file_time)

    d.msgbox("Sorted {} game entries.\n\nRemoved {} duplicate entries.".format(game_counter, duplicate_counter))

    return


def gamelist_utilities_dialog():
    code, tag = d.menu("Main Menu", 
                    choices=[("1", "Check Game Lists"), 
                             ("2", "Clean Game Lists"), 
                             ("3", "Restore Clean Game List Logs"), 
                             ("4", "Remove Check/Clean Game List Logs"), 
                             ("5", "Manually Select Genres"), 
                             ("6", "Realign Genre Collections"), 
                             ("7", "Sort Game Lists"), 
                             ("8", "Clean Emulators Config"), 
                             ("9", "Count of Games")],
                    title="Gamelist (Etc) Utilities")
    
    if code == d.OK:
        if tag == "1":
            gamelists_dialog("Check")
        elif tag == "2":
            gamelists_dialog("Clean")
        elif tag == "3":
            logs_dialog("Restore", "Restore Clean Game List Logs", ["clean_gamelists*", "auto_clean_gamelists*"], multi=False)
        elif tag == "4":
            logs_dialog("Remove", "Remove Check/Clean Game List Logs", ["check_gamelists*", "clean_gamelists*", "auto_clean_gamelists*"], multi=True)
        elif tag == "5":
            gamelists_dialog("Genre")
        elif tag == "6":
            gamelists_dialog("Realign")
        elif tag == "7":
            gamelists_dialog("Sort")
        elif tag == "8":
            do_clean_emulators_cfg()
        elif tag == "9":
            gamelists_dialog("Count")

    if code == d.CANCEL:
        cls()
        main_dialog()

    cls()
    gamelist_utilities_dialog()

    return


def get_manual_updates(path: str, available_updates: list):
    files = []
    manual_updates = []

    if os.path.isfile(path) == True:
        if os.path.splitext(path)[1] == ".zip":
            files.append(path)

    if os.path.isdir(path):
        for file in os.listdir(path):
            if os.path.splitext(file)[1] == ".zip":
                files.append(os.path.join(path, file))

    files.sort()
    for file in files:
        for update in available_updates:
#   file name check is not necessary so skip it
#            if update[0] == os.path.basename(file):
            #if update[3] == convert_filesize(os.path.getsize(file)):
            if update[4] == os.path.getsize(file):
                  manual_updates.append(update)

    return manual_updates


def auto_clean_gamelists(installed_updates: list, manual=False):
    if len(installed_updates) > 0:
        systems = get_all_systems_from_cfg()
        type = "" if manual == False else "MANUAL "

        file_time = datetime.datetime.utcnow()

        if not os.path.exists("/home/pi/.update_tool/gamelist_logs"):
            os.mkdir("/home/pi/.update_tool/gamelist_logs")

        log_file = "/home/pi/.update_tool/gamelist_logs/auto_clean_gamelists-{}.log".format(file_time.strftime("%Y%m%d-%H%M%S"))
        log_this(log_file, "AUTO CLEANING {}UPDATES INSTALLED:".format(type))
        for installed_update in installed_updates:
            log_this(log_file, "-{}".format(installed_update))
        log_this(log_file, "")
        log_this(log_file, "")

        do_process_gamelists(systems, del_roms=True, del_art=True, del_snaps=True, del_m3u=True, clean=True, log_file=log_file, auto_clean=True)
    
    return
    

def process_manual_updates(path: str, updates: list, delete=False, auto_clean=False):
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

#    if os.path.isdir(path):
#        if delete == True:
#            if len(os.listdir(path)) == 0:
#                shutil.rmtree(path)

    d.msgbox("{} of {} selected manual updates installed.\n\nTotal time to process: {}".format(len(installed_updates), len(updates), str(datetime.datetime.utcnow() - start_time)[:-7]))
    reboot_msg = "\nReboot required for these changes to take effect. Rebooting now.!\n"
    reboot_dialog(reboot_msg)

    return


def get_valid_path_portion(path: str):
    return_path = "/"
    parts = path.split("/")
    for part in parts:
        if len(part) > 0:
            if os.path.isdir(os.path.join(return_path, part)) == True or os.path.isfile(os.path.join(return_path, part)) == True:
                return_path = os.path.join(return_path, part)

    #will add the trailing slash if it's not already there.
    return_path = os.path.join(return_path, '')

    return return_path


def manual_updates_dialog(init_path: str, delete: bool):
    help_text = ("Type the path to directory or file directly into the text entry window."
                  "\nAs you type the directory or file will be highlighted, at this point you can press [Space] to add the highlighted item to the path."
                  "\n\nIf you are adding a directory to the text entry window, and the path ends with a \"/\", the files in that directory will automatically show in the \"Files\" window."
                  "\nYou can use also cycle through the windows with [Tab] or [Arrow] keys.")
    code, path = d.fselect(init_path, height=10, width=60, help_button=True)

    if code == d.OK:
        if os.path.isdir(path) or os.path.isfile(path):
            set_config_value("CONFIG_ITEMS", "update_dir", os.path.dirname(path))
            official_improvements_dialog(path, delete)
        else:
            d.msgbox("Invalid path " + path)
            path = get_valid_path_portion(path)
            path = "/" if len(path) == 0 else path
            d.msgbox("Path is now set to " + path)
            cls()
            manual_updates_dialog(path, delete)
    elif code == d.HELP:
        d.msgbox(help_text)
        path = get_valid_path_portion(path)
        path = "/" if len(path) == 0 else path
        cls()
        manual_updates_dialog(path, delete)
    elif code == d.CANCEL:
        cls()
        main_dialog()

    return


def get_default_update_dir():
    if os.path.exists("/home/pi/.update_tool/update_tool.ini"):
        update_dir = get_config_value("CONFIG_ITEMS", "update_dir")
        if update_dir is not None and os.path.exists(update_dir):
            return update_dir
        else:
            if update_dir is not None:
                d.msgbox("Invalid saved update_dir " + update_dir + ", resetting to /")                

    return "/"


def downloaded_update_question_dialog():
    code = d.yesno(text="You will be asked to choose a .zip file to load, or a directory where multiple .zip files are located."
                        "\nThis will process the .zip file(s)?"
                        "\n\nIf the name of a .zip file is identified as a valid official update, it will be processed as an official update package."
                        "\n\nSelecting \"Keep\" will keep the .zip files once the process is complete."
                        "\nSelecting \"Delete\" will delete the .zip files once the process is complete."
                        "\n\nWould you like to remove .zip files?", yes_label="Keep", no_label="Delete")

    update_dir = get_default_update_dir()
    update_dir = get_valid_path_portion(update_dir)

    if code == d.OK:
        manual_updates_dialog(update_dir, False)

    if code == d.CANCEL:
        manual_updates_dialog(update_dir, True)

    return


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
            
            updates_status += "{} ({}) [{}]".format(update[0], update[3], update_status)

    if len(all_updates) == 0:
        set_config_value("CONFIG_ITEMS", "show_all_updates", "True")
        d.msgbox("No updates are needed.")
        check_update_status_dialog(available_updates=available_updates)
        return

    update_totals = "Show All Updates is {}\n\nNumber of available updates: {} ({})\nNumber of updates needed: {} ({})\nRecommended number of updates: {} ({})\n\n".format("on" if show_all_updates == True else "off", len(available_updates), get_total_size_of_updates(available_updates), len(needed_updates), get_total_size_of_updates(needed_updates), len(recommended_updates), get_total_size_of_updates(recommended_updates))
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


def improvements_dialog():
    code, tag = d.menu("Select Option", 
                    choices=[("1", "Download and Install Updates"),
                             ("2", "Manually Install Downloaded Updates"), 
                             ("3", "Update Status")],
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
            downloaded_update_question_dialog()
        elif tag == "3":
            check_update_status_dialog()

    cls()
    main_dialog()

    return


def misc_menu():
    code, tag = d.menu("Select Option",
                    choices=[("1", "System Overlays"),
                             ("2", "Handheld Mode"),
                             ("3", "Reset Permissions"),
                             ("4", "Gamelist (Etc) Utilities"),
                             ("5", "Select Update Notification"),
                             ("6", "Toggle Auto Clean"),
                             ("7", "Toggle Count Official Only")],
                    title="System Tools and Utilities")

    if code == d.OK:

        if tag == "1":
            if not check_internet():
                d.msgbox("You need to be connected to the internet for this.")
                misc_menu()
            else:
                overlays_dialog()
        elif tag == "2":
            if not check_internet():
                d.msgbox("You need to be connected to the internet for this.")
                misc_menu()
            else:
                handheld_dialog()
        elif tag == "3":
            fix_permissions()
        elif tag == "4":
            gamelist_utilities_dialog()
        elif tag == "5":
            select_notification()
        elif tag == "6":
            toggle_autoclean()
        elif tag == "7":
            toggle_countofficialonly()

    cls()
    main_dialog()

    return


def support_dialog():
    d.msgbox("Rick Dangerous's Discord server is https://discord.gg/H3FdEanPmv"
             "\n\nThe Insanium Update Guide channel can be found here"
             "\n\nhttps://discord.com/channels/857515631422603286/1059484786302922842"
             "\n\nDocumentation for this Update Tool can be found here"
             "\n\nhttps://github.com/h3xp/RickDangerousUpdate"
             "\n\nPlease use Google Lens to grab these links to avoid typing mistakes.")

    main_dialog()

    return


def main_dialog():
    global update_available_result
    if update_available_result == "no connection":
        update_available_result = update_available()

    code, tag = d.menu("Main Menu", 
                    choices=[("1", "Improvements"),    
                             ("2", "System Tools and Utilities"),
                             ("3", "Installation"),
                             ("4", "Support")],
                             
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
            support_dialog()

    if code == d.CANCEL:
        cls()
        exit(0)

    return


def check_drive():
    if os.environ.get('RickDangerousUpdateTests') is not None:
       return "https://mega.nz/folder/tQpwhD7a#WA1sJBgOKJzQ4ybG4ozezQ"
    else:
        if os.path.exists("/home/pi/.update_tool/update_tool.ini"):
            config = configparser.ConfigParser()
            config.read("/home/pi/.update_tool/update_tool.ini")
            if config.has_option("CONFIG_ITEMS", "mega_dir"):
                return config["CONFIG_ITEMS"]["mega_dir"]

        if len(sys.argv) > 1:
            pattern = re.compile("^https://mega\.nz/((folder|file)/([^#]+)#(.+)|#(F?)!([^!]+)!(.+))$")
            if pattern.match(str(sys.argv[1])):
                return str(sys.argv[1])

        print("You didnt provide a link to the mega drive.")
        exit(1)


def check_root(directory):
    for files in os.listdir(directory):
        if os.path.exists(directory / "etc" / "emulationstation"):
            return True
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


def get_total_size_of_updates(updates: list):
    total_size = 0

    for update in updates:
        total_size += int(update[4])

    return convert_filesize(str(total_size))


def official_improvements_dialog(update_dir=None, delete=False, available_updates=[]):
    megadrive = check_drive()
    check_wrong_permissions()

    reboot_msg = "Updates installed:"
    title_msg  = "Download and Install Official Updates"
    if update_dir is not None:
        title_msg  = "Manually Install Official Updates"

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
            menu_choices.append(("{} ({})".format(update[0], update[3]), "", not update_applied))

    if len(all_updates) == 0:
        set_config_value("CONFIG_ITEMS", "show_all_updates", "True")
        d.msgbox("No updates are needed.")
        official_improvements_dialog(update_dir, delete, available_updates)
        return

    update_text = "Available" if show_all_updates == True else "Recommended"
    code, tags = d.checklist(text="Auto Clean is {}\nShow All Updates is {}\n\nNumber of available updates: {} ({})\nNumber of updates needed: {} ({})\nRecommended number of updates: {} ({})\n\n{} Updates".format("on" if auto_clean == True else "off", "on" if show_all_updates == True else "off", len(available_updates), get_total_size_of_updates(available_updates), len(needed_updates), get_total_size_of_updates(needed_updates), len(recommended_updates), get_total_size_of_updates(recommended_updates), update_text),
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
                if "{} ({})".format(update[0], update[3]) == tag:
                    reboot_msg += "\n" + tag
                    selected_updates.append(update)
                    break

    if code == d.EXTRA:
        if d.yesno(text="Are you sure you want to apply all available updates?") == d.OK:
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
        print()
        if update_dir is None:
            do_improvements(selected_updates, megadrive, auto_clean=auto_clean)
        else:
            process_manual_updates(update_dir, selected_updates, delete, auto_clean=auto_clean)
        #reboot_msg += "\n\n" + "Rebooting in 5 seconds!"

    return


def update_config(extracted: str):
    tmp_config = Path(extracted, "home", "pi", ".update_tool", "update_tool.ini")
    ini_file = "/home/pi/.update_tool/update_tool.ini"
    if not os.path.exists(tmp_config):
        return
    if not os.path.exists(ini_file):
        return

    new_config = configparser.ConfigParser()
    new_config.optionxform = str
    config_file = configparser.ConfigParser()
    config_file.optionxform = str

    new_config.read(tmp_config)
    config_file.read(ini_file)

    for section in new_config.sections():
        if len(new_config[section]) > 0:
            if config_file.has_section(section):
                config_file.remove_section(section)

            config_file.add_section(section)
            for key in new_config[section]:
                config_file[section][key] = str(new_config[section][key]).strip()

    with open(ini_file, 'w') as configfile:
        config_file.write(configfile)

    os.remove(tmp_config)

    return


def process_improvement(file: str, extracted: str, auto_clean=False):
    print("Processing official update: {}...".format(os.path.basename(file)))
    with zipfile.ZipFile(file, 'r') as zip_ref:
        zip_ref.extractall(extracted)

    if check_root(extracted):
        os.system("sudo chown -R pi:pi /etc/emulationstation/ > /tmp/test")

    update_config(extracted)
    make_deletions(extracted)
    merge_gamelist(extracted)
    copydir(extracted, "/")

    if check_root(extracted):
        os.system("sudo chown -R root:root /etc/emulationstation/")

    try:
        shutil.rmtree(extracted)
    except OSError as e:
        print("Error: %s : %s" % (extracted, e.strerror))
        return False

    return True


def do_improvements(selected_updates: list, megadrive: str, auto_clean=False):
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
            d.msgbox("Unable to download from MEGA.\n\nThe site enforces a 5GB per day download limit, based on your public IP address. You may have reached this limit.\n\nPlease try again later...", 10, 60)
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

    if remove_improvements == True:
        try:
            shutil.rmtree(improvements_dir)
        except OSError as e:
            print("Error: %s : %s" % (improvements_dir, e.strerror))
    
    d.msgbox("{} of {} selected updates installed.\n\nTotal time to process: {}".format(len(installed_updates), len(selected_updates), str(datetime.datetime.utcnow() - start_time)[:-7]))
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
    d.msgbox("There are no system overlays to {}.".format(enable_disable.lower()))

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
                             ok_label="{} Selected".format(enable_disable))    

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
                             ok_label="{} Selected".format(enable_disable), 
                             extra_button=True, 
                             extra_label="{} All".format(enable_disable))

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
                    choices=[("1", "Install/Reinstall"),
                             ("2", "Update"), 
                             ("3", "Uninstall/Remove")],
                    title="Installation",
                    cancel_label=" Cancel ")
    
    if code == d.OK:
        if tag == "1":
            if os.path.exists("/home/pi/.update_tool/update_tool.ini"):
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
            shutil.rmtree("/tmp/improvements")
    if os.path.exists("/tmp/extracted"):
        if os.path.isdir("/tmp/extracted"):
            shutil.rmtree("/tmp/extracted")

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


def main():
    global update_available_result
    update_available_result = update_available()

    mega_ini_check()

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
        nothing = None
    except:
        title_text = ""
        if os.path.exists("/home/pi/.update_tool/update_tool.ini"):
            datetime.datetime.utcnow()
            log_this("/home/pi/.update_tool/exception.log", "*****{}\n{}".format(datetime.datetime.utcnow(), traceback.format_exc()))
            log_this("/home/pi/.update_tool/exception.log", "\n\n")
            title_text = "A copy of this exception is logged in /home/pi/.update_tool/exception.log for your records\n\n"

        d.msgbox(title_text + traceback.format_exc(), title="Something has gone really bad...")
