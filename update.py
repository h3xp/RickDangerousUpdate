"""
Update Script for Rick Dangerous' Minecraftium Edition
https://github.com/h3xp/RickDangerousUpdate
"""

from genericpath import isfile
import os
import zipfile
import platform
from distutils.dir_util import copy_tree
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

if platform.uname()[1] == "retropie":
    d = Dialog()
    d.autowidgetsize = True

logger = logging.getLogger(__name__)
config = configparser.ConfigParser()


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


def get_config_value(section: str, key: str):
    config_file = configparser.ConfigParser()
    config_file.read("/home/pi/.update_tool/update_tool.ini")
    if config_file.has_option(section, key):
        return config_file[section][key]

    return None


def restart_es():
    runcmd("sudo reboot")
    #runcmd("touch /tmp/es-restart && pkill -f \"/opt/retropie/supplementary/.*/emulationstation([^.]|$)\"")
    #runcmd("sudo systemctl restart autologin@tty1.service")
    return


def is_update_applied(key: str):
    if os.path.exists("/home/pi/.update_tool/update_tool.ini") == False:
        return False

    config = configparser.ConfigParser()
    config.read("/home/pi/.update_tool/update_tool.ini")
    if config.has_option("INSTALLED_UPDATES", key):
        return True

    return False


def uninstall():
    runcmd("bash <(curl 'https://raw.githubusercontent.com/h3xp/RickDangerousUpdate/v1.0.1/install.sh' -s -N) -remove")
    return

def update():
    runcmd("bash <(curl 'https://raw.githubusercontent.com/h3xp/RickDangerousUpdate/v1.0.1/install.sh' -s -N) -update")
    return


def install():
    megadrive = check_drive()
    runcmd("bash <(curl 'https://raw.githubusercontent.com/h3xp/RickDangerousUpdate/v1.0.1/install.sh' -s -N) {}".format(megadrive))
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


def get_available_updates(megadrive):
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
        if node["t"] == 0:
            #print("file_name: {}\tfile_id: {}".format(file_name, file_id))
            available_updates.append([file_name, file_id])
    return available_updates


def download_update(ID, destdir, megadrive):
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
            print("Downloading: {}...".format(attrs["n"]))
            file_data = get_file_data(file_id, root_folder)
            download_file(file_id, key, file_data, str(destdir))
            print("Processing: {}...".format(attrs["n"]))


def cls():
    os.system('cls' if os.name == 'nt' else 'clear')


def runcmd(command):
    code = subprocess.check_output(["bash","-c",command])
    return str(code, "UTF-8")
    #return os.popen(command).read()


def copyfile(localpath, filepath):
    shutil.copy(localpath, filepath)


def copydir(source_path, target_path):
    copy_tree(source_path, target_path)


def fix_permissions():
    runcmd('sudo chown -R pi:pi ~/RetroPie/roms/ && sudo chown -R pi:pi ~/.emulationstation/')


def permissions_dialog():
    code = d.yesno('Your permissions seem to be wrong, which is a known bug in this image.\nThis might prevent you from '
            'saving configurations, gamestates and metadata.\nDo you want this script to fix this issue for you?\n')

    if code == d.OK:
        fix_permissions()

    return


def check_wrong_permissions():
    output = runcmd('ls -la /home/pi/RetroPie/ | grep roms | cut -d \' \' -f3,4')
    if output.rstrip() != 'pi pi':
        permissions_dialog()
    else:
        output = runcmd('ls -la /home/pi/.emulationstation/gamelists/retropie | grep gamelist.xml | cut -d \' \' -f3,4')
        if output.rstrip() != 'pi pi':
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

        # Dedent after the last child by overwriting the previous indentation.
        if not child.tail.strip():
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
                                dest_node.text

    shutil.copy2(dest_xml, dest_xml + "." + file_time)
    dest_tree = ET.ElementTree(dest_root)
    
    # ET.indent(dest_tree, space="\t", level=0)
    indent(dest_root, space="\t", level=0)
    with open(dest_xml, "wb") as fh:
        dest_tree.write(fh, "utf-8")

    if os.path.getsize(dest_xml) > 0:
        os.remove(dest_xml + "." + file_time)

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


def main_dialog():
    code, tag = d.menu("Main Menu", 
                    choices=[("1", "Load improvements"), 
                             ("2", "Fix known bugs"), 
                             ("3", "Restore Retroarch configurations"), 
                             ("4", "Reset emulationstation configurations"), 
                             ("5", "System overlays"), 
                             ("6", "Installation")], 
                    cancel_label=" Exit ")
    
    if code == d.OK:
        if tag == "1":
            improvements_dialog()
        elif tag == "2":
            bugs_dialog()
        elif tag == "3":
            restore_retroarch_dialog()
        elif tag == "4":
            reset_controls_dialog()
        elif tag == "5":
            overlays_dialog()
        elif tag == "6":
            installation_dialog()

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


def improvements_dialog():
    megadrive = check_drive()
    check_wrong_permissions()
    reboot_msg = "Updates installed:"

    available_updates = get_available_updates(megadrive)
    available_updates.sort()

    menu_choices = []
    for update in available_updates:
        #TO DO: check if update has been installed from config and make True
        menu_choices.append((update[0], "", not is_update_applied(update[0])))

    code, tags = d.checklist(text="Available Updates",
                             choices=menu_choices,
                             ok_label="Apply Selected", 
                             extra_button=True, 
                             extra_label="Apply All")

    selected_updates = []
    if code == d.OK:
        for tag in tags:
            for update in available_updates:
                if update[0] == tag:
                    reboot_msg += "\n" + tag
                    selected_updates.append(update)
                    break

    if code == d.EXTRA:
        selected_updates = available_updates

    if code == d.CANCEL:
        cls()
        main_dialog()

    if len(selected_updates) > 0:
        print()
        do_improvements(selected_updates, megadrive)
        #reboot_msg += "\n\n" + "Rebooting in 5 seconds!"
        reboot_msg = "\nUpdates installed, rebooting in 5 seconds!\n"
        d.pause(reboot_msg, height=10, width=60)
        restart_es()

    return


def do_improvements(selected_updates: list, megadrive: str):
    improvements_dir = Path("/", "tmp", "improvements")
    os.makedirs(improvements_dir, exist_ok=True)
    extracted = improvements_dir / "extracted"

    for update in selected_updates:
        download_update(update[1], improvements_dir, megadrive)

    install_candidates = []
    for filename in os.listdir(improvements_dir):
        f = os.path.join(improvements_dir, filename)
        if os.path.isfile(f):
            if f.endswith(".zip"):
                install_candidates.append(filename)
    install_candidates.sort()
    for filename in install_candidates:
        f = os.path.join(improvements_dir, filename)
        with zipfile.ZipFile(f, 'r') as zip_ref:
            zip_ref.extractall(extracted)
        if check_root(extracted):
            os.system("sudo chown -R pi:pi /etc/emulationstation/ > /tmp/test")
            make_deletions(extracted)
            merge_gamelist(extracted)
            copydir(extracted, "/")
            os.system("sudo chown -R root:root /etc/emulationstation/")
        else:
            make_deletions(extracted)
            merge_gamelist(extracted)
            copydir(extracted, "/")

        if os.path.exists("/home/pi/.update_tool/update_tool.ini"):
            config = configparser.ConfigParser()
            config.read("/home/pi/.update_tool/update_tool.ini")
            config["INSTALLED_UPDATES"][filename] = datetime.datetime.utcnow().strftime("%Y%m%d-%H%M%S")

            with open("/home/pi/.update_tool/update_tool.ini", 'w') as configfile:
                config.write(configfile)


        try:
            shutil.rmtree(extracted)
        except OSError as e:
            print("Error: %s : %s" % (extracted, e.strerror))
    try:
        shutil.rmtree(improvements_dir)
    except OSError as e:
        print("Error: %s : %s" % (improvements_dir, e.strerror))
    
    return


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
                        if enable_disable == "Enable":
                            if line.strip()[0:1] == "#":
                                line = line.strip()[1:] + "\n"
                        else:
                            line = "#" + line.strip() + "\n"

                    lines_out += line

            with open(os.path.join(system, "retroarch.cfg"), 'w') as configfile:
                configfile.write(lines_out)

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
        for system in menu_choices[0]:
            do_system_overlay(system, enable_disable)

    cls()
    overlays_dialog()
                
    return


def  overlays_dialog():
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


def bugs_dialog():
    code, tag = d.menu("Bugs Menu", 
                    choices=[("1", "Fix permissions")])
    
    if code == d.OK:
        if tag == "1":
            fix_permissions()

    if code == d.CANCEL:
        main_dialog()

    return


def restore_retroarch_dialog():
    code = d.yesno(text="Are you sure you want to reset all retroarch.cfgs?")

    if code == d.OK:
        do_retroarch_configs()

    if code == d.CANCEL:
        main_dialog()

    return


def do_retroarch_configs():
    localpath = Path("/", "tmp")
    urllib.request.urlretrieve("https://raw.githubusercontent.com/h3xp/RickDangerousUpdate/main/retroarch_configs.zip", localpath / "retroarch_configs.zip")
    f = os.path.join(localpath, "retroarch_configs.zip")
    if os.path.isfile(f):
        with zipfile.ZipFile(f, 'r') as zip_ref:
            zip_ref.extractall(localpath / "retroarch_configs")
        copydir(localpath / "retroarch_configs/", "/opt/retropie/configs/")
        try:
            shutil.rmtree(localpath / "retroarch_configs")
        except OSError as e:
            print("Error: %s : %s" % (localpath / "retroarch_configs", e.strerror))
        os.remove(localpath / "retroarch_configs.zip")

    return


def reset_controls_dialog():
    code = d.yesno(text="Are you sure you want to reset your emulationstation configs?")

    if code == d.OK:
        do_retroarch_configs()

    if code == d.CANCEL:
        main_dialog()

    return


def do_emulationstation_configs():
    localpath = Path("/", "tmp")
    urllib.request.urlretrieve(
        "https://raw.githubusercontent.com/h3xp/RickDangerousUpdate/main/emulationstation_configs.zip",
        localpath / "emulationstation_configs.zip")
    f = os.path.join(localpath, "emulationstation_configs.zip")
    if os.path.isfile(f):
        with zipfile.ZipFile(f, 'r') as zip_ref:
            zip_ref.extractall(localpath / "emulationstation_configs")
        copydir(localpath / "emulationstation_configs/", "/home/pi/.emulationstation/")
        try:
            shutil.rmtree(localpath / "emulationstation_configs")
        except OSError as e:
            print("Error: %s : %s" % (localpath / "emulationstation_configs", e.strerror))
        os.remove(localpath / "emulationstation_configs.zip")

    return


def install_dialog():
    code = d.yesno('Continue with installation?\n\nThis will add the tool to the Options menu, overwriting any previous installations.')

    if code == d.OK:
        install()
        reboot_msg = "\nUpdate tool has been installed, rebooting in 5 seconds!\n"
        d.pause(reboot_msg, height=10, width=60)
        restart_es()
    return


def update_dialog():
    code = d.yesno('Continue with update?')

    if code == d.OK:
        update()
        reboot_msg = "\nUpdate tool has been updated, rebooting in 5 seconds!\n"
        d.pause(reboot_msg, height=10, width=60)
        restart_es()

    return


def uninstall_dialog():
    code = d.yesno('Continue with uninstall?\n\nThis will remove the tool from the Options menu.')

    if code == d.OK:
        uninstall()
        reboot_msg = "\nUpdate tool has been uninstalled, rebooting in 5 seconds!\n"
        d.pause(reboot_msg, height=10, width=60)
        restart_es()
    return


def installation_dialog():
    code, tag = d.menu("Installation", 
                    choices=[("1", "Install/Reinstall"),
                             ("2", "Update"), 
                             ("3", "Uninstall/Remove")],
                    cancel_label=" Cancel ")
    
    if code == d.OK:
        if tag == "1":
            install_dialog()
        elif tag == "2":
            update_dialog()
        elif tag == "3":
            uninstall_dialog()

    if code == d.CANCEL:
        cls()
        main_dialog()

    return


def main():
    main_dialog()


main()