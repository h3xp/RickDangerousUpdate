"""
Update Script for Rick Dangerous' Minecraftium Edition
https://github.com/h3xp/RickDangerousUpdate
"""

from genericpath import isdir, isfile
from http.client import OK
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
from packaging import version
import copy

d = Dialog()
d.autowidgetsize = True

logger = logging.getLogger(__name__)
config = configparser.ConfigParser()
genres = ["Action", "Action-Adventure", "Adventure", "Beat'em up", "Fighting", "Platform", "Puzzle", "Racing", "Role Playing Games", "Shoot'em up", "Simulation", "Sports", "Strategy"]
update_available_result = "no connection"

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

    return "https://raw.githubusercontent.com/h3xp/RickDangerousUpdate"
    
    
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
    if os.path.exists("/home/pi/.update_tool/update_tool.ini"):
        if os.path.isfile("/home/pi/.update_tool/update_tool.ini"):
            config_file = configparser.ConfigParser()
            config_file.read("/home/pi/.update_tool/update_tool.ini")
            if config_file.has_option(section, key):
                return config_file[section][key]

    return None


def set_config_value(section: str, key: str, value: str):
    if os.path.exists("/home/pi/.update_tool/update_tool.ini"):
        if os.path.isfile("/home/pi/.update_tool/update_tool.ini"):
            config_file = configparser.ConfigParser()
            config_file.read("/home/pi/.update_tool/update_tool.ini")
            if config_file.has_section(section):
                config_file[section][key] = value

                with open("/home/pi/.update_tool/update_tool.ini", 'w') as configfile:
                    config_file.write(configfile)

                    return True
    return False


def restart_es():
    runcmd("sudo reboot")
    #runcmd("touch /tmp/es-restart && pkill -f \"/opt/retropie/supplementary/.*/emulationstation([^.]|$)\"")
    #runcmd("sudo systemctl restart autologin@tty1.service")
    return


def is_update_applied(key: str, modified_timestamp: str):
    if os.path.exists("/home/pi/.update_tool/update_tool.ini") == False:
        return False

    config = configparser.ConfigParser()
    config.read("/home/pi/.update_tool/update_tool.ini")
    if config.has_option("INSTALLED_UPDATES", key):
        return config["INSTALLED_UPDATES"][key] == str(modified_timestamp)

    return False


def uninstall():
    git_repo = get_git_repo()
    git_branch = get_git_branch()
    runcmd("bash <(curl '{}/{}/install.sh' -s -N) {} -remove".format(git_repo, git_branch, git_branch))
    return

def update():
    git_repo = get_git_repo()
    git_branch = get_git_branch()
    runcmd("bash <(curl '{}/{}/install.sh' -s -N) {} -update".format(git_repo, git_branch, git_branch))
    return


def install():
    git_repo = get_git_repo()
    git_branch = get_git_branch()
    megadrive = check_drive()
    runcmd("bash <(curl '{}/{}/install.sh' -s -N) {} {}".format(git_repo, git_branch, git_branch, megadrive))
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
        modified_date = node["ts"]
        if node["t"] == 0:
            #print("file_name: {}\tfile_id: {}".format(file_name, file_id))
            available_updates.append([file_name, file_id, modified_date])
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
    d.msgbox("Done! The permissions bug has been fixed!")
    main_dialog()


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
            return file_name

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

        return False
    else:
        for file in good_files:
            if file in m3u_files:
                index = m3u_files.index(os.path.basename(file))
                del m3u_files[index]

    return True


def process_supporting_files(src_game: ET.Element, src_name: str, subelement_name: str, system_roms: str, rom_file: str, supporting_files_dir_name: str, supporting_files_dir: str, supporting_files_types: list, supporting_files: list, found_files: list, log_file: str):
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
            path = os.path.join(supporting_files_dir, file)
            if src_node.text[0:1] == "/":
                path = src_node.text

            if not os.path.isfile(path):
                # look for file based on rom name
                log_this(log_file, "-{} file \"{}\" (full path \"{}\") does not exist for rom \"{}\" ({})".format(subelement_name, file, path, rom_file, src_name))
                file = look_for_supporting_files(rom_file, supporting_files_dir, supporting_files_types)
                if len(file) > 0:
                    log_this(log_file, "-{} file found: \"{}\" for rom \"{}\"".format(subelement_name, file, rom_file))
                    src_node.text = file
                    _new_element(src_node, subelement_name, log_file)
        else:
            # look for file based on rom name
            log_this(log_file, "-no {} defined for rom \"{}\" ({})".format(subelement_name, rom_file, src_name))
            file = look_for_supporting_files(rom_file, supporting_files_dir, supporting_files_types)
            if len(file) > 0:
                log_this(log_file, "-{} file found: \"{}\" for rom \"{}\"".format(subelement_name, file, rom_file))
                src_node.text = file
                _new_element(src_node, subelement_name, log_file)
    else:
        # look for file based on rom name and add to element tree if it exists
        log_this(log_file, "-no {} element defined in gamelist.xml for rom \"{}\"".format(subelement_name, rom_file))
        file = look_for_supporting_files(rom_file, supporting_files_dir, supporting_files_types)
        if len(file) > 0:
            child = ET.SubElement(src_game, subelement_name)
            child.text = "./{}/{}".format(supporting_files_dir, file)
            log_this(log_file, "-{} file found: \"{}\" for rom \"{}\"".format(subelement_name, file, rom_file))
            _new_element(child, subelement_name, log_file)

    # delete validated files
    if len(file) > 0:
        if file in supporting_files:
            if file not in found_files:
                found_files.append(file)
            index = supporting_files.index(file)
            del supporting_files[index]

    return


def process_orphaned_files(orphaned_files: list, dir: str, log_file: str, file_type: str, clean=False):
    orphaned_files.sort()
    process = "DELETING" if clean == True else "IDENTIFIED"
    for orphaned_file in orphaned_files:
        file_path = os.path.join(dir, orphaned_file)
        if os.path.exists(file_path):
            log_this(log_file, "-{} orphaned {} file: \"{}\"".format(process, file_type, file_path))
            if clean == True:
                os.remove(file_path)

    return


def delete_gamelist_entry_dialog(rom: str):
    code = d.yesno("Gamelist entry for {} has invalid rom entries, would you like to remove it from your gamelist.xml?".format(rom))

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


def process_gamelist(system: str, gamelist_roms_dir: str, log_file: str, del_roms=False, del_art=False, del_snaps=False, del_m3u=False, clean=False):
    file_time = datetime.datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    rom_dir = "/home/pi/RetroPie/roms"
    art_dir = "boxart"
    snaps_dir = "snaps"
    m3u_dir = ".data"
    art_types = [".png", ".jpg"]
    snaps_types = [".mp4"]
    do_not_delete = ["neogeo.zip"]
    no_m3u_spport = ["atari800"]

    system_gamelists = os.path.join(gamelist_roms_dir, system)
    system_roms = os.path.join(rom_dir, system)
    system_art = os.path.join(system_roms, art_dir)
    system_snaps = os.path.join(system_roms, snaps_dir)
    system_m3u = os.path.join(system_roms, m3u_dir)

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

    # remove duplicate gamelist entries
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

        # get rom file
        src_node = src_game.find("path")
        if src_node is not None:
            if src_node.text is not None:
                found_files = []
                rom_file = os.path.basename(src_node.text)
                rom_path = os.path.join(system_roms, rom_file)
                if src_node.text[0:1] == "/":
                    rom_path = src_node.text
                
                if os.path.exists(rom_path):
                    found_files.append(rom_file)
                    if rom_file in rom_files:
                        keep_rom = True
                        if os.path.splitext(rom_file)[1] == ".m3u":
                            keep_rom &= process_m3u_file(rom_path, src_game, src_tree, system_roms, m3u_files, log_file)
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
                process_supporting_files(src_game, src_name, "image", system_roms, rom_file, art_dir, system_art, art_types, art_files, found_files, log_file)

                # check if snap exists
                process_supporting_files(src_game, src_name, "video", system_roms, rom_file, snaps_dir, system_snaps, snaps_types, snaps_files, found_files, log_file)

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
            log_this(log_file, "-auto removing gamelist.xml entry for {} because it has 0 rom, image, or video files".format(entry))
            log_this(log_file, ET.tostring(parent).decode())
            #src_root.remove(parent)

        #safe_write_backup(src_xml, file_time)
        
        #indent(src_root, space="\t", level=0)
        #with open(src_xml, "wb") as fh:
        #    src_tree.write(fh, "utf-8")

        #if safe_write_check(src_xml, file_time) == False:
        #    log_this(log_file, "-writing to {} FAILED".format(src_xml))

    # clean out bad roms from gamelist
    for rom_file in bad_roms:
        parents = src_tree.findall(".//game[path=\"./{}\"]".format(rom_file))
        for parent in parents:
            if clean == True:
                if delete_gamelist_entry_dialog(rom_file) == True:
                    log_this(log_file, "-removing gamelist.xml entry for {}".format(rom_file))
                    log_this(log_file, ET.tostring(parent).decode())
                    src_root.remove(parent)
                else:
                    log_this(log_file, "-overridden: removing gamelist.xml entry for {}".format(rom_file))
                    log_this(log_file, ET.tostring(parent).decode())
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
        process_orphaned_files(rom_files, system_roms, log_file, "rom", clean=clean)

    # clean art
    if del_art == True:
        process_orphaned_files(art_files, system_art, log_file, "image", clean=clean)

    # clean snaps
    if del_snaps == True:
        process_orphaned_files(snaps_files, system_snaps, log_file, "video", clean=clean)

    # clean m3u
    if del_m3u == True:
        if system not in no_m3u_spport:
            process_orphaned_files(m3u_files, system_m3u, log_file, "m3u disk", clean=clean)
        else:
            log_this(log_file, "-cannot process orphaned files from {} directory because m3u file is not supported for {}".format(m3u_dir, system))
    
    return


def do_process_gamelists(systems: list, del_roms=False, del_art=False, del_snaps=False, del_m3u=False, clean=False):
    file_time = datetime.datetime.utcnow()
    process_type = "clean" if clean == True else "check"
    gamelist_roms_dir = "/home/pi/RetroPie/roms"
    check_gamelist_roms_dir = get_config_value("CONFIG_ITEMS", "check_gamelists_roms_dir")
    if check_gamelist_roms_dir is not None:
        gamelist_roms_dir = check_gamelist_roms_dir

    log_file = "/home/pi/.update_tool/{}_gamelists-{}.log".format(process_type, file_time.strftime("%Y%m%d-%H%M%S"))

    with open(log_file, 'w', encoding='utf-8') as logfile:
        logfile.write("{}ING GAMELISTS: started at {}".format(process_type.upper(), file_time))

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
            process_gamelist(single_system, gamelist_roms_dir, log_file, del_roms=del_roms, del_art=del_art, del_snaps=del_snaps, del_m3u=del_m3u, clean=clean)

    log_this(log_file, "\n")
    log_this(log_file, "{}ING GAMELISTS: ended at {}".format(process_type.upper(), datetime.datetime.utcnow()))
    cls()
    d.textbox(log_file, title="Contents of {0}".format(log_file))

    cls()
    main_dialog()

    return


def gamelists_orphan_dialog(systems, clean: bool):
    menu_text = ""
    if clean == True:
        menu_text = ("Clean Orphaned Files"
                    "\n\nThis will clean your gamelist.xml files and optionally remove orphaned roms, artwork,  video snapshots, and multiple disk (m3u) files according to your choices below."
                    "\n\nThe results of this procedure can be viewed in the \"/home/pi/.update_tool\" folder, it will be called \"clean_gamelists-[date]-[time].log"
                    "\n\nWARNING: removing orphaned files will permantly DELETE them and you will not get them back, only do this if you REALLY want to..."
                    "\n\nRemove orphaned:")
    else:
        menu_text = ("Check Orphaned Files"
                    "\n\nThis will check your gamelist.xml files and optionally check for orphaned roms, artwork, video snapshots, and multiple disk (m3u) files according to your choices below."
                    "\n\nThe results of this procedure can be viewed in the \"/home/pi/.update_tool\" folder, it will be called \"check_gamelists-[date]-[time].log"
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
    global genres
    dialog_text = ""
    menu_choices = []

    genres.sort()
    for genre in genres:
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
                             title="Manually Select Genres")

    if code == d.OK:
        genre = elem.find("genre")
        if genre is not None:
            genre.text = tag
        else:
            elem.append(ET.fromstring("<genre>{}</genre>".format(tag)))

    if code == d.CANCEL:
        return False

    return True


def do_gamelist_genres(systems: list):
    def _process_entry(elem: ET.Element):
        genre = elem.find("genre")
        if genre is not None:
            if genre.text is not None:
                return genre.text not in genres

        return True

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


def gamelists_dialog(function: str):
    rom_dir = "/home/pi/RetroPie/roms"
    art_dir = "boxart"
    snaps_dir = "snaps"

    dialog_title = ""
    if function == "Check":
        dialog_title = "Check Game Lists"
    elif function == "Clean":
        dialog_title = "Clean Game Lists"
    elif function == "Genre":
        dialog_title = "Manually Select Genres"

    systems = get_all_systems_from_dirs()
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
        else:
            gamelists_orphan_dialog(tags, function == "Clean")

    if code == d.EXTRA:
        if function == "Genre":
            do_gamelist_genres(systems)
        else:
            gamelists_orphan_dialog(systems, function == "Clean")        

    if code == d.CANCEL:
        cls()
        gamelist_utilities_dialog()

    cls()
    gamelists_dialog(function)

    return


def gamelist_utilities_dialog():
    code, tag = d.menu("Main Menu", 
                    choices=[("1", "Check Game Lists"), 
                             ("2", "Clean Game Lists"), 
                             ("3", "Manually Select Genres")],
                    title="Game List Utilities")
    
    if code == d.OK:
        if tag == "1":
            gamelists_dialog("Check")
        elif tag == "2":
            gamelists_dialog("Clean")
        elif tag == "3":
            gamelists_dialog("Genre")

    if code == d.CANCEL:
        cls()
        main_dialog()

    return


def process_manual_updates(path: str, delete: bool):
    files = []
    megadrive = check_drive()
    available_updates = get_available_updates(megadrive)
    extracted = Path("/", "tmp", "extracted")

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
            if update[0] == os.path.basename(file):
                if process_improvement(file, extracted) == True:
                    if delete == True:
                        os.remove(file)

                    set_config_value("INSTALLED_UPDATES", update[0], str(update[2]))
                break

    if os.path.isdir(path):
        if delete == True:
            if len(os.listdir(path)) == 0:
                shutil.rmtree(path)

    return


def get_valid_path_portion(path: str):
    return_path = ""
    parts = path.split("/")
    for part in parts:
        if len(part) > 0:
            if os.path.isdir(os.path.join(return_path, "/" + part)) == True or os.path.isfile(os.path.join(return_path, "/" + part)) == True:
                return_path += "/" + part

    if os.path.isdir(return_path):
        return_path += "/"

    return return_path


def manual_updates_dialog(init_path: str, delete: bool):
    help_text = ("Type the path to directory or file directly into the text entry window."
                  "\nAs you type the directory or file will be highlighted, at this point you can press [Space] to add the highlighted item to the path."
                  "\n\nIf you are adding a directory to the text entry window, and the path ends with a \"/\", the files in that directory will automatically show in the \"Files\" window."
                  "\nYou can use also cycle through the windows with [Tab] or [Arrow] keys.")
    code, path = d.fselect(init_path, height=10, width=60, help_button=True)

    if code == d.OK:
        if os.path.isdir(path) or os.path.isfile(path):
            process_manual_updates(path, delete)
        else:
            d.msgbox("Invalid path!")
            path = get_valid_path_portion(path)
            path = "/" if len(path) == 0 else path
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


def downloaded_update_question_dialog():
    code = d.yesno(text="You will be asked to choose a .zip file to load, or a directory where multiple .zip files are located."
                         "\nThis will process the .zip file(s)?"
                         "\n\nIf the name of a .zip file is identified as a valid official update, it will be processed as an official update package."
                         "\n\nSelecting \"Yes\" will delete the .zip files and directories once the process is complete."
                         "\nSelecting \"No\" will leave the .zip files and directories once the process is complete."
                         "\n\nWould you like to remove .zip files and directories?")

    if code == d.OK:
        manual_updates_dialog("/", True)

    if code == d.CANCEL:
        manual_updates_dialog("/", False)

    return

def improvements_dialog():
    code, tag = d.menu("Load Improvements", 
                    choices=[("1", "Download and Install Official Updates"), 
                             ("2", "Install Downloaded Updates")],
                    title="Load Improvements")

    if code == d.OK:
        if tag == "1":
            if not check_internet():
                d.msgbox("You need to be connected to the internet for this.")
                improvements_dialog()
            else:
                official_improvements_dialog()
        elif tag == "2":
            downloaded_update_question_dialog()

    return


def main_dialog():
    global update_available_result
    if update_available_result == "no connection":
        update_available_result - update_available()

    code, tag = d.menu("Main Menu", 
                    choices=[("1", "Load Improvements"), 
                             ("2", "Fix Known Bugs"), 
                             ("3", "Restore Retroarch Configurations"), 
                             ("4", "Reset EmulationStation Configurations"), 
                             ("5", "System Overlays"),
                             ("6", "Handheld Mode"),
                             ("7", "Gamelist Utilities"),
                             ("8", "Installation")],
                    title=check_update(),
                    backtitle="Rick Dangerous Insanium Edition Update Tool",
                    cancel_label=" Exit ")
    
    if code == d.OK:
        if tag == "1":
            improvements_dialog()
        elif tag == "2":
            bugs_dialog()
        elif tag == "3":
            if not check_internet():
                d.msgbox("You need to be connected to the internet for this.")
                main_dialog()
            else:
                restore_retroarch_dialog()
        elif tag == "4":
            if not check_internet():
                d.msgbox("You need to be connected to the internet for this.")
                main_dialog()
            else:
                reset_controls_dialog()
        elif tag == "5":
            if not check_internet():
                d.msgbox("You need to be connected to the internet for this.")
                main_dialog()
            else:
                overlays_dialog()
        elif tag == "6":
            if not check_internet():
                d.msgbox("You need to be connected to the internet for this.")
                main_dialog()
            else:
                handheld_dialog()
        elif tag == "7":
            gamelist_utilities_dialog()
        elif tag == "8":
            if not check_internet():
                d.msgbox("You need to be connected to the internet for this.")
                main_dialog()
            else:
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


def official_improvements_dialog():
    megadrive = check_drive()
    check_wrong_permissions()
    reboot_msg = "Updates installed:"

    available_updates = get_available_updates(megadrive)
    available_updates.sort()

    menu_choices = []
    for update in available_updates:
        #TO DO: check if update has been installed from config and make True
        menu_choices.append((update[0], "", not is_update_applied(update[0], update[2])))

    code, tags = d.checklist(text="Available Updates",
                             choices=menu_choices,
                             ok_label="Apply Selected", 
                             extra_button=True, 
                             extra_label="Apply All", 
                             title="Download and Install Official Updates")

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


def process_improvement(file: str, extracted: str):
    print("Processing official update: {}...".format(os.path.basename(file)))
    with zipfile.ZipFile(file, 'r') as zip_ref:
        zip_ref.extractall(extracted)

    if check_root(extracted):
        os.system("sudo chown -R pi:pi /etc/emulationstation/ > /tmp/test")

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
                for update in selected_updates:
                    if update[0] == filename:
                        install_candidates.append((update[0], update[2]))
    #install_candidates.sort()
    install_candidates.sort(key = lambda x: x[0])
    remove_improvements = True
    for install_file in install_candidates:
        f = os.path.join(improvements_dir, install_file[0])
        improvement_passed = process_improvement(f, extracted)
        if improvement_passed == True:
            set_config_value("INSTALLED_UPDATES", install_file[0], str(install_file[1]))

        remove_improvements = remove_improvements & improvement_passed

        try:
            shutil.rmtree(extracted)
        except OSError as e:
            print("Error: %s : %s" % (extracted, e.strerror))

    if remove_improvements == True:
        try:
            shutil.rmtree(improvements_dir)
        except OSError as e:
            print("Error: %s : %s" % (improvements_dir, e.strerror))
    
    return


def do_system_overlay(system: str, enable_disable = "Enable"):
    file_time = datetime.datetime.utcnow().strftime("%Y%m%d-%H%M%S")
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
            safe_write_backup(os.path.join(system, "retroarch.cfg"), os.path.join(system, "retroarch.cfg"), file_time)

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
        for system in menu_choices[0]:
            do_system_overlay(system, enable_disable)

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


def bugs_dialog():
    code, tag = d.menu("Bugs Menu", 
                    choices=[("1", "Fix permissions")], 
                    title="Fix Known Bugs")
    
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
    urllib.request.urlretrieve("https://raw.githubusercontent.com/h3xp/RickDangerousUpdate/main/configs/retroarch_configs.zip", localpath / "retroarch_configs.zip")
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
        "https://raw.githubusercontent.com/h3xp/RickDangerousUpdate/main/configs/emulationstation_configs.zip",
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
    global update_available_result
    update_available_result = update_available()

    if update_available_result == "update available" or update_available_result == "alt branch":
        code = d.yesno('Continue with update?')

        if code == d.OK:
            update()
            reboot_msg = "\nUpdate tool has been updated, rebooting in 5 seconds!\n"
            d.pause(reboot_msg, height=10, width=60)
            restart_es()
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


def main():
    global update_available_result
    update_available_result = update_available()

    if runcmd("id -u -n") == "pi\n":
        hostname_dialog()
    else:
        user_dialog()

main()