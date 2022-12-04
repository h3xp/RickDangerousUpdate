from genericpath import isfile
import subprocess
import sys
import os
import configparser
import datetime
import shutil
import re
from pathlib import Path
import xml.etree.ElementTree as ET
import requests

git_repo = "https://raw.githubusercontent.com/h3xp/RickDangerousUpdate/main"
home_dir = "/home/pi/.update_tool"
ini_file = "/home/pi/.update_tool/update_tool.ini"
png_file = "/home/pi/RetroPie/retropiemenu/icons/update_tool.png"
gamelist_file = "/opt/retropie/configs/all/emulationstation/gamelists/retropie/gamelist.xml"
sh_file = "/home/pi/RetroPie/retropiemenu/update_tool.sh"
mega_folder = ""


def get_version(version):
    latest_tag = version
    if os.path.exists(ini_file):
        if os.path.isfile(ini_file):
            config = configparser.ConfigParser()
            config.read(ini_file)
            if config.has_option("CONFIG_ITEMS", "git_branch"):
                if config["CONFIG_ITEMS"]["git_branch"] != "main":
                    url = "https://api.github.com/repos/h3xp/RickDangerousUpdate/releases/latest"
                    resp = requests.get(url)
                    latest_tag = resp.json().get('tag_name').replace("v","")

    return latest_tag


def runcmd(command):
    return os.popen(command).read()
        

def runshell(command: str):
    code = subprocess.call(["bash","-c",command])
    return code


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

    shutil.copy2(dest_xml, dest_xml + "." + file_time)
    dest_tree = ET.ElementTree(dest_root)
    
    # ET.indent(dest_tree, space="\t", level=0)
    indent(dest_root, space="\t", level=0)
    with open(dest_xml, "wb") as fh:
        dest_tree.write(fh, "utf-8")

    if os.path.getsize(dest_xml) == 0:
        # this somehow failed badly
        shutil.copy2(dest_xml + "." + file_time, dest_xml)
    os.remove(dest_xml + "." + file_time)
        

def uninstall():
    file_time = datetime.datetime.utcnow().strftime("%Y%m%d-%H%M%S")

    if os.path.exists(home_dir):
        shutil.rmtree(home_dir)

    if os.path.exists(sh_file):
        os.remove(sh_file)

    if os.path.exists(png_file):
        os.remove(png_file)

    src_tree = ET.parse(gamelist_file)
    src_root = src_tree.getroot()

    parents = src_tree.findall(".//game[path=\"./update_tool.sh\"]")
    for parent in parents:
        src_root.remove(parent)

    shutil.copy2(gamelist_file, gamelist_file + "." + file_time)
    
    # ET.indent(dest_tree, space="\t", level=0)
    indent(src_root, space="\t", level=0)
    with open(gamelist_file, "wb") as fh:
        src_tree.write(fh, "utf-8")

    if os.path.getsize(gamelist_file) > 0:
        # this somehow failed badly
        shutil.copy2(gamelist_file + "." + file_time, gamelist_file)
    os.remove(gamelist_file + "." + file_time)
    
    ##remove cronjob
    #runcmd("crontab -l | sed '/.update_tool/d' | crontab")
    # remove autostart.sh entry if one exists
    runcmd("sed '/update_tool/d' /opt/retropie/configs/all/autostart.sh >/tmp/ut.$$ ; mv /tmp/ut.$$ /opt/retropie/configs/all/autostart.sh")

    return    


def install(overwrite=True):
    global git_repo

    file_time = datetime.datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    new_config = configparser.ConfigParser()
    new_config.optionxform = str
    old_config = configparser.ConfigParser()
    old_config.optionxform = str
    new_version_label = ""
    git_branch = "main"

    if overwrite == True:
        uninstall()
    
    if os.path.exists(home_dir) == False:
        os.mkdir(home_dir)
    if os.path.exists(ini_file) == False:
        os.mknod(ini_file)

    if os.path.exists(ini_file):
        old_config.read(ini_file)
        if old_config.has_option("CONFIG_ITEMS", "git_repo") and old_config.has_option("CONFIG_ITEMS", "git_branch"):
            git_repo = "{}/{}".format(old_config["CONFIG_ITEMS"]["git_repo"], old_config["CONFIG_ITEMS"]["git_branch"])
            git_branch = old_config["CONFIG_ITEMS"]["git_branch"]

    tmp_dir = Path("/", "tmp", "update_tool_install")
    if os.path.exists(tmp_dir) == False:
        os.mkdir(tmp_dir)
        
    #download update_tool.ini
    runshell("curl {}/update_tool.ini -o {}/update_tool.ini".format(git_repo, tmp_dir))
    #download the menu image
    runshell("curl {}/docs/options_logo.png -o {}/options_logo.png".format(git_repo, tmp_dir))
    #download the gamelist.xml
    runshell("curl {}/gamelist.xml -o {}/gamelist.xml".format(git_repo, tmp_dir))
    #download the update.py
    runshell("curl {}/update.py -o {}/update.py".format(git_repo, home_dir))
    ##download the notification.py
    #runshell("curl {}/notification.py -o {}/notification.py".format(git_repo, home_dir))

    if os.path.exists("{}/update_tool.ini".format(tmp_dir)) == True:
        new_config.read("{}/update_tool.ini".format(tmp_dir))
        if new_config.has_option("CONFIG_ITEMS", "tool_ver"):
            new_version = new_config["CONFIG_ITEMS"]["tool_ver"]
            new_version_label = "[Version {}]: ".format(new_version)
            if new_version != get_version(new_version):
                new_version_label = "[Version {} (running from version {} on branch {})]: ".format(get_version(new_version), new_version, git_branch)
                new_config["CONFIG_ITEMS"]["tool_ver"] = get_version(new_version)

    
    for section in new_config.sections():
        if len(new_config[section]) > 0:
            if section == "CONFIG_ITEMS":
                for key, val in new_config.items(section):
                    if key != "tool_ver":
                        if old_config.has_option(section, key):
                            new_config[section][key] = str(old_config[section][key]).strip()
        elif old_config.has_section(section):
            for key, val in old_config.items(section):
                new_config[section][key] = str(old_config[section][key]).strip()


    if len(mega_folder) > 0:
        pattern = re.compile("^https://mega\.nz/((folder|file)/([^#]+)#(.+)|#(F?)!([^!]+)!(.+))$")
        if pattern.match(str(mega_folder)):
            new_config["CONFIG_ITEMS"]["mega_dir"] = mega_folder

    with open(ini_file, 'w') as configfile:
        new_config.write(configfile)

    #write script
    print("Writing bash script...")
    with open("/home/pi/RetroPie/retropiemenu/{}".format("update_tool.sh"), "w") as shellfile:
        shellfile.write("#!/bin/bash\n")
        #shellfile.write("source <(grep = {} | sed 's/ *= */=/g') 2>/dev/null\n".format(ini_file))
        shellfile.write("source <(sed '/INSTALLED_UPDATES/q' {} | grep = | sed 's/ *= */=/g') 2>/dev/null\n".format(ini_file))
        shellfile.write("$home_exe $home_dir/$home_command $mega_dir $1")

    runcmd("chmod +x /home/pi/RetroPie/retropiemenu/update_tool.sh")
    runcmd("chmod +x /home/pi/.update_tool/update.py")
    runcmd("sudo ln -sf /home/pi/RetroPie/retropiemenu/update_tool.sh /usr/bin/update_tool")

    #merge gamelist
    print("Merging gamelist entries...")
    new_gamelist_path = "{}/gamelist.xml".format(tmp_dir)
    if os.path.exists(new_gamelist_path) == True:
        #update <desc>
        src_tree = ET.parse(new_gamelist_path)
        src_root = src_tree.getroot()
        for game in src_root.findall("game"):
            desc = game.find("desc")
            if desc is not None:
                desc.text = "{}{}".format(new_version_label, desc.text)
            
        shutil.copy2(new_gamelist_path, new_gamelist_path + "." + file_time)

        # ET.indent(dest_tree, space="\t", level=0)
        indent(src_root, space="\t", level=0)
        with open(new_gamelist_path, "wb") as fh:
            src_tree.write(fh, "utf-8")

        merge_xml(new_gamelist_path, gamelist_file)

        if os.path.getsize(new_gamelist_path) == 0:
            # this somehow failed badly
            shutil.copy2(new_gamelist_path + "." + file_time, gamelist_file)
        os.remove(new_gamelist_path + "." + file_time)

    #copy image file
    print("Copying icon...")
    new_banner_path = "{}/options_logo.png".format(tmp_dir)
    shutil.copy(new_banner_path, png_file)

    shutil.rmtree(tmp_dir)

    return


def main():
    global mega_folder
    if len(sys.argv) > 1:
        for arg in sys.argv:
            if arg == "-remove":
                uninstall()
                exit(0)
            elif arg == "-update":
                install(False)
                exit(0)
            else:
                pattern = re.compile("^https://mega\.nz/((folder|file)/([^#]+)#(.+)|#(F?)!([^!]+)!(.+))$")
                if pattern.match(str(arg)):
                    mega_folder = arg

    install()

main()
