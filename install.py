import subprocess
import sys
import os
import configparser
import datetime
import shutil
from pathlib import Path
import xml.etree.ElementTree as ET

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

    os.remove(src_xml)


def run_cmd(command: str):
    code = subprocess.call(["bash","-c",command])
    return code

tmp_dir = Path("/", "tmp", "update_tool_install")
home_dir = ""
git_repo = "https://raw.githubusercontent.com/h3xp/RickDangerousUpdate/main/"

#check if already exists, this is useful for debugging
if os.path.exists("/home/pi/.update_tool/update_tool.ini"):
    old_config = configparser.ConfigParser()
    old_config.read("/home/pi/.update_tool/update_tool.ini")
    git_repo = old_config["CONFIG_ITEMS"]["git_repo"]

if os.path.exists(tmp_dir) == False:
    os.mkdir(tmp_dir)

print("Installing depencencies...")
run_cmd("sudo apt-get -y install python3-pip")
run_cmd("pip3 install -r <(curl \"{}requirements.txt\" -s -N)".format(git_repo))

print("Downloading required files...")
    
#download update_tool.ini
run_cmd("curl {}update_tool.ini -o {}/update_tool.ini".format(git_repo, tmp_dir))
#download the menu image
run_cmd("curl {}banner.png -o {}/banner.png".format(git_repo, tmp_dir))
#download the gamelist.xml
run_cmd("curl {}gamelist.xml -o {}/gamelist.xml".format(git_repo, tmp_dir))

print("Synching configs...")
#synch config
new_config_path = "{}/update_tool.ini".format(tmp_dir)
if os.path.exists(new_config_path) == True:
    #write new items
    new_config = configparser.ConfigParser()
    new_config.read(new_config_path)
    home_dir = new_config["CONFIG_ITEMS"]["home_path"]
    old_config_path = "{}/update_tool.ini".format(home_dir)
    if os.path.exists(home_dir) == False:
        os.mkdir(home_dir)
    if os.path.exists(old_config_path) == False:
        os.mknod(old_config_path)

    old_config = configparser.ConfigParser()
    old_config.read(old_config_path)
    for section in new_config.sections():
        if old_config.has_section(section) == False:
            old_config[section] = {}
        for key, val in new_config.items(section):
            if old_config.has_option(section, key):
                if val.strip() != "":
                    old_config[section][key] = val.strip()
            else:
                old_config[section][key] = val.strip()

    #delete deprecated items
    for section in old_config.sections():
        if section == "CONFIG_ITEMS":
            for key, val in old_config.items(section):
                if new_config.has_option(section, key) == False:
                    old_config.remove_option(section, key)
        if new_config.has_section(section) == False:
            old_config.remove_section(section)

    #write 
    if len(sys.argv) > 1:
        old_config["CONFIG_ITEMS"]["mega_dir"] = sys.argv[1]

    with open(old_config_path, 'w') as configfile:
        old_config.write(configfile)
    
#write script
print("Writing bash script...")
with open("/home/pi/RetroPie/retropiemenu/{}".format("update_tool.sh"), "w") as shellfile:
    shellfile.write("#!/bin/bash\n")
    shellfile.write("source <(grep = {}/update_tool.ini | sed 's/ *= */=/g')\n".format(home_dir))
    shellfile.write("python3 <(curl $git_repo$git_command -s -N) $mega_dir")

#merge gamelist entries
print("Merging gamelist entries...")
new_gamelist_path = "{}/gamelist.xml".format(tmp_dir)
if os.path.exists(new_gamelist_path) == True:
    merge_xml(new_gamelist_path, "/opt/retropie/configs/all/emulationstation/gamelists/retropie/gamelist.xml")

#copy image file
print("Copying icon...")
new_banner_path = "{}/banner.png".format(tmp_dir)
shutil.copy(new_banner_path, "/home/pi/RetroPie/retropiemenu/icons/update_tool.png")

shutil.rmtree(tmp_dir)