from os import listdir
import xml.etree.ElementTree as ET
import configparser
from update import get_config_value, get_available_updates, is_update_applied, runcmd, check_drive
import sys
import requests
import time

NOTIFICATION_TEXT_NAME = "e_UpdateTool_Notification"
THEMES_PATH = "/etc/emulationstation/themes/"
IGNORE_THEMES = ["supersweeterx", "supersweeterx-black"] # these two start with a comment which is not supported by xml.etree.ElementTree

notification = ET.Element('text', {'extra': 'true', 'name':NOTIFICATION_TEXT_NAME})
position = ET.SubElement(notification, 'pos').text = '0.05 0.02'
color = ET.SubElement(notification, 'color').text = 'ff5733'
text = ET.SubElement(notification, 'text').text = 'UPDATE AVAILABLE'
size = ET.SubElement(notification, 'size').text = '0 0'

config = configparser.ConfigParser()
config.optionxform = str


def check_for_updates():
    needed_updates = 0
    available_updates = get_available_updates(check_drive(), True)
    for update in available_updates:
        update_applied = is_update_applied(update[0], update[2])
        if update_applied == False:
            needed_updates += 1
    if len(sys.argv) > 1:
        if sys.argv[1] == "disable": return False
    if needed_updates > 0:
        return True
    else:
        return False


def check_config():
    display_notification = get_config_value('CONFIG_ITEMS', 'display_notification')
    if display_notification == "True":
        return True
    return False


def get_themes():
    themes = []
    for directory in listdir(THEMES_PATH):
        if directory not in IGNORE_THEMES:
            path = THEMES_PATH + directory + "/" + "theme.xml"
            themes.append(path)
    return themes


def find_custom_elements(themes, view, name):
    custom_elements = []
    for theme in themes:
        tree = ET.parse(theme)
        root = tree.getroot()
        for view in root.iter("view"):
            if view.attrib['name'] == 'system':
                main_menu = view

        for element in main_menu.findall("text"):
            if element.attrib['name'] == name:
                custom_elements.append(element)
    return custom_elements


def change_notifications(themes, action):
    for theme in themes:
        missing = True
        tree = ET.parse(theme)
        root = tree.getroot()
        for view in root.iter("view"):
            if view.attrib['name'] == 'system':
                main_menu = view
        for element in main_menu.findall("text"):
            if element.attrib['name'] == NOTIFICATION_TEXT_NAME:
                missing = False
                if action == 'remove':
                    main_menu.remove(element)
                    write_theme(tree, theme)
                    print('removed')
        
        if missing:
            if action == 'create':
                main_menu.append(notification)
                write_theme(tree, theme)
                print('created')


def write_theme(tree, theme):
    tree.write("/tmp/theme.xml")
    runcmd("sudo mv /tmp/theme.xml " + theme)


def wait_for_network():
    for i in range(20):
        try:
            r = requests.get('https://1.1.1.1/')
            print(i, r)
            return True
        except requests.exceptions.RequestException as e:
            print(i, e)
            time.sleep(1)
            pass
    return False



def main():
    if check_config():
        themes = get_themes()
        if wait_for_network():
            if check_for_updates():
                found = find_custom_elements(themes, 'system', NOTIFICATION_TEXT_NAME)
                if len(found) == len(themes):
                    print("notification already shown")
                else:
                    change_notifications(themes, 'create')
            else:
                change_notifications(themes, 'remove')

main()