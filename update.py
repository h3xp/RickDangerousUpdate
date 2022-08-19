'''
Date: 16.08.22
By: hexp

Update Script for Rick Dangerous' Minecraftium Edition
'''
import os
import paramiko
import pathlib
import zipfile
import shutil
import configparser
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
from mega.errors import ValidationError, RequestError

logger = logging.getLogger(__name__)
localpath = Path(__file__).parent.resolve()
destpath = localpath / "improvements"
destpath = str(destpath)
config = configparser.ConfigParser()

def download_file(file_handle,
                  file_key,
                  file_data,
                  dest_path=destpath,
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


def get_available_updates():
    (root_folder, shared_enc_key) = parse_folder_url(
        "https://mega.nz/folder/DfBWGTjA#BFcNX-XcMEnY-cdFDWTx1Q")
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


def download_update(ID):
    (root_folder, shared_enc_key) = parse_folder_url(
        "https://mega.nz/folder/DfBWGTjA#BFcNX-XcMEnY-cdFDWTx1Q")
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
            file_data = get_file_data(file_id, root_folder)
            download_file(file_id, key, file_data)

class MySFTPClient(paramiko.SFTPClient):
    def put_dir(self, source, target):
        ''' Uploads the contents of the source directory to the target path. The
            target directory needs to exists. All subdirectories in source are
            created under target.
        '''
        for item in os.listdir(source):
            if os.path.isfile(os.path.join(source, item)):
                self.put(os.path.join(source, item), '%s/%s' % (target, item))
            else:
                self.mkdir('%s/%s' % (target, item), ignore_existing=True)
                self.put_dir(os.path.join(source, item), '%s/%s' % (target, item))

    def mkdir(self, path, mode=511, ignore_existing=False):
        ''' Augments mkdir by adding an option to not fail if the folder exists  '''
        try:
            super(MySFTPClient, self).mkdir(path, mode)
        except IOError:
            if ignore_existing:
                pass
            else:
                raise


def cls():
    os.system('cls' if os.name == 'nt' else 'clear')


def runcmd(command):
    if os.environ["RetroPieUpdaterUseSSH"] == "Yes":
        host, username, password = connect_pi()
        client = paramiko.client.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(host, username=username, password=password)
        _stdin, _stdout, _stderr = client.exec_command(command)

        client.close()
    else:
        os.system(command)


def copyfile(localpath, filepath):
    if os.environ["RetroPieUpdaterUseSSH"] == "Yes":
        host, username, password = connect_pi()
        transport = paramiko.Transport((host, 22))
        transport.connect(None, username, password)

        sftp = paramiko.SFTPClient.from_transport(transport)
        sftp.put(localpath, filepath)

        if sftp:
            sftp.close()
        if transport:
            transport.close()
    else:
        shutil.copy(localpath, filepath)



def copydir(source_path, target_path):
    if os.environ["RetroPieUpdaterUseSSH"] == "Yes":
        host, username, password = connect_pi()
        transport = paramiko.Transport((host, 22))
        transport.connect(None, username, password)

        sftp = MySFTPClient.from_transport(transport)
        sftp.mkdir(target_path, ignore_existing=True)
        sftp.put_dir(source_path, target_path)
        sftp.close()
    else:
        copy_tree(source_path, target_path)

def ip_instructions():
    while True:
        cls()
        print('\n ===========[ CONNECT RETROPIE INSTRUCTIONS ]=============')
        print("\nMake sure your Retropie is connected to your local network via ethernet cable or WI-FI.\n"
              "Boot it and navigate to Options.\nSelect Show IP address.\n"
              "Alternatively look for \"retropie\" on your routers connected devices overview.")
        print(' ')
        input('\n Press any key to return.')
        break


def enter_connection():
    while True:
        cls()
        ip = input('\n Enter IP: ')
        username = input('\n Enter username, or press enter for default [pi]:')
        password = input('\n Enter password, or press enter for default [raspberry]:')
        if username == "":
            username = "pi"
        if password == "":
            password = "raspberry"
        if ip == "":
            ip = "192.168.119.179"
        config['SSH'] = {'host': ip, 'username': username, 'password': password}
        with open('config.ini', 'w') as configfile:
            config.write(configfile)
        return ip, username, password


def connect_pi():
    if os.path.exists('config.ini'):
        config.read("config.ini")
        host = config.get('SSH', 'host')
        username = config.get('SSH', 'username')
        password = config.get('SSH', 'password')
        print(username)
        print(password)
        print(host)
        return host, username, password
    else:
        while True:
            cls()
            print('\n ===========[ CONNECT RETROPIE ]=============')
            print("\nIn order to automatically apply updates/fixes \n"
                  "to your Retropie you have to provide it's IP address.")
            print(' ')
            print(' 1. Enter IP')
            print(' 2. Where do I find the IP adress?')
            print(' 9. Quit ❌')

            uinp = input('\n Enter your Selection: ')

            if uinp == '1':
                host, username, password = enter_connection()
                return host, username, password
                break
            elif uinp == '2':
                ip_instructions()
            elif uinp == '9':
                break
                return
            else:
                print('\n  Please select from the Menu.')


def main_menu():
    while True:
        cls()
        print('\n ===========[ MAIN MENU ]=============')
        print('  ')
        print(' 1. Load Improvements ✨')
        print(' 2. Fix known bugs 🐛')
        print(' 3. Restore retroarch configurations 👾')
        print(' 4. Update this script 📄')
        print(' 9. Quit ❌')
        try:
            uinp = input('\n Enter your Selection: ')
        except EOFError:
            break
        if uinp == '1':
            improvements_menu()
            break
        elif uinp == '2':
            bugs_menu()
            break
        elif uinp == '3':
            restore_retroarch_menu()
            break
        elif uinp == '4':
            print("not yet supported")
            break
            return
        elif uinp == '9':
            break
            return
        else:
            print('\n  Please select from the Menu.')


def improvements_menu():
    while True:
        cls()
        print('\n ===========[ AVAILABLE UPDATES ]=============')
        print('  ')
        available_updates = get_available_updates()
        localpath = pathlib.Path(__file__).parent.resolve()
        improvements_dir = localpath / "improvements"
        os.makedirs(improvements_dir, exist_ok=True)
        extracted = improvements_dir / "extracted"

        print("0. all")
        for i in range(len(available_updates)):
            print(str(i+1) + ". " + available_updates[i][0])
        selection = input('\nSelect which update you want to apply: ')
        selected_updates = []
        if int(selection) in range(len(available_updates)+1):
            if int(selection) == 0:
                print("Downloading all available updates...")
                selected_updates = available_updates
            else:
                print("Downloading: " + available_updates[int(selection)-1][0] + "...")
                selected_updates.append(available_updates[int(selection)-1])
            for update in selected_updates:
                download_update(update[1])
        else:
            print("Invalid selection.")
            break
        for filename in os.listdir(improvements_dir):
            f = os.path.join(improvements_dir, filename)
            if os.path.isfile(f):
                if f.endswith(".zip"):
                    print(f)
                    with zipfile.ZipFile(f, 'r') as zip_ref:
                        zip_ref.extractall(extracted)
                    copydir(extracted, "/")
        try:
            shutil.rmtree(improvements_dir)
        except OSError as e:
            print("Error: %s : %s" % (extracted, e.strerror))

        cls()
        print("All done!")
        break


def bugs_menu():
    while True:
        cls()
        print('\n ===========[ FIX BUGS ]=============')
        print('  ')
        print(' 1. Fix permissions')
        print(' 2. Fix videomodes.cfg')
        print(' 9. Return ')
        uinp = input('\n Enter your Selection: ')

        if uinp == '1':
            runcmd('sudo chown -R pi:pi ~/RetroPie/roms/ && sudo chown -R pi:pi ~/.emulationstation/')
            cls()
            print("All done!")
            break
        elif uinp == '2':
            localpath = pathlib.Path(__file__).parent.resolve()
            videomodes_dir = localpath / "resources" / "bugs" / "videomodes" / "opt" / "retropie" / "configs" / "all"
            videomodes_file = videomodes_dir / "videomodes.cfg"
            copyfile(videomodes_file, "/opt/retropie/configs/all/videomodes.cfg")
            cls()
            print("All done!")
            break
        elif uinp == '9':
            break
            main_menu()
        else:
            print('\n  Please select from the Menu. For more details check README.md.')


def restore_retroarch_menu():
    while True:
        cls()
        print('\n ===========[ RESTORE RETROARCH CONFIGS ]=============')
        print('\nAre you sure you want to reset all retroarch.cfgs?:\n')
        print(' 1. Yes')
        print(' 2. No')
        uinp = input("\nPlease select from the menu: ")
        if uinp == "1":
            urllib.request.urlretrieve("https://raw.githubusercontent.com/h3xp/RickDangerousUpdate/main/retroarch_configs.zip", "retroarch_configs.zip")
            localpath = pathlib.Path(__file__).parent.resolve()
            f = os.path.join(localpath, "retroarch_configs.zip")
            if os.path.isfile(f):
                with zipfile.ZipFile(f, 'r') as zip_ref:
                    zip_ref.extractall("retroarch_configs")
                copydir("retroarch_configs/", "/opt/retropie/configs/")
        else:
            break

        cls()
        print("All done!")
        break


def check_hostname():
    if platform.uname()[1] == "retropie":
        os.environ["RetroPieUpdaterUseSSH"] = "No"
    else:
        os.environ["RetroPieUpdaterUseSSH"] = "Yes"


def main():
    check_hostname()
    main_menu()


main()