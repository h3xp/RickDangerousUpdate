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

from megadl import get_available_updates, download_update

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


def runcmd(host, username, password, command):
    client = paramiko.client.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(host, username=username, password=password)
    _stdin, _stdout, _stderr = client.exec_command(command)

    client.close()


def copyfile(host, username, password, localpath, filepath):
    transport = paramiko.Transport((host, 22))
    transport.connect(None, username, password)

    sftp = paramiko.SFTPClient.from_transport(transport)
    sftp.put(localpath, filepath)

    if sftp:
        sftp.close()
    if transport:
        transport.close()

def copydir(host,username, password, source_path, target_path):
    transport = paramiko.Transport((host, 22))
    transport.connect(None, username, password)

    sftp = MySFTPClient.from_transport(transport)
    sftp.mkdir(target_path, ignore_existing=True)
    sftp.put_dir(source_path, target_path)
    sftp.close()

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
        return ip, username, password


def connect_pi():
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
        uinp = input('\n Enter your Selection: ')

        if uinp == '1':
            improvements_menu()
            break
        elif uinp == '2':
            bugs_menu()
            break
        elif uinp == '3':
            restore_retroarch_menu()
            break
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
        os.mkdir(improvements_dir)
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
        host, username, password = connect_pi()
        for filename in os.listdir(improvements_dir):
            f = os.path.join(improvements_dir, filename)
            if os.path.isfile(f):
                if f.endswith(".zip"):
                    print(f)
                    with zipfile.ZipFile(f, 'r') as zip_ref:
                        zip_ref.extractall(extracted)
                    copydir(host, username, password, extracted, "/")
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
            host, username, password = connect_pi()
            runcmd(host, username, password,
                   'sudo chown -R pi:pi ~/RetroPie/roms/ && sudo chown -R pi:pi ~/.emulationstation/')
            cls()
            print("All done!")
            break
        elif uinp == '2':
            host, username, password = connect_pi()
            localpath = pathlib.Path(__file__).parent.resolve()
            videomodes_dir = localpath / "resources" / "bugs" / "videomodes" / "opt" / "retropie" / "configs" / "all"
            videomodes_file = videomodes_dir / "videomodes.cfg"
            copyfile(host, username, password, videomodes_file, "/opt/retropie/configs/all/videomodes.cfg")
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
        print('\n ===========[ RESTORE RETROPIE CONFIGS ]=============')
        print('\nSelect All for the general config file or select a platform for platform specific config files:\n')
        print(' 1. All')
        print(' 2. atarijaguar')
        print(' 3. neogeocd')
        print(' 4. nes')
        print(' 5. atarist')
        print(' 6. zxspectrum')
        print(' 7. naomi')
        print(' 8. atari7800')
        print(' 9. odyssey2')
        print(' 10. c64')
        print(' 11. fds')
        print(' 12. pcenginecd')
        print(' 13. tg16')
        print(' 14. n64')
        print(' 15. gamecube')
        print(' 16. genesis')
        print(' 17. arcade alts')
        print(' 18. coco')
        print(' 19. atari800')
        print(' 20. pcengine')
        print(' 21. atarilynx')
        print(' 22. msx2')
        print(' 23. amigacd32')
        print(' 24. atari2600')
        print(' 25. megadrive')
        print(' 26. ngpc')
        print(' 27. pcx68000')
        print(' 28. lightgun')
        print(' 29. wonderswancolor')
        print(' 30. FDS alts')
        print(' 31. scummvm')
        print(' 32. neogeo')
        print(' 33. switch')
        print(' 34. Mac')
        print(' 35. dendy')
        print(' 36. mastersystem')
        print(' 37. mame-advmame')
        print(' 38. sgb')
        print(' 39. zx81')
        print(' 40. pico8')
        print(' 41. amiga')
        print(' 42. samcoupe')
        print(' 43. virtualboy')
        print(' 44. coleco')
        print(' 45. gbc')
        print(' 46. wonderswan')
        print(' 47. famicom')
        print(' 48. openbor')
        print(' 49. ngp')
        print(' 50. supergrafx')
        print(' 51. atari5200')
        print(' 52. msx')
        print(' 53. snes')
        print(' 54. xbox')
        print(' 55. pc')
        print(' 56. neocdz')
        print(' 57. arcade')
        print(' 58. fba')
        print(' 59. 3do')
        print(' 60. favs')
        print(' 61. mame-libretro')
        print(' 62. x68000')
        print(' 63. gameandwatch')
        print(' 64. sg-1000')
        print(' 65. sega32x')
        print(' 66. pce-cd')
        print(' 67. PS2')
        print(' 68. wii')
        print(' 69. gb')
        print(' 70. tgcd')
        print(' 71. gx4000')
        print(' 72. segacd')
        print(' 73. kodi')
        print(' 74. steam')
        print(' 75. acornelectron')
        print(' 76. apple2')
        print(' 77. intellivision')
        print(' 78. psp')
        print(' 79. amiga1200')
        print(' 80. gba')
        print(' 81. psx')
        print(' 82. pspminis')
        print(' 83. ports')
        print(' 84. vectrex')
        print(' 85. saturn')
        print(' 86. snesmsu1')
        print(' 87. steamlink')
        print(' 88. intellivision2')
        print(' 89. wiiu')
        print(' 90. videopac')
        print(' 91. gamewatch alts')
        print(' 92. bbcmicro')
        print(' 93. dreamcast')
        print(' 94. amstradcpc')
        print(' 95. tg16cd')
        print(' 96. snes alts')
        print(' 97. daphne')
        print(' 98. gamegear')
        print(' 99. PS3')
        print(' 100. nds')
        print(' 101. sfc')
        print(' 102. oric')
        uinp = input('\n Enter your Selection: ')
        cls()
        switch_dict = {
            1: 'all',
            2: 'atarijaguar',
            3: 'neogeocd',
            4: 'nes',
            5: 'atarist',
            6: 'zxspectrum',
            7: 'naomi',
            8: 'atari7800',
            9: 'odyssey2',
            10: 'c64',
            11: 'fds',
            12: 'pcenginecd',
            13: 'tg16',
            14: 'n64',
            15: 'gamecube',
            16: 'genesis',
            17: 'arcade alts',
            18: 'coco',
            19: 'atari800',
            20: 'pcengine',
            21: 'atarilynx',
            22: 'msx2',
            23: 'amigacd32',
            24: 'atari2600',
            25: 'megadrive',
            26: 'ngpc',
            27: 'pcx68000',
            28: 'lightgun',
            29: 'wonderswancolor',
            30: 'FDS alts',
            31: 'scummvm',
            32: 'neogeo',
            33: 'switch',
            34: 'Mac',
            35: 'dendy',
            36: 'mastersystem',
            37: 'mame-advmame',
            38: 'sgb',
            39: 'zx81',
            40: 'pico8',
            41: 'amiga',
            42: 'samcoupe',
            43: 'virtualboy',
            44: 'coleco',
            45: 'gbc',
            46: 'wonderswan',
            47: 'famicom',
            48: 'openbor',
            49: 'ngp',
            50: 'supergrafx',
            51: 'atari5200',
            52: 'msx',
            53: 'snes',
            54: 'xbox',
            55: 'pc',
            56: 'neocdz',
            57: 'arcade',
            58: 'fba',
            59: '3do',
            60: 'favs',
            61: 'mame-libretro',
            62: 'x68000',
            63: 'gameandwatch',
            64: 'sg-1000',
            65: 'sega32x',
            66: 'pce-cd',
            67: 'PS2',
            68: 'wii',
            69: 'gb',
            70: 'tgcd',
            71: 'gx4000',
            72: 'segacd',
            73: 'kodi',
            74: 'steam',
            75: 'acornelectron',
            76: 'apple2',
            77: 'intellivision',
            78: 'psp',
            79: 'amiga1200',
            80: 'gba',
            81: 'psx',
            82: 'pspminis',
            83: 'ports',
            84: 'vectrex',
            85: 'saturn',
            86: 'snesmsu1',
            87: 'steamlink',
            88: 'intellivision2',
            89: 'wiiu',
            90: 'videopac',
            91: 'gamewatch alts',
            92: 'bbcmicro',
            93: 'dreamcast',
            94: 'amstradcpc',
            95: 'tg16cd',
            96: 'snes alts',
            97: 'daphne',
            98: 'gamegear',
            99: 'PS3',
            100: 'nds',
            101: 'sfc',
            102: 'oric'
        }

        if uinp == "":
            uinp = "1"
        selection = switch_dict.get(int(uinp))
        host, username, password = connect_pi()
        localpath = pathlib.Path(__file__).parent.resolve()
        selection_path = localpath / "resources" / "retroarch_configs" / selection
        copydir(host, username, password, selection_path, "/opt/retropie/configs/" + selection)
        cls()
        print("All done!")
        break

main_menu()

