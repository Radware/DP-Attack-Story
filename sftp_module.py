import re
import warnings
import configparser
from getpass import getpass  # For secure password input

try:
    import pysftp
except ImportError:
    print("The python module 'pysftp' is not installed. Please install it by running: pip install pysftp")
    exit()

warnings.filterwarnings(action='ignore', module='pysftp', category=UserWarning)

#Remove commented section when script confirmed to work in multiple environments
#def load_config():
#    config = configparser.ConfigParser()
#    config.read("config.ini")
#    return config
#
#def save_config(config):
#    with open("config.ini", "w") as config_file:
#        config.write(config_file)
#
#def create_connection_section(config):
#    if not config.has_section('DefensePro'):
#        config.add_section('DefensePro')
#    if not config.has_option('DefensePro', 'ip'):
#        config.set('DefensePro', 'ip', '')
#    if not config.has_option('DefensePro', 'username'):
#        config.set('DefensePro', 'username', '')
#    if not config.has_option('DefensePro', 'password'):
#        config.set('DefensePro', 'password', '')

def get_attack_log(v, device_ips, from_month, start_year, to_month=None):
    #Remove commented section when script confirmed to work in multiple environments
    #config = load_config()
    #create_connection_section(config)
    #
    # Prompt user for SFTP credentials
    #username = input("Enter Defensepro SSH username: ")
    #password = getpass("Enter Defensepro SSH password: ")  # Using getpass for secure input
    #port = 22  # Default SFTP port
    #
    #config.set('DefensePro', 'username', username)
    #config.set('DefensePro', 'password', password)
    #save_config(config)

    cnopts = pysftp.CnOpts()
    cnopts.hostkeys = None  # Disable host key checking

    # Define the remote and local paths
    remote_path = '/disk/var/attacklog/bdos'
    local_path = './Output/'

    #year = 2024 

    if to_month:
        pattern = re.compile(f"BDOS{start_year}[{from_month}-{to_month}]")
    else:
        pattern = re.compile(f"BDOS{start_year}{from_month}")
    
    all_found_files = []

    # Connect to the SFTP server and perform operations
    for device_ip in device_ips:
        try:
            device_ip = device_ip.strip()
            dpData = v.getDeviceData(device_ip)
            username = dpData['deviceSetup']['deviceAccess']['httpsUsername']
            password = dpData['deviceSetup']['deviceAccess']['httpsPassword']
            port = dpData['deviceSetup']['deviceAccess']['cliPort']
            with pysftp.Connection(device_ip, username=username, password=password, port=port, cnopts=cnopts) as sftp:
                print(f"Connected to {device_ip} ... ")

                files = sftp.listdir(remote_path)
                found_files = [file for file in files if pattern.match(file)]
    
                if found_files:
                    print(f"Found files: {found_files}")
                    all_found_files.extend(found_files)
                    for found_file in found_files:
                        remote_file_path = f"{remote_path}/{found_file}"
                        local_file_path = f"{local_path}/{found_file}"
                        sftp.get(remote_file_path, local_file_path)
                        print(f"Downloaded {remote_file_path} to {local_file_path}")
                else:
                    print(f"No files found on {device_ip} with the format BDOS{start_year}{from_month}")

        except Exception as e:
            print(f"Failed to connect to {device_ip}: {str(e)}")
            
    print("SFTP operations completed.")
    return all_found_files
