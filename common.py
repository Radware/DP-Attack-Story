import configparser
import datetime
import sys
import re

outputFolder = f"./Output/{datetime.datetime.now().strftime('%Y-%m-%d_%H.%M.%S')}/"
#outputFolder = './Output/'
LogfileName = outputFolder + "P-Attack-Story.log"


args = sys.argv.copy()
script_filename = args.pop(0)

if len(args) > 0 and (args[0].startswith('-h') or args[0].startswith('?')):
    print("  Script syntax:")
    print("  python main.py [--use-cached | <Vision_IP Username Password RootPassword>] <Time-Range> <DefensePro-list> <First-DP-policy-list> <Second-DP-policy-list> <X-DP-policy-list>...")
    print("    ***Note: The order of arguments is important and must not deviate from the above template.***")
    print("    --use-cached, -c      Use information stored in 'config.ini' for Vision IP, username, and password")
    print("    <time-range> options:")
    print("        --hours, -h <number_of_hours>                      Select data from the past X hours.")
    print("        --date-range, -dr <start_datetime> <end_datetime>  Select data between two specified dates.")
    print("        --epoch-range, -er <epoch_start> <epoch_end>       Select data between two Unix epoch times.")
    print("        --previous-time-range, -p                          Use the cached time range from the last time the script was run.")
    print("    <defensepro-list>     Comma-separated list of DefensePro names or IP addresses (use '' for all).")
    print("    <policy-list>         Comma-separated list of policy names (use '' for all).")
    print("  Examples:")
    print("    python main.py -c --hours 3 DefensePro1,DefensePro2,192.168.1.20 DefensePro1_BdosProfile,DefensePro1_SynFloodProtection DP2_BdosProfile,DP2_SynFloodProtection DP3_Policy1")    
    print("    python main.py 192.168.1.1 admin radware radware1 --epoch-range 859885200 859971600 '' ''")    
    print('    python main.py --use-cached --date-range "11 Oct 2024 09:00:00" "11 Oct 2024 18:00:00" "DP1, DP2" "DP1_Policy1, DP1_Policy2" "DP2_Policy1, DP2_Policy2"')    
    exit(0)

class clsConfig():
    def __init__(self):
        self.config = configparser.ConfigParser()
        self.config.read("config.ini")

        if not self.config.has_section('Vision'):
            self.config.add_section('Vision')
        visionOptions = ['ip', 'username', 'password', 'rootPassword']
        for option in visionOptions:
            if not self.config.has_option('Vision', option):
                self.config.set('Vision', option, '')
        if not self.config.has_option('General', 'Top_N'):
            self.set("General","Top_N","10")
        if not self.config.has_option('General', 'Compress_Output'):
            self.set("General","Compress_Output","TRUE")

    def save(self):
        with open("config.ini", "w") as config_file:
            self.config.write(config_file)

    def get(self, *args, fallback=None, **kwargs):
        return self.config.get(*args, fallback=fallback, **kwargs)

    def set(self, section, option, value):
        if not self.config.has_section(section):
            self.config.add_section(section)
        if isinstance(value, (int, float)): 
            value = str(value) 
        if isinstance(value, bool):
             value = 'true' if value else 'false'
        self.config.set(section, option, value)
        self.save()


config = clsConfig()
topN = int(config.get("General","Top_N","10"))

def update_log(message):
    print(message)
    with(open(LogfileName,"a")) as file:
        timeStamp = datetime.datetime.now().strftime('%d %b %Y %H:%M:%S')
        log_entry = f"[{timeStamp}] {message}\n"
        file.write(log_entry)


