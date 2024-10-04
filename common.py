import configparser
import datetime

outputFolder = './Output/'
LogfileName = outputFolder + "P-Attack-Story.log"
topN = 10 #number of entries to include in the attack table


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

config = clsConfig()


def update_log(message):
    print(message)
    with(open(LogfileName,"a")) as file:
        timeStamp = datetime.datetime.now().strftime('%d %b %Y %H:%M:%S')
        log_entry = f"[{timeStamp}] {message}\n"
        file.write(log_entry)


