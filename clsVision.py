import requests
import configparser
import getpass
import sys
import datetime
import os
import json
import time

# Egor demo #####

LogfileName = "DP-Attack-Story.log"

#We ignore if Vision has an invalid security certificate. The next 
#lines prevent an error from being displayed every time we send 
#a command or query to vision
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

def update_log(message):
    print(message)
    with(open(LogfileName,"a")) as file:
        timeStamp = datetime.datetime.now().strftime('%d %b %Y %H:%M:%S')
        log_entry = f"[{timeStamp}] {message}\n"
        file.write(log_entry)

##configuration 
def load_config():
    config = configparser.ConfigParser()
    config.read("config.ini")
    return config

def save_config(config):
    with open("config.ini", "w") as config_file:
        config.write(config_file)

def create_connection_section(config):
    if not config.has_section('Vision'):
        config.add_section('Vision')
    if not config.has_option('Vision', 'ip'):
        config.set('Vision', 'ip', '')
    if not config.has_option('Vision', 'username'):
        config.set('Vision', 'username', '')
    if not config.has_option('Vision', 'password'):
        config.set('Vision', 'password', '')


class clsVision:
    #Initialize and log in to vision instance
    def __init__(self):
        print("\nPlease enter Vision \\ Cyber Controller Information")
        config = load_config()
        create_connection_section(config)

        ip = input(f"Enter Management IP [{config.get('Vision', 'ip')}]: ") or config.get('Vision', 'ip') if len(sys.argv) == 1 else config.get('Vision', 'ip')
        username = input(f"Enter Username [{config.get('Vision', 'username')}]: ") or config.get('Vision', 'username') if len(sys.argv) == 1 else config.get('Vision', 'username')

        # Use getpass to securely handle password input
        stored_password = config.get('Vision', 'password')
        stars=''
        for char in stored_password:
            stars+='*'
        password = getpass.getpass(prompt=f"Enter Password [{stars}]: ") or stored_password if len(sys.argv) == 1 else stored_password

        # Check if entered password is different from the stored password
        if password != stored_password:
            if input("Password has changed. Do you want to save the new password? (yes/no): ").lower() in ['yes','y']:
                config.set('Vision', 'password', password)

        # Save the management IP and username in the configuration
        config.set('Vision', 'ip', ip)
        config.set('Vision', 'username', username)

        # Save the configuration
        save_config(config)

        stars=""
        for char in password:
            stars+='*'
        print("")
        update_log(f"Connecting to Management IP: {ip} Username: {username} Password: {stars}")

        # Perform the actual connection using the gathered information

        self.ip = ip
        self.auth_data = {"username": username, "password": password}
        self.sess = requests.Session()
        self.sess.headers.update({"Content-Type": "application/json"})
        
        login_url = f"https://{self.ip}/mgmt/system/user/login"
        try:
            r = self.sess.post(url=login_url, json=self.auth_data, verify=False)
        except any as err:
            update_log(err)
            raise SystemExit(err)
        
        try:
            response = r.json()
            r.raise_for_status()
        except (requests.exceptions.HTTPError, requests.exceptions.ConnectionError, requests.exceptions.SSLError,
                requests.exceptions.Timeout, requests.exceptions.ConnectTimeout,
                requests.exceptions.ReadTimeout) as err:
            update_log(f"Error logging in to Vision at {ip}\n{r}\n{err}\nExiting.")
            raise SystemExit(err)

        if response['status'] == 'ok':
            self.sess.headers.update({"JSESSIONID": response['jsessionid']})
            update_log("Vision login successful")
        else:
            update_log(f"Error logging in to Vision at {ip}.\n{r}")
            raise Exception(f"Error logging in to Vision at {ip}.\n{r}")
            
    def _post(self, URL, requestData = ""):
        try:
            r = self.sess.post(url=URL, verify=False, data=requestData)
        except any as err:
            raise err
        
        try:
            r.raise_for_status()
        except (requests.exceptions.HTTPError, requests.exceptions.ConnectionError, requests.exceptions.SSLError,
            requests.exceptions.Timeout, requests.exceptions.ConnectTimeout,
            requests.exceptions.ReadTimeout) as err:
            update_log(f"Error processing POST to {URL}.\n{r.json()}")
            raise err

        return r
    
    def _get(self, URL):
        try:
            r = self.sess.get(url=URL, verify=False)
        except any as err:
            raise err
        
        try:
            r.raise_for_status()
        except (requests.exceptions.HTTPError, requests.exceptions.ConnectionError, requests.exceptions.SSLError,
            requests.exceptions.Timeout, requests.exceptions.ConnectTimeout,
            requests.exceptions.ReadTimeout) as err:
            update_log(f"Error processing GET to {URL}.\n{r.json()}")
            raise err
        return r
    
    def isLocked(self, DeviceIP):
        print(f"Checking {DeviceIP} Lock Status")
        APIUrl = f"https://{self.ip}/mgmt/system/config/tree/device/byip/{DeviceIP}/lock"
        
        response = self._get(APIUrl).json()
        print(response)
        if response['status'] == 'ok':
            if "is not locked" in response['message']:
                return False
            else:
                return True
        else:
            update_log(f"Error checking lock status for {DeviceIP}.\n{response}")
            raise Exception(f"Error checking lock status for {DeviceIP}.\n{response}")

    def LockDevice(self, DeviceIP):
        print(f"Locking {DeviceIP}")
        APIUrl = f"https://{self.ip}/mgmt/system/config/tree/device/byip/{DeviceIP}/lock"
        
        response = self._post(APIUrl).json()
        if response['status'] == 'ok':
            update_log(f"Config lock acquired for {DeviceIP}")
            return True
        else:
            update_log(f"Error acquiring config lock for {DeviceIP}.\n{response}")
            raise Exception(f"Error acquiring config lock for {DeviceIP}.\n{response}")

    def UnlockDevice(self, DeviceIP):
        update_log(f"Unlocking {DeviceIP}")
        APIUrl = f"https://{self.ip}/mgmt/system/config/tree/device/byip/{DeviceIP}/unlock"
        
        response = self._post(APIUrl).json()
        if response['status'] == 'ok':
            update_log(f"Config lock released for {DeviceIP}")
            return True
        else:
            update_log(f"Error releasing config lock for {DeviceIP}.\n{response}")
            raise Exception(f"Error releasing config lock for {DeviceIP}.\n{response}")

    def CreateTechData(self, AlteonIP):
        update_log(f"Attempting to create TechData on {AlteonIP}")
        print("Please be patient. This may take several minutes.")
        APIUrl = f"https://{self.ip}/mgmt/device/byip/{AlteonIP}/config/techdump?usekey=no&IncludeDNSSEC=no&Includeper=no&IncludeUDP=no"
        
        response = self._post(APIUrl).json()
        
        if response['status'] == 'ok':
            update_log(f"Successfully created TechData on {AlteonIP}")
            return True
        else:
            update_log(f"Error creating TechData on {AlteonIP}.\n{response}")
            raise Exception(f"Error creating TechData on {AlteonIP}.\n{response}")
        
    def DownloadTechData(self, AlteonIP, file = None):
        '''Unused in '''
        filePath = f"./TechData_{datetime.datetime.now().strftime('%d%b%Y')}/"
        fileName = file or f"Techdata.{AlteonIP.replace(':','.')}.tgz"
        update_log(f"Attempting to download TechData from {AlteonIP} to {filePath}{fileName}")
        APIUrl = f"https://{self.ip}/mgmt/device/byip/{AlteonIP}/config/gettechdata"
        response = self._get(APIUrl)
        
        if response.status_code == 200:
            if not os.path.exists(filePath):
                os.makedirs(filePath)
            with open(filePath + fileName, "wb") as file:
                file.write(response.content)
            update_log("Techdata File Exported Successfully")
            return True
        else:
            update_log(f"Error downloading Techdata from {AlteonIP}. Response: {response}")
            raise Exception(f"{response}")
        
    def getDPDeviceList(self):
        APIUrl = f"https://{self.ip}/mgmt/system/config/itemlist/defensepro"
        r = self._get(APIUrl)
        if r.status_code == 200:
            return r.json()
        else:
            print("Error getting Device list.")
            update_log(f"Error getting Device list. Status code: {r.status_code}")
            raise Exception(f"Error getting Device list: {r}")
        
    def getDeviceData(self, DeviceIP):
        APIUrl = f"https://{self.ip}/mgmt/system/config/tree/device/byip/{DeviceIP}"
        r = self._get(APIUrl)
        if r.status_code == 200:
            return r.json()
        else:
            update_log(f"Error getting device data for {DeviceIP}")
            raise Exception(f"Error getting device data for {DeviceIP} - {r}")
        
    def getAttackReports(self, DeviceIP,StartTime,EndTime):
        data = {
            "criteria": [
                {
                    "type": "timeFilter",
                    "inverseFilter": False,
                    "field": "endTime",
                    "lower": StartTime,
                    "upper": EndTime,
                    "includeUpper": False,
                    "includeLower": False
                },
                {
                    "type": "orFilter",
                    "inverseFilter": False,
                    "filters": [
                        {
                            "type": "termFilter",
                            "inverseFilter": False,
                            "field": "deviceIp",
                            "value": DeviceIP
                        }
                    ]
                }
            ],
            "order": [
                {
                    "aggregationName": None,
                    "field": "endTime",
                    "order": "DESC",
                    "sortingType": "STRING",
                    "type": "Order"
                }
            ],
            "pagination": {
                "page": 0,
                "size": 20,
                "topHits": 10000
            },
            "aggregation": None,
            "sourceFilters": [],
            "sourceIncludeFilters": [],
            "useFullTableScan": False,
            "validateReportStructure": False
        }
        update_log(f"Getting attack reports from {DeviceIP}")

        APIUrl = f'https://{self.ip}/mgmt/monitor/reporter/reports-ext/DP_ATTACK_REPORTS'
        
        response = self._post(APIUrl,json.dumps(data))
        print(response)
        if response.status_code == 200:
            update_log(f"Successfully pulled attack report from {DeviceIP}. Time range: {time.strftime('%d-%b-%Y %H:%M:%S', time.localtime(StartTime/1000))} - {time.strftime('%d-%b-%Y %H:%M:%S', time.localtime(EndTime/1000))}")
            return response.json()
        else:
            update_log(f"Error pulling attack report from {DeviceIP}. Time range: {time.strftime('%d-%b-%Y %H:%M:%S', time.localtime(StartTime/1000))} - {time.strftime('%d-%b-%Y %H:%M:%S', time.localtime(EndTime/1000))}")
            raise Exception(f"Error pulling attack report from {DeviceIP}. Time range: {time.strftime('%d-%b-%Y %H:%M:%S', time.localtime(StartTime/1000))} - {time.strftime('%d-%b-%Y %H:%M:%S', time.localtime(EndTime/1000))}")