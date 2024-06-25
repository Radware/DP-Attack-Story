#Version .4
#Updated 25 June 2024

import json
import urllib3
import csv
#import pandas as pd #unused at this point
import time
from clsVision import *
from datetime import datetime
from tabulate import tabulate


#region ####################Helper functions####################

def epoch_to_datetime(epoch_time):
    """Convert epoch time to human-readable datetime format."""
    epoch_time = int(epoch_time)  # Convert epoch_time to integer
    return datetime.fromtimestamp(epoch_time / 1000.0).strftime('%d-%m-%Y %H:%M:%S')
    #return datetime.fromtimestamp(epoch_time / 1000.0).strftime('%Y-%m-%d %H:%M:%S')

def convert_to_epoch(human_readable_time, time_format='%d-%m-%Y %H:%M:%S'):
    # Parse the human-readable time to a datetime object
    dt = datetime.strptime(human_readable_time, time_format)
    # Convert the datetime object to epoch time
    epoch_time = int(time.mktime(dt.timetuple()) * 1000)
    return epoch_time


def calculate_duration(start_time, end_time):
    start_dt = datetime.strptime(start_time, '%d-%m-%Y %H:%M:%S')
    end_dt = datetime.strptime(end_time, '%d-%m-%Y %H:%M:%S')
    duration = end_dt - start_dt
    return str(duration)

def attackipsid_to_syslog_id(attackid):
   # This function converts AttackIpsID to Syslog ID

    id_first_part_dec = int(attackid.split('-')[0])
    id_second_part_dec = int(attackid.split('-')[1])

    # convert id_first_part_dec to hex removing 0x
    id_first_part_new = '00' + str(id_first_part_dec)
    id_second_part_new = '00' + str(id_second_part_dec)
    syslog_id = 'FFFFFFFF-0000-0000-' + id_first_part_new + '-' + id_second_part_new
    return(syslog_id)
#endregion




#instantiate v as a logged in vision instance:
v = clsVision()

##Old code no longer needed:
'''#vision_ip = input("Enter Vision / CC IP address:")

# First request to login and get the jsessionid
login_url = f'https://{vision_ip}/mgmt/system/user/login'
login_headers = {
    'accept': 'application/json, text/plain, */*',
    'accept-language': 'en-US,en;q=0.9',
    'content-type': 'application/json;charset=UTF-8',
    'origin': f'https://{vision_ip}',
    'priority': 'u=1, i',
    'referer':f'https://{vision_ip}/login',
    'sec-ch-ua': '"Google Chrome";v="125", "Chromium";v="125", "Not.A/Brand";v="24"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'sec-fetch-dest': 'empty',
    'sec-fetch-mode': 'cors',
    'sec-fetch-site': 'same-origin',
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36'
}
login_data = '{"username":"radware","password":"radware"}'

login_response = requests.post(login_url, headers=login_headers, data=login_data, verify=False)

# Parse the JSON response to get the jsessionid
login_response_json = login_response.json()
#jsessionid = login_response_json.get('jsessionid')

# Print the jsessionid
#print(f"JSESSIONID: {jsessionid}")'''

#Ask user for time period:
print("Please select a time period:")
print("1) The past 5 hours")
print("2) Manually enter times")
choice = input("Enter selection (1-2) or other to quit: ")
if choice == '1':
    epoch_from_time = (int(time.time()) - (60 * 60 * 5)) * 1000
    epoch_to_time = int(time.time()) * 1000
elif choice == '2':
    from_time = input("Enter the duration start time (format: DD-MM-YYYY HH:MM:SS): ")
    epoch_from_time = convert_to_epoch(from_time)
    to_time = input("Enter the duration end time (format: DD-MM-YYYY HH:MM:SS): ")
    epoch_to_time = convert_to_epoch(to_time)
else:
    print("Other input, quit")
    exit(1)

DPlist = v.getDPDeviceList()
DPString = '\nAvailable devices: '
for DP in v.getDPDeviceList():
    DPString += DP['managementIp'] + " "
print(DPString)

device_ip = input("Enter the device IP: ")


#print(epoch_from_time)
#print(epoch_to_time)

##Old code no longer needed
'''# Second request to the report endpoint using the obtained jsessionid
report_url = 'https://155.1.1.6/mgmt/monitor/reporter/reports-ext/DP_ATTACK_REPORTS'
headers = {
    'accept': 'application/json, text/plain, */*',
    'accept-language': 'en-US,en;q=0.9',
    'content-type': 'application/json;charset=UTF-8',
    'cookie': f'JSESSIONID={jsessionid}',
    'origin': 'https://155.1.1.6',
    'priority': 'u=1, i',
    'referer': 'https://155.1.1.6/events',
    'sec-ch-ua': '"Google Chrome";v="125", "Chromium";v="125", "Not.A/Brand";v="24"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'sec-fetch-dest': 'empty',
    'sec-fetch-mode': 'cors',
    'sec-fetch-site': 'same-origin',
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36'
}
data = {
    "criteria": [
        {
            "type": "timeFilter",
            "inverseFilter": False,
            "field": "endTime",
            "lower": epoch_from_time,
            "upper": epoch_to_time,
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
                    "value": device_ip
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

response = requests.post(report_url, headers=headers, data=json.dumps(data), verify=False)
'''



# Parse the JSON response
response_data = v.getAttackReports(device_ip, epoch_from_time, epoch_to_time)

try:
    total_hits = int(response_data["metaData"]["totalHits"])
    if total_hits == 0:
        raise ValueError("No data present for the specified time period.")
    
    # Save the formatted JSON to a file
    with open('response.json', 'w') as file:
        json.dump(response_data, file, indent=4)
    
    print("Response saved to response.json")
    
    def parse_response_file(file_path):
        with open(file_path, 'r') as file:
            data = json.load(file)

        # Parse and extract start time and end time for each "row" in "data"
        rows = data.get('data', [])
        table_data = []
        headers = ["Device IP", "Policy", "Attack ID", "Radware ID", "Syslog ID" , "Attack Category", "Attack Name", "Threat Group", "Protocol", "Source Address", "Source Port", "Destination Address", "Destination Port", "Action", "Attack Status", "Latest Attack State", "Final Attack Footprint", "Average Attack Rate(PPS)", "Average Attack Rate(BPS)", "Packet Count", "Attack Duration", "Start Time", "End Time", "Direction", "Physical Port"]
        
        for row_data in rows:
            row = row_data.get('row', {})
            device_ip = row.get('deviceIp', 'N/A')
            policy_id = row.get('ruleName', 'N/A')
            attackid = row.get('attackIpsId', 'N/A')
            radwareid = row.get('radwareId', 'N/A')
            attack_category = row.get('category', 'N/A')
            attack_name = row.get('name', 'N/A')
            Threat_Group = row.get('threatGroup', 'N/A')
            Protocol = row.get('protocol', 'N/A')
            Source_Address = row.get('sourceAddress', 'N/A')
            Source_Port = row.get('sourcePort', 'N/A')
            Destination_Address = row.get('destAddress', 'N/A')
            Destination_Port = row.get('destPort', 'N/A')
            Action_Type = row.get('actionType', 'N/A')
            Attack_Status = row.get('status', 'N/A')
            Latest_State = row.get('latestBlockingState', 'N/A')
            final_footprint = row.get('latestFootprintText', 'N/A')
            Average_Attack_Rate_PPS = row.get('averageAttackPacketRatePps', 'N/A')
            Average_Attack_Rate_BPS = row.get('averageAttackRateBps', 'N/A')
            Packet_Count = row.get('packetCount', 'N/A')
            start_time_epoch = row.get('startTime', 'N/A')
            end_time_epoch = row.get('endTime', 'N/A')
            Direction = row.get('direction', 'N/A')
            Physical_Port = row.get('physicalPort', 'N/A')

            if start_time_epoch != 'N/A':
                start_time = epoch_to_datetime(start_time_epoch)
            else:
                start_time = 'N/A'

            if end_time_epoch != 'N/A':
                end_time = epoch_to_datetime(end_time_epoch)
            else:
                end_time = 'N/A'

            if start_time != 'N/A' and end_time != 'N/A':
                duration = calculate_duration(start_time, end_time)
            else:
                duration = 'N/A'

            syslog_id = attackipsid_to_syslog_id(attackid)
            print(syslog_id)
            table_data.append([device_ip,policy_id,attackid,radwareid,syslog_id,attack_category,attack_name,Threat_Group,Protocol,Source_Address,Source_Port,Destination_Address,Destination_Port,Action_Type,Attack_Status,Latest_State,final_footprint,Average_Attack_Rate_PPS,Average_Attack_Rate_BPS,Packet_Count,duration,start_time,end_time,Direction,Physical_Port])
        
        table = tabulate(table_data, headers=headers, tablefmt="pretty")
        
        with open('output_table.txt', 'w') as f:
            f.write(table)
        
        output_csv_file = "output_table.csv"

        with open(output_csv_file, mode='w', newline='') as csv_file:
            writer = csv.writer(csv_file)
            writer.writerow(headers)  # Write headers to CSV
            for row in table_data:
                writer.writerow(row)

        print(f"Data written to CSV file: {output_csv_file}")

    # Parse the saved response file and print the start and end times
    parse_response_file('response.json')

except ValueError as ve:
    print(str(ve))

