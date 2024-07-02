#Version 0.4.1
#Updated 26 June 2024

import json
#import urllib3 #unused at this point
#import pandas as pd #unused at this point
import time
from clsVision import *
from datetime import datetime

outputFolder = './Output/'

if not os.path.exists(outputFolder):
    os.makedirs(outputFolder)

#instantiate v as a logged in vision instance:
v = clsVision()

#################### Helper functions ####################

def convert_to_epoch(human_readable_time, time_format='%d-%m-%Y %H:%M:%S'):
    # Parse the human-readable time to a datetime object
    dt = datetime.strptime(human_readable_time, time_format)
    # Convert the datetime object to epoch time
    epoch_time = int(time.mktime(dt.timetuple()) * 1000)
    return epoch_time

def set_user_time_period():

    #Ask user for time period:
    print("Please select a time period:")
    print("1) The past 24 hours")
    print("2) The past 48 hours")
    print("3) Manually enter times")
    choice = input("Enter selection (1-3) or other to quit: ")
    if choice == '1':
        epoch_from_time = (int(time.time()) - (60 * 60 * 24)) * 1000
        epoch_to_time = int(time.time()) * 1000
    elif choice == '2':
        epoch_from_time = (int(time.time()) - (60 * 60 * 48)) * 1000
        epoch_to_time = int(time.time()) * 1000
    elif choice == '3':
        from_time = input("Enter the duration start time (format: DD-MM-YYYY HH:MM:SS): ")
        epoch_from_time = convert_to_epoch(from_time)
        to_time = input("Enter the duration end time (format: DD-MM-YYYY HH:MM:SS): ")
        epoch_to_time = convert_to_epoch(to_time)
    else:
        print("Other input, quit")
        exit(1)

    epoch_time_range = [epoch_from_time,epoch_to_time]
    return epoch_time_range

def get_available_devices():
    #Display a list of available DefensePros
    DPString = '\nAvailable devices: '
    for DP in v.getDPDeviceList():
        DPString += DP['managementIp'] + " "
    print(DPString)
    return DPString

def get_attack_data(epoch_from_time,epoch_to_time):
    device_ip = input("Enter the device IP: ")

    #Query Vision for attack data that matches the specified timeframe
    response_data = v.getAttackReports(device_ip, epoch_from_time, epoch_to_time)
    print(response_data)

    try:
        total_hits = int(response_data["metaData"]["totalHits"])
        if total_hits == 0:
            raise ValueError("No data present for the specified time period.")
        
        # Save the formatted JSON to a file
        with open(outputFolder + 'response.json', 'w') as file:
            json.dump(response_data, file, indent=4)

        print("Response saved to response.json")

    except ValueError as ve:
        print(str(ve)) # type: ignore
             
    return response_data


        
