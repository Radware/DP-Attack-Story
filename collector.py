#Version 0.4.1
#Updated 26 June 2024

import json
#import urllib3 #unused at this point
#import pandas as pd #unused at this point
import time
from clsVision import *
from datetime import datetime




#################### Helper functions ####################

def convert_to_epoch(human_readable_time, time_format='%d-%m-%Y %H:%M:%S'):
    # Parse the human-readable time to a datetime object
    dt = datetime.strptime(human_readable_time, time_format)
    # Convert the datetime object to epoch time
    epoch_time = int(time.mktime(dt.timetuple()) * 1000)
    return epoch_time

def prompt_user_time_period():
    """ Prompt user for time period, returns a list, [0] epoch start time, [1] epoch end time """

    #Ask user for time period:
    print("Please select a time period:")
    print("1) The past 2 hours")
    print("2) The past 48 hours")
    print("3) Manually enter times")
    choice = input("Enter selection (1-3) or other to quit: ")
    if choice == '1':
        epoch_from_time = (int(time.time()) - (60 * 60 * 2)) * 1000
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

def display_available_devices(v):
    """
    Fetches the list of available DefensePro devices from Vision instance 'v',
    displays them to the user, and validates user input for device IPs.
    Returns:
    - device_ips (list): A list of validated DefensePro device IPs entered by the user.
    - dp_list_ip (dict): A dictionary mapping DefensePro device IPs to device information, fetched from the Vision instance 'v'.
                         Keys are device IPs and values are the corresponding device information.
    """
    try:
        device_list = v.getDPDeviceList()
        dp_list_ip = {device['managementIp']: device for device in device_list}
        
        # Display list of available DefensePros
        print("Available Defensepros: " + ' '.join(dp_list_ip.keys()))
        
        while True:
            device_ips = input("Enter the device IPs separated by commas. Input 'All' to use all available DefensePros: ").split(',')
            if device_ips[0].upper() == "ALL":
                device_ips = list(dp_list_ip.keys())
                break
            else:
                # Validate IP addresses format and existence
                valid_ips = []
                invalid_ips = []
                for ip in device_ips:
                    ip = ip.strip()
                    if ip in dp_list_ip:
                        valid_ips.append(ip)
                    else:
                        invalid_ips.append(ip)

                if invalid_ips:
                    print(f"The following IPs are invalid or not available: {', '.join(invalid_ips)}")
                if valid_ips:
                    device_ips = valid_ips
                    break
                else:
                    print("Please enter valid IP addresses.")

        return device_ips, dp_list_ip

    except Exception as e:
        print(f"An error occurred while fetching device list: {e}")
        return [], {}


def get_attack_data(epoch_from_time,epoch_to_time,v, device_ips, policies, dp_list_ip):


    try:
  
        attack_data = {}

        for device_ip in device_ips:
            device_ip = device_ip.strip()
            if device_ip not in dp_list_ip:
                print(f"Device IP {device_ip} is not available or does not exist. Skipping.")
                continue
            device_policies = policies.get(device_ip, [])
            filters = [
                {
                    "type": "termFilter",
                    "inverseFilter": False,
                    "field": "ruleName",
                    "value": policy
                }
                for policy in device_policies
            ]
            
            filter_json = {
                "type": "orFilter",
                "inverseFilter": False,
                "filters": filters
            } if filters else None

            response_data = v.getAttackReports(device_ip, epoch_from_time, epoch_to_time,filter_json)

            print(f"Attack data for {device_ip}:")
            #print(response_data)
            try:
                    total_hits = int(response_data["metaData"]["totalHits"])
                    if total_hits == 0:
                        raise ValueError(f"No data present for the specified time period for {device_ip}")
            except KeyError:
                    print(f"No 'metaData' key in response for {device_ip}")
                    continue
            except ValueError as ve:
                    print(str(ve))
                    continue   

            attack_data[device_ip] = response_data

        
        return attack_data

    except Exception as e:
        print(f"An error occurred: {e}")             
    


        
