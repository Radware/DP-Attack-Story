import os
import json

import collector
import data_parser
import clsVision
import graph_parser

collect_data=True
parse_data=True
outputFolder = './Output/'

if not os.path.exists(outputFolder):
    os.makedirs(outputFolder)


if __name__ == '__main__':
    if collect_data:
        #Get start time and end time from the user input
        epoch_from_to_time_list = collector.prompt_user_time_period()
        epoch_from_time = epoch_from_to_time_list[0]
        epoch_to_time = epoch_from_to_time_list[1]

        #Connect to Vision (instantiate v as a logged in vision instance)
        v = clsVision.clsVision()
        #print available devices
        #collector.display_available_devices(v)
        #device_ips = input("Enter the device IPs separated by commas. Input 'All' to use all available Defensepros: ").split(',')

        device_ips, dp_list_ip = collector.display_available_devices(v)

        policies = {}
        for ip in device_ips:
            ip = ip.strip()
            policy_input = input(f"Enter the policies for {ip} separated by commas (or leave blank to skip): ").strip()
            if policy_input:
                policies[ip] = [policy.strip() for policy in policy_input.split(',')]

        #Get attack data

        attack_data = collector.get_attack_data(epoch_from_time, epoch_to_time, v, device_ips, policies, dp_list_ip)

        #Save the formatted JSON to a file
        with open(outputFolder + 'response.json', 'w') as file:
            json.dump(attack_data, file, indent=4)
        print("Response saved to response.json")

        #Get the attack rate graph data for the specified time period
        rate_data = {
            'bps': v.getAttackRate(epoch_from_time,epoch_to_time,"bps"),
            'pps': v.getAttackRate(epoch_from_time,epoch_to_time,"pps")
            }
        #Save the raw attack rate graph data to a file
        ######

    if parse_data:
        headerHTML = """<html>
  <head>
    <script type="text/javascript" src="https://www.gstatic.com/charts/loader.js"></script>
  </head>
  <body>"""

        data_parser.parse_response_file(outputFolder + 'response.json')

        graphHTML = graph_parser.createGraphHTML(rate_data['bps'], rate_data['pps'])
        
        endHTML = "</body></html>"
        with open(outputFolder + 'graphs.html', 'w') as file:
            file.write(headerHTML + graphHTML + endHTML)
        print("Graphs saved to graphs.html")

