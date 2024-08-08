import os
import json
import collector
import data_parser
import clsVision
import graph_parser
import sftp_module

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
        from_month = epoch_from_to_time_list[2]
        start_year = epoch_from_to_time_list[3]
        to_month = epoch_from_to_time_list[4] if len(epoch_from_to_time_list) == 5 else None

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

        #get bdos attack log from Defensepros
        found_files = sftp_module.get_attack_log(device_ips,from_month, start_year, to_month)
        print(f"Files found: {found_files}")
       
        syslog_ids = data_parser.parse_response_file(outputFolder + 'response.json')
        #print(syslog_ids)

        for file in found_files:
            file_path = os.path.join(outputFolder, file)
            print(f"Processing file for BDoS attack logs: {file}")
            result = data_parser.parse_log_file(file_path, syslog_ids)
            #print(f"Result for {file}: {result}")

        categorized_logs = data_parser.categorize_logs_by_state(result)
        '''for syslog_id, entries in categorized_logs.items():
            if entries:
                print(f"\nBDOS Attack logs for Syslog ID {syslog_id}:")
            #for state, entries in state_logs.items():
                for entry in entries:
                    timestamp, state_description, log_entry = entry
                    print(f"{timestamp}: {state_description} - {log_entry}")'''

        print(categorized_logs)
        metrics, metricsHTML = data_parser.calculate_attack_metrics(categorized_logs)

        for syslog_id, metric in metrics.items():
            print(f"\nMetrics for Attack ID {syslog_id}:")
            print(f"Total Attack Duration: {metric['total_duration']}")
            print(f"Time taken to create initial footprint : {metric['state_2_to_4_duration']}")
            print(f"Time taken to optimize and create final footprint: {metric['state_4_to_6_duration']}")
            print(f"Blocking Time: {metric['blocking_time']}")
            print(f"Blocking Time Percentage: {metric['blocking_time_percentage']:.2f}%")



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


        #attack_log_info = attack_log_parser.parse_log_file(outputFolder + 'response.json', attack_ids)
        

        graphHTML = graph_parser.createGraphHTML(rate_data['bps'], rate_data['pps'])
        
        endHTML = "</body></html>"

        finalHTML = headerHTML + metricsHTML + graphHTML + endHTML

        with open(outputFolder + 'graphs.html', 'w') as file:
            file.write(finalHTML)
        print("Graphs and metrics saved to graphs.html")

