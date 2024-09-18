import os
import traceback
import json
import collector
import data_parser
import clsVision
import graph_parser
import sftp_module

collect_data=True
parse_data=True
outputFolder = './Output/'

def clear_output_folder(folder_path):
    if os.path.exists(folder_path):
        # Remove all files in the output folder
        for filename in os.listdir(folder_path):
            file_path = os.path.join(folder_path, filename)
            try:
                if os.path.isfile(file_path):
                    os.unlink(file_path)
            except Exception as e:
                print(f"Failed to delete {file_path}. Reason: {e}")
    else:
        # Create the output folder if it doesn't exist
        os.makedirs(folder_path)

clear_output_folder(outputFolder)

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
            policy_input = input(f"Enter the policies for {ip} separated by commas (or leave blank for All Policies): ").strip()
            if policy_input:
                policies[ip] = [policy.strip() for policy in policy_input.split(',')]

        #Get attack data

        attack_data = collector.get_attack_data(epoch_from_time, epoch_to_time, v, device_ips, policies, dp_list_ip)

        #Save the formatted JSON to a file
        with open(outputFolder + 'response.json', 'w') as file:
            json.dump(attack_data, file, indent=4)
        print("Response saved to response.json")

        #get bdos attack log from Defensepros
        found_files = sftp_module.get_attack_log(v, device_ips, from_month, start_year, to_month)
        print(f"Files found: {found_files}")
       
        syslog_ids, syslog_details = data_parser.parse_response_file(v,outputFolder + 'response.json')
        #print(syslog_details)
        all_results = {}

        for file in found_files:
            file_path = os.path.join(outputFolder, file)
            print(f"Processing file for BDoS attack logs: {file}")
            result = data_parser.parse_log_file(file_path, syslog_ids)
            
            all_results.update(result)
            #print(f"Result for {file}: {result}")
        #print(all_results)
        categorized_logs = data_parser.categorize_logs_by_state(all_results)
        #print(categorized_logs) 
        metrics = data_parser.calculate_attack_metrics(categorized_logs)
        for syslog_id in syslog_ids:
            if syslog_id in metrics:
                syslog_details[syslog_id].update(metrics[syslog_id])

        #print(metrics)

        #for each attack in syslog_details, check if ['graph'] is set to true. Graph is set to true for top_n graphs in the data_parser module.
        attackGraphData = {}
        for syslogID, details in syslog_details.items():
            if details.get('graph', False):
                attackData = v.getRawAttackSSH(details['Attack ID'])
                if len(attackData.get('data',"")) > 2:
                    attackGraphData.update({details['Attack Name'].replace(' ','_') + '_' + details['Attack ID']: attackData})
        with open(outputFolder + 'AttackGraphsData.json', 'w', encoding='utf-8') as file:
            json.dump(attackGraphData, file, ensure_ascii=False, indent=4)

        #Get the overall attack rate graph data for the specified time period
        selectedDevices = []
        if len(device_ips) > 0:
            for ip in device_ips:
                selectedDevices.append({'deviceId': ip, 'networkPolicies': policies.get(ip, []), 'ports': []})
        rate_data = {
            'bps': v.getAttackRate(epoch_from_time, epoch_to_time, "bps", selectedDevices),
            'pps': v.getAttackRate(epoch_from_time, epoch_to_time, "pps", selectedDevices)
            }
        #Save the raw attack rate graph data to a file
        with open(outputFolder + 'CombinedGraphData.json', 'w', encoding='utf-8') as file:
            json.dump(rate_data, file, ensure_ascii=False, indent=4)

    if parse_data:
        headerHTML = """<html>
  <head>
    <script type="text/javascript" src="https://www.gstatic.com/charts/loader.js"></script>
  </head>
  <body>"""

        #attack_log_info = attack_log_parser.parse_log_file(outputFolder + 'response.json', attack_ids)
        
        #with open(outputFolder + 'CombinedGraphData.json') as data_file:
        #    rate_data = json.load(data_file)
        graphHTML = graph_parser.createGraphHTMLOverall(rate_data['bps'], rate_data['pps'])
        top_by_bps, top_by_pps, unique_protocols, count_above_threshold = data_parser.get_top_n(syslog_details, top_n=10, threshold_gbps=1)
        attackdataHTML = data_parser.generate_html_report(top_by_bps, top_by_pps, unique_protocols, count_above_threshold, top_n=10, threshold_gbps=1)
        
        endHTML = "</body></html>"

        finalHTML = headerHTML + graphHTML + attackdataHTML 

        try:
            #with open(outputFolder + 'AttackGraphsData.json') as data_file:
            #    attackGraphData = json.load(data_file)
            finalHTML += graph_parser.createCombinedChart("All Attacks", attackGraphData) 
        except:
            print("Unexpected createCombinedChart() error: ")
            traceback.print_exc()

        #Add an individual graph for each attack
        for attackID, data in attackGraphData.items():
            try:
                finalHTML += graph_parser.createGraphHTMLGoogleCharts(attackID, data)
            except:
                print(f"Error graphing attackID '{attackID}':")
                traceback.print_exc()

        finalHTML += endHTML

        with open(outputFolder + 'DP-Attack-Story_Report.html', 'w') as file:
            file.write(finalHTML)
        print("Graphs and metrics saved to DP-Attack-Story_Report.html")

