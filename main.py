import os
import traceback
import json
import datetime

#internal modules
import clsVision
import collector
import data_parser
import html_data
import html_graphs
import html_header
import sftp_module

#Default options such as topN and output folder are now stored in common.py. 
from common import *


collect_data=True
parse_data=True
if __name__ == '__main__':
    if collect_data:
        #Make sure outputFolder exists and that it is empty
        if os.path.exists(outputFolder):
            # Remove all files in the output folder
            for filename in os.listdir(outputFolder):
                file_path = os.path.join(outputFolder, filename)
                try:
                    if os.path.isfile(file_path):
                        os.unlink(file_path)
                except Exception as e:
                    print(f"Failed to delete {file_path}. Reason: {e}")
        else:
            # Create the output folder if it doesn't exist
            os.makedirs(outputFolder)

        #Get start time and end time from the user input
        epoch_from_to_time_list = collector.prompt_user_time_period()
        epoch_from_time = epoch_from_to_time_list[0]
        epoch_to_time = epoch_from_to_time_list[1]
        from_month = epoch_from_to_time_list[2]
        start_year = epoch_from_to_time_list[3]
        to_month = epoch_from_to_time_list[4] if len(epoch_from_to_time_list) == 5 else None

        #Connect to Vision (instantiate v as a logged in vision instance. This will prompt a user for credentials)
        v = clsVision.clsVision()

        #Prompt user for a list of DefensePros
        device_ips, dp_list_ip = collector.user_selects_defensePros(v)

        policies = {}
        for ip in device_ips:
            ip = ip.strip()
            policy_input = input(f"Enter the policies for {dp_list_ip[ip]['name']} ({ip}) separated by commas (or leave blank for All Policies): ").strip()
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
       
        syslog_ids, syslog_details = data_parser.parse_response_file(v)
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
        with open(outputFolder + 'TopGraphsData.json', 'w', encoding='utf-8') as file:
            json.dump(rate_data, file, ensure_ascii=False, indent=4)
        
        #Save a file with the details of the current run.
            #altenate datetime format .strftime('%a, %d %b %Y %H:%M:%S %Z')
        executionStatistics=f"""\
Start Time: {datetime.datetime.fromtimestamp(epoch_from_time/1000, tz=datetime.timezone.utc).strftime('%d-%m-%Y %H:%M:%S %Z')}
End Time: {datetime.datetime.fromtimestamp(epoch_to_time  /1000, tz=datetime.timezone.utc).strftime('%d-%m-%Y %H:%M:%S %Z')}
Vision / Cyber Controller IP: {v.ip}
DPs: {', '.join(device_ips)}
Policies: {"All" if len(policies) == 0 else policies}"""
        with open(outputFolder + 'ExecutionDetails.txt', 'w', encoding='utf-8') as file:
            file.write(executionStatistics)

        ##############################End of Collect_Data section##############################




    if parse_data:
        #Open executionStatistics.txt and include the contained information in the header
        statsForHeader = ""
        with open(outputFolder + 'ExecutionDetails.txt', "r") as file:
            for line in file:
                statsForHeader += f"<p>{line.strip()}</p>\n"

        headerHTML = html_header.getHeader(statsForHeader) + html_graphs.graphPrerequesites()

        #attack_log_info = attack_log_parser.parse_log_file(outputFolder + 'response.json', attack_ids)
        
        #Create the two graphs at the top of the HTML file
        with open(outputFolder + 'TopGraphsData.json') as data_file:
            rate_data = json.load(data_file)
        graphHTML = html_graphs.createTopGraphsHTML(rate_data['bps'], rate_data['pps'])

        top_by_bps, top_by_pps, unique_protocols, count_above_threshold = html_data.get_top_n(syslog_details, topN, threshold_gbps=1)
        bps_data, pps_data = collector.get_all_sample_data(v, top_by_bps, top_by_pps)
        #print("BPS Data:", bps_data)
        #print("PPS Data:", pps_data)
        attackdataHTML = html_data.generate_html_report(top_by_bps, top_by_pps, unique_protocols, count_above_threshold, bps_data, pps_data, topN, threshold_gbps=1)
        
        

        finalHTML = headerHTML + graphHTML + attackdataHTML 

        #Create dynamic graph combining all attacks into one graph.
        try:
            with open(outputFolder + 'AttackGraphsData.json') as data_file:
                attackGraphData = json.load(data_file)
            finalHTML += html_graphs.createCombinedChart("All Attacks", attackGraphData) 
        except:
            print("Unexpected createCombinedChart() error: ")
            traceback.print_exc()

        #Add an individual graph for each attack
        for attackID, data in attackGraphData.items():
            try:
                finalHTML += html_graphs.createSingleChart(attackID, data)
            except:
                print(f"Error graphing attackID '{attackID}':")
                traceback.print_exc()

        endHTML = "</body></html>"
        finalHTML += endHTML

        with open(outputFolder + 'DP-Attack-Story_Report.html', 'w') as file:
            file.write(finalHTML)
        print("Graphs and metrics saved to DP-Attack-Story_Report.html")

        ##############################End of Parse_Data Section##############################
