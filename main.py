import os
import traceback
import json
import datetime
import tarfile

#internal modules
import clsVision
import collector
import data_parser
import html_attack_summary
import html_data
import html_graphs
import html_header
import sftp_module

#Default options such as topN and output folder are now stored in common.py. 
from common import *


collect_data=True
parse_data=True
if __name__ == '__main__':
    if collect_data and (not args or (args[0].lower() != '--offline' and args[0] != '-o')):
    #if collect_data:
        #Make sure outputFolder exists and that it is empty
        if os.path.exists(outputFolder):
            # Remove all files in the output folder
            for filename in os.listdir(outputFolder):
                file_path = os.path.join(outputFolder, filename)
                if LogfileName not in file_path:
                    try:
                        if os.path.isfile(file_path):
                            os.unlink(file_path)
                    except Exception as e:
                        update_log(f"Failed to delete {file_path}. Reason: {e}")
            pass
        else:
            # Create the output folder if it doesn't exist
            os.makedirs(outputFolder)

        #Connect to Vision (instantiate v as a logged in vision instance. This will prompt a user for credentials)
        v = clsVision.clsVision()

        #Get start time and end time from the user input
        epoch_from_to_time_list = collector.prompt_user_time_period()
        epoch_from_time = epoch_from_to_time_list[0]
        epoch_to_time = epoch_from_to_time_list[1]
        from_month = epoch_from_to_time_list[2]
        start_year = epoch_from_to_time_list[3]
        to_month = epoch_from_to_time_list[4] if len(epoch_from_to_time_list) == 5 else None

        

        #Prompt user for a list of DefensePros
        device_ips, dp_list_ip = collector.user_selects_defensePros(v)

        policies = {}
        args_used = False
        for ip in device_ips:
            ip = ip.strip()
            if args:
                policy_input = args.pop(0).strip()
                args_used = True
            else:
                if len(sys.argv) == 1: #Only prompt if script is run without arguments. Length of 1 is 0 user arguments.
                    policy_data = v.getDPPolicies(ip)['rsIDSNewRulesTable']
                    policy_names = ', '.join(policy['rsIDSNewRulesName'] for policy in policy_data)
                    print(f"\nPlease enter the policy names for {dp_list_ip[ip]['name']} ({ip}), separated by commas")
                    print(f"    Available policies: ")
                    print(f"        {policy_names}")
                    policy_input = input(f"Policies (leave blank for All Policies): ").strip()
                else:
                    #Args have been used elsewhere but no args have been specified for policies. Default to no filter.
                    policy_input = ""
            if policy_input:
                policies[ip] = [policy.strip() for policy in policy_input.split(',')]

        #Get attack data

        attack_data = collector.get_attack_data(epoch_from_time, epoch_to_time, v, device_ips, policies, dp_list_ip)

        #Save the formatted JSON to a file
        with open(outputFolder + 'response.json', 'w') as file:
            json.dump(attack_data, file, indent=4)
        update_log("Response saved to response.json")

        #get bdos attack log from Defensepros
        found_files = sftp_module.get_attack_log(v, device_ips, from_month, start_year, to_month)
        update_log(f"Files found: {found_files}")
       
        syslog_ids, syslog_details = data_parser.parse_response_file(v)
        #print(syslog_details)
        all_results = {}

        for file in found_files:
            file_path = os.path.join(outputFolder, file)
            update_log(f"Processing file for BDoS attack logs: {file}")
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

        # Calculate top BPS and PPS using html_data.get_top_n
        top_by_bps, top_by_pps, unique_protocols, count_above_threshold = html_data.get_top_n(syslog_details, topN, threshold_gbps=1)
        with open(outputFolder + 'TopMetrics.json', 'w') as file:
            json.dump({
                'top_by_bps': top_by_bps,
                'top_by_pps': top_by_pps,
                'unique_protocols': unique_protocols,
                'count_above_threshold': count_above_threshold
            }, file, ensure_ascii=False, indent=4)

        bps_data, pps_data, unique_ips_bps, unique_ips_pps, deduplicated_sample_data, combined_unique_samples = collector.get_all_sample_data(v, top_by_bps, top_by_pps)
        print(combined_unique_samples)

        with open(outputFolder + 'SampleData.json', 'w') as file:
            json.dump({
                'bps_data': bps_data,
                'pps_data': pps_data,
                'unique_ips_bps': unique_ips_bps,
                'unique_ips_pps': unique_ips_pps,
                'deduplicated_sample_data': deduplicated_sample_data,
                'combined_unique_samples': combined_unique_samples
            }, file, ensure_ascii=False, indent=4)

        #print(metrics)
        #for each attack in syslog_details, check if ['graph'] is set to true. Graph is set to true for top_n graphs in the data_parser module.
        attack_graph_data = {}
        for syslogID, details in syslog_details.items():
            if details.get('graph', False):
                attackData = v.getRawAttackSSH(details['Attack ID'])
                if len(attackData.get('data',"")) > 2:
                    attack_graph_data.update({details['Attack Name'].replace(' ','_') + '_' + details['Attack ID']: attackData})
        with open(outputFolder + 'AttackGraphsData.json', 'w', encoding='utf-8') as file:
            json.dump(attack_graph_data, file, ensure_ascii=False, indent=4)

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
Top {topN} Attacks by BPS and CPS
Start Time: {datetime.datetime.fromtimestamp(epoch_from_time/1000, tz=datetime.timezone.utc).strftime('%d-%m-%Y %H:%M:%S %Z')}
End Time: {datetime.datetime.fromtimestamp(epoch_to_time  /1000, tz=datetime.timezone.utc).strftime('%d-%m-%Y %H:%M:%S %Z')}
Vision / Cyber Controller IP: {v.ip}
DPs: {', '.join(device_ips)}
Policies: {"All" if len(policies) == 0 else policies}"""
        
        with open(outputFolder + 'ExecutionDetails.txt', 'w', encoding='utf-8') as file:
            file.write(executionStatistics)

        ##############################End of Collect_Data section##############################



    if parse_data:
        # Load saved metrics if collect_data is False
        with open(outputFolder + 'TopMetrics.json') as file:
            top_metrics = json.load(file)
        top_by_bps = top_metrics['top_by_bps']
        top_by_pps = top_metrics['top_by_pps']
        unique_protocols = top_metrics['unique_protocols']
        count_above_threshold = top_metrics['count_above_threshold']

        # Read sample data from JSON file
        with open(outputFolder + 'SampleData.json') as file:
            sample_data = json.load(file)
        bps_data = sample_data['bps_data']
        pps_data = sample_data['pps_data']
        unique_ips_bps = sample_data['unique_ips_bps']
        unique_ips_pps = sample_data['unique_ips_pps']
        deduplicated_sample_data = sample_data['deduplicated_sample_data']
        combined_unique_samples = sample_data['combined_unique_samples']

        #Create a set of the topN attack IDs
        top_n_attack_ids = set()
        for attack in top_metrics['top_by_bps']:
            top_n_attack_ids.add(attack[1]['Attack ID'])
        for attack in top_metrics['top_by_pps']:
            top_n_attack_ids.add(attack[1]['Attack ID'])

        #Load graph data from JSON file
        with open(outputFolder + 'AttackGraphsData.json') as data_file:
            attack_graph_data = json.load(data_file)
        with open(outputFolder + 'TopGraphsData.json') as data_file:
            rate_data = json.load(data_file)
        with open(outputFolder + 'response.json') as data_file:
            attack_data = json.load(data_file)

        #Open executionStatistics.txt and include the contained information in the header
        statsForHeader = ""
        with open(outputFolder + 'ExecutionDetails.txt', "r") as file:
            for line in file:
                statsForHeader += f"<p>{line.strip()}</p>\n"

        finalHTML = html_header.getHeader(statsForHeader) + html_graphs.graphPrerequesites()

        finalHTML += "\n<h2>Attack Summary</h2>"
        finalHTML += html_attack_summary.getSummary(top_metrics, rate_data, attack_graph_data, deduplicated_sample_data, attack_data, top_n_attack_ids)

        #Create the two graphs at the top of the HTML file
        finalHTML += "\n<h2>Traffic Bandwidth</h2>"
        graphHTML = html_graphs.createTopGraphsHTML(rate_data['bps'], rate_data['pps'])
        finalHTML += graphHTML

        #Create pie charts
        finalHTML += html_graphs.createPieCharts(attack_data, top_n_attack_ids)


        #top_by_bps, top_by_pps, unique_protocols, count_above_threshold = html_data.get_top_n(syslog_details, topN, threshold_gbps=1)
        #bps_data, pps_data = collector.get_all_sample_data(v, top_by_bps, top_by_pps)
        # Call the function to get all sample data and unique source IPs
        #bps_data, pps_data, unique_ips_bps, unique_ips_pps = collector.get_all_sample_data(v, top_by_bps, top_by_pps)
        #bps_data, pps_data, unique_ips_bps, unique_ips_pps, deduplicated_sample_data, combined_unique_samples = collector.get_all_sample_data(v, top_by_bps, top_by_pps)
        #print(combined_unique_samples)
        #print("BPS Data:", bps_data)
        #print("PPS Data:", pps_data)
        attackdataHTML = html_data.generate_html_report(top_by_bps, top_by_pps, unique_protocols, count_above_threshold, bps_data, pps_data, unique_ips_bps, unique_ips_pps, deduplicated_sample_data, topN, threshold_gbps=1)
        finalHTML += attackdataHTML 

        #Create dynamic graph combining all attacks into one graph.
        finalHTML += "\n<h2>Combined Chart</h2>"
        try:
            finalHTML += html_graphs.createCombinedChart("Custom", attack_graph_data) 
        except:
            update_log("Unexpected createCombinedChart() error: ")
            traceback.print_exc()

        finalHTML += "\n<h2>Charts per attack ID</h2>"
        #Add an individual graph for each attack
        for attackID, data in attack_graph_data.items():
            try:
                #inalHTML += html_graphs.createChart(attackID, data, epoch_from_time, epoch_to_time)
                finalHTML += html_graphs.createChart(attackID, data)
            except:
                update_log(f"Error graphing attackID '{attackID}':")
                traceback.print_exc()

        endHTML = "</body></html>"
        finalHTML += endHTML

        html_file_path = os.path.join(outputFolder, 'DP-Attack-Story_Report.html')
        with open(html_file_path, 'w') as file:
            file.write(finalHTML)
        update_log(f"Graphs and metrics saved to {html_file_path}")
        
        #Script execution complete. Compress and delete the output folder
        if False:
            if config.get("General","Compress_Output","TRUE").upper() == "TRUE":
                with tarfile.open(outputFolder[:-1] + ".tgz", "w:gz"):
                    tarfile.add(outputFolder, arcname='.') #Arcname='.' preserves the folder structure
                    print(f"{outputFolder} has been compressed to {outputFolder[:-1]}.tgz")
                if os.path.exists(outputFolder):
                    # Remove all files in the output folder
                    for filename in os.listdir(outputFolder):
                        file_path = os.path.join(outputFolder, filename)
                        try:
                            if os.path.isfile(file_path):
                                os.unlink(file_path)
                        except Exception as e:
                            update_log(f"Failed to delete {file_path}. Reason: {e}")
                    try:
                        os.rmdir(outputFolder)
                        print(f"{outputFolder} has been deleted.")
                    except FileNotFoundError:
                        print(f"{outputFolder} does not exist.")
                    except OSError:
                        print(f"{outputFolder} is not empty or cannot be deleted.")

        ##############################End of Parse_Data Section##############################
