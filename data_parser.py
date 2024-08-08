from datetime import datetime
import json
import csv
import re
from collections import defaultdict

try:
    from tabulate import tabulate
except ImportError:
    print("The python module 'tabulate' is not installed. Please install it by running: pip install tabulate")
    exit()

#################### Helper functions ####################

def epoch_to_datetime(epoch_time):
	"""Convert epoch time to human-readable datetime format."""
	epoch_time = int(epoch_time)  # Convert epoch_time to integer
	return datetime.fromtimestamp(epoch_time / 1000.0).strftime('%d-%m-%Y %H:%M:%S')
	#return datetime.fromtimestamp(epoch_time / 1000.0).strftime('%Y-%m-%d %H:%M:%S')

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


def parse_response_file(outputFolder):
	with open(outputFolder, 'r') as file:
		data = json.load(file)

	#Parse and extract start time and end time for each "row" in "data"
	#rows = data.get('data', [])
	#print(rows)
	
	table_data = []
	syslog_ids = []
	headers = ["Device IP", "Policy", "Attack ID", "Radware ID", "Syslog ID" , "Attack Category", "Attack Name", "Threat Group", "Protocol", "Source Address", "Source Port", "Destination Address", "Destination Port", "Action", "Attack Status", "Latest Attack State", "Final Attack Footprint", "Average Attack Rate(PPS)", "Average Attack Rate(BPS)", "Max Attack Rate(BPS)", "Packet Count", "Attack Duration", "Start Time", "End Time", "Direction", "Physical Port"]

	for ip_address, ip_data in data.items():
		if ip_address == 'metaData':
			continue
        
		for row_data in ip_data.get('data', []):
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
			Max_Attack_Rate_BPS = row.get('maxAttackRateBps',' N/A')   
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
			#syslog_id = attackid.split('-')[1] if attackid != 'N/A' else 'N/A'
			table_data.append([device_ip, policy_id, attackid, radwareid, syslog_id, attack_category, attack_name, Threat_Group, Protocol, Source_Address, Source_Port, Destination_Address, Destination_Port, Action_Type, Attack_Status, Latest_State, final_footprint, Average_Attack_Rate_PPS, Average_Attack_Rate_BPS, Max_Attack_Rate_BPS, Packet_Count, duration, start_time, end_time, Direction, Physical_Port])
			syslog_ids.append(syslog_id)

	table_data.sort(key=lambda x: float(x[19]) if x[19] != 'N/A' else 0, reverse=True)    
	table = tabulate(table_data, headers=headers, tablefmt="pretty")


	with open(outputFolder + 'output_table.txt', 'w') as f:
		f.write(table)

	output_csv_file = outputFolder + "output_table.csv"
	with open(output_csv_file, mode='w', newline='') as csv_file:
		writer = csv.writer(csv_file)
		writer.writerow(headers)  # Write headers to CSV
		for row in table_data:
			writer.writerow(row)

	print(f"Data written to CSV file: {output_csv_file}")
	return syslog_ids
	
def parse_log_file(outputFolder, syslog_ids):
    # Initialize a dictionary to hold the log entries for each attack ID
    attack_logs = {syslog_id: [] for syslog_id in syslog_ids}
    
    with open(outputFolder, 'r') as file:
        lines = file.readlines()

        # Store previous line information
        prev_line = None
        
        for i in range(len(lines)):
            line = lines[i].strip()
            
            if prev_line is not None:
                # Check if the previous line contains the special attack ID
                if 'FFFFFFFF-0000-0000-0000-000000000000' in prev_line:
                    for syslog_id in syslog_ids:
                        if syslog_id in line:
                            prev_timestamp = prev_line.split(',')[0].strip()
                            prev_data = prev_line.split(',', 5)[-1].strip()
                            attack_logs[syslog_id].append((prev_timestamp, prev_data))
                            break  # Move to the next line after processing the attack_id
            
            # Check if the current line contains any attack ID
            for syslog_id in syslog_ids:
                if syslog_id in line:
                    timestamp = line.split(',')[0].strip()
                    data = line.split(',', 5)[-1].strip()
                    attack_logs[syslog_id].append((timestamp, data))
                    break  # Move to the next line after processing the attack_id
            
            # Update previous line information
            prev_line = line

    return attack_logs

 # type: ignore

def categorize_logs_by_state(attack_logs):
    # State definitions
	state_definitions = {
        '0': "Attack Ended",
        '2': "Attack has been detected, fp characterization started - FORWARDING",
        #'3': "Anomaly state (Generated FP not able to mitigate the attack)",
        '4': "Initial fp created - FORWARDING",
        #'5': "Sub-hierarchy state (AND part of the FP is created)",
        '6': "Final fp created - BLOCKING"
        #'7': "Non-strictness footprint state (When generated FP is not meeting strictness level)",
		#'9': "Burst attack state (Handling burst attack)"
	}
	
	# Initialize a dictionary to hold categorized logs based on states
	#categorized_logs = {syslog_id: [] for syslog_id in attack_logs}
	categorized_logs = {syslog_id: [] for syslog_id in attack_logs}
	state_pattern = re.compile(r"Entering state (\d+)")
	footprint_pattern = re.compile(r"Footprint \[(.*)\]")
	
	for syslog_id, logs in attack_logs.items():
		current_state = None
		for timestamp, entry in logs:
			state_match = state_pattern.search(entry)
			footprint_match = footprint_pattern.search(entry)
			if state_match:
				state_code = state_match.group(1)
				if state_code in state_definitions:
					current_state = state_match.group(1)
					state_description = state_definitions[state_code]
					categorized_logs[syslog_id].append((timestamp, f"State {state_code}: {state_description}", entry))
			elif footprint_match and current_state in state_definitions:
				state_description = state_definitions.get(current_state, "Unknown state")
				categorized_logs[syslog_id].append((timestamp, f"State {current_state}: {state_description}", entry))
    
	return categorized_logs


def calculate_attack_metrics(categorized_logs):
    metrics = {}
    metrics_html = "<h2>Attack Metrics</h2>"

    metrics_html += """
    <table border="1" style="width: 100%; border-collapse: collapse;">
        <tr>
            <th style="width: 30%;">Attack ID</th>
            <th style="width: 70%;">Metrics</th>
         </tr>
    """

    for syslog_id, entries in categorized_logs.items():
        state_2_time = None
        state_4_time = None
        state_6_start = None
        state_0_time = None
        state_6_footprint = None
        
        timestamps = [entry[0] for entry in entries]
        if not timestamps:
            continue
        
        # Format for parsing timestamps
        fmt = '%d-%m-%Y %H:%M:%S'
        
        # Convert the first and last timestamps to datetime objects
        first_time = datetime.strptime(timestamps[0], fmt)
        last_time = datetime.strptime(timestamps[-1], fmt)

        first_entry_state = entries[0][1]

        if "State 6" in first_entry_state:
            state_6_start = first_time
            # Find states 2, 4, and 6 before reaching state 0
            for entry in entries[1:]:
                timestamp, state_description, _ = entry
                log_time = datetime.strptime(timestamp, fmt)

                if "State 0" in state_description:
                    break
                elif "State 2:" in state_description and state_2_time is None:
                    state_2_time = log_time
                elif "State 4:" in state_description and state_4_time is None:
                    state_4_time = log_time
                elif "State 6" in state_description and state_2_time and state_4_time:
                    state_6_start = log_time
        else:
            # Iterate through the entries to find states 2, 4, 6, and 0
            for entry in entries:
                timestamp, state_description, _ = entry
                log_time = datetime.strptime(timestamp, fmt)

                if "State 2:" in state_description and state_2_time is None:
                    state_2_time = log_time
                elif "State 4:" in state_description and state_4_time is None:
                    state_4_time = log_time
                elif "State 6" in state_description and state_6_start is None:
                    state_6_start = log_time
                elif "State 0" in state_description and state_0_time is None:
                    state_0_time = log_time

                if state_2_time and state_4_time and state_6_start and state_0_time:
                    break

        # Calculate the total duration of the attack
        duration = last_time - first_time

        # Calculate the time differences between states
        state_2_to_4_duration = None
        if state_2_time and state_4_time:
            state_2_to_4_duration = state_4_time - state_2_time
            if state_2_to_4_duration.total_seconds() < 0:
                state_2_to_4_duration = None

        state_4_to_6_duration = None
        if state_4_time and state_6_start:
            state_4_to_6_duration = state_6_start - state_4_time
            if state_4_to_6_duration.total_seconds() < 0:
                state_4_to_6_duration = None

        # Calculate the blocking time from state 6
        blocking_time = None
        if state_6_start:
            blocking_time = last_time - state_6_start
            if blocking_time.total_seconds() < 0:
                blocking_time = None

        blocking_time_percentage = None
        if duration and blocking_time:
            blocking_time_percentage = (blocking_time / duration) * 100

        # Store the metrics for this syslog_id
        metrics[syslog_id] = {
            'total_duration': duration,
            'state_2_to_4_duration': state_2_to_4_duration,
            'state_4_to_6_duration': state_4_to_6_duration,
            'blocking_time': blocking_time,
            'blocking_time_percentage': blocking_time_percentage
        }

        metrics_html += f"<tr><td>{syslog_id}</td><td>"
        metrics_html += f"Total Attack Duration: {duration}<br>"
        if state_2_to_4_duration is not None:
            metrics_html += f"Time taken to create initial footprint: {state_2_to_4_duration}<br>"
        else:
            metrics_html += "Time taken to create initial footprint: N/A<br>"
        if state_4_to_6_duration is not None:
            metrics_html += f"Time taken to optimize and create final footprint: {state_4_to_6_duration}<br>"
        else:
            metrics_html += "Time taken to optimize and create final footprint: N/A<br>"  
        metrics_html += f"Blocking Time: {blocking_time}<br>"
        if blocking_time_percentage is not None:
            metrics_html += f"Blocking Time Percentage: {blocking_time_percentage:.2f}%"
        else:
            metrics_html += "Blocking Time Percentage: N/A"
        metrics_html += "</td></tr>"

    metrics_html += "</table>"
    return metrics, metrics_html