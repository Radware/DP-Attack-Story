from datetime import datetime
import json
import csv

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
	
	with open(outputFolder + 'output_table.txt', 'w') as f:
		f.write(table)
	
	output_csv_file = outputFolder + "output_table.csv"

	with open(output_csv_file, mode='w', newline='') as csv_file:
		writer = csv.writer(csv_file)
		writer.writerow(headers)  # Write headers to CSV
		for row in table_data:
			writer.writerow(row)

	print(f"Data written to CSV file: {output_csv_file}")


 # type: ignore