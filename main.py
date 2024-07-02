import collector
import data_parser
import clsVision
import os
import json

collect_data=True
parse_data=False
outputFolder = './Output/'

if not os.path.exists(outputFolder):
	os.makedirs(outputFolder)


if __name__ == '__main__':
	if collect_data:
		#1 Get start time and end time from the user input
		epoch_from_to_time_list = collector.prompt_user_time_period()
		epoch_from_time = epoch_from_to_time_list[0]
		epoch_to_time = epoch_from_to_time_list[1]

		#2 Connect to Vision (instantiate v as a logged in vision instance)
		v = clsVision()

		#3 Get attack data
		attack_data= collector.get_attack_data(epoch_from_time,epoch_to_time,v)

		#4 Save the formatted JSON to a file
		with open(outputFolder + 'response.json', 'w') as file:
			json.dump(attack_data, file, indent=4)
		print("Response saved to response.json")

	if parse_data:
		data_parser.parse_response_file(outputFolder + 'response.json')


