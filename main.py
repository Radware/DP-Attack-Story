import collector
import data_parser

collect_data=True
parse_data=False
outputFolder = './Output/'


if __name__ == '__main__':
	if collect_data:
		print('true')

		#1 Get start time and end time
		epoch_from_to_time_list = collector.set_user_time_period()
		epoch_from_time = epoch_from_to_time_list[0]
		epoch_to_time = epoch_from_to_time_list[1]

		#2 Display list of available devices
		collector.get_available_devices()

		#3 Get attack data

		attack_data= collector.get_attack_data(epoch_from_time,epoch_to_time)

	if parse_data:
		data_parser.parse_response_file(outputFolder + 'response.json')


