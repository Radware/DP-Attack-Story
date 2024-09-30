#DP-Attack-Story

# Owners

	Prateek Vishwanath - prateek.vishwanath@radware.com
	Steve Harris - steven.harris@radware.com
	Egor Egorov - egore@radware.com

# About

	This script will pull DefensePro attack details through Vision/CyberController and from DP directly. It uses these details to generate a user-friendly report.

# Prerequisites

	This script requires the tabulate, requests, paramiko, and pysftp libraries. 'pip install tabulate requests paramiko pysftp' to download them.
	You will need to know your Vision/CC username, password and root password. You will need to know the username and password for every defensepro you are pulling data from.
	DefensePro version at least 8.32
	DefensePro must have BDOS attack lifecycle logging enabled: 'system internal security bdos attack-log-status set enable'. 'Unknown command' means your DefensePro must be upgraded.

# How to run

	1. Run the script 
		python main.py
	2. Enter start and end times
	3. Enter Vision/CC login credentials
	4. (optional - press enter to skip) Select target DPs 
	5. (optional - press enter to skip) Enter a comma separated list of policies
	6. Input individual DefensePro username/password when prompted. 
	7. View your report under .\Output\

# Version Control
	v0.10.0 - 30 September 2024 (Steve)
		Initial concept for a header.
	v0.9.8 - 26 September 2024 (Steve)
		Changed time format for first two graphs from date to datetime. onHover popup will now display the time as well as the date.
	v0.9.7 - 26 September 2024 (Prateek)
		Bug fix for Pagenation during data collection
		Added Timezone (UTC) in attack report tables
		Modified wordings for option to manually input timeframes option
	v0.9.6.1
		adding run.sh to run from container
	v0.9.6 - 18 September 2024 (Prateek)
		Bug fix for LOW footprint strictness time calucation
		Seperated functions for creating topN attacks (in preparation for this is for sample data collection)
	v0.9.5 - 12 September 2024 (Prateek)
		Added enhancements to print BDoS lifecycle parsing for burst attacks accurately
		Added functionality to clear output folder before running the script
		Renamed "Syslog ID" in the output table as "BDOS Lifecycle log attack ID"
	v0.9.4 - 4 September 2024 (Prateek)
		Improved attack lifecycle calucation logic - transition between blocking and non-blocking states
		Cleaned unused libraries - mainly tabulate
	v0.9.3 - 4 September 2024 (Steve)
		Improved display of graph timestamps.
		We will now sort graph data received from vision prior to displaying it.
		Set option interpolateNulls: true for 'All Attacks' graph to account for some datasets containing null values when merged.
		Moved Vision log file to .\Output\ folder
		Increased verbosity of vision server logging.
	v0.9.2 - 28 August 2024 (Prateek)
		Added functionality to process different attack-id to syslog-id conversion
		Added AttackID to the HTML report
	v0.9.1 - 22 August 2024 (Steve)
		Will no longer include DefensePros in a 'FAILED' state in the list of available devices.
		Fixed potential issue where DP selection input is accepted when the user inputs a mix of valid and invalid IPs.
		Fixed device_ips "TypeError: 'int' object is not iterable"
	v0.9.0 - 21 August 2024 (Steve)
		Graph data now saves to a file.
		Data for combined graphs will now be filtered according to selected DPs and policies.
		Added error handling when entering a time range. Invalid entries will now prompt for a correction.
		Script will pull DefensePro CLI credentials from Vision instead of prompting user.
	v0.8.6 - 21 August 2024 (Prateek)
		added summary that displays acttack vector for top n attacks
		added summary that displays x attacks are over "y" gbps
	v0.8.5 - 21 August 2024 (Steve)
		Added more robust error handling and reporting to graph operations. 
		Renamed output html file from graph.html to DP-Attack-Story_Report.html
	v0.8.4 - 21 August 2024 (Prateek)
		Added logic to ignore EAAF events.
	v0.8.3 - 15 August 2024 (Steve)
		Combined Graph: Added Attack Name to dataset names
		Combined Graph: Selecting a Both/Bps/Pps will now check/uncheck the appropriate boxes.
		Combined Graph: Data Points are now rounded to the nearest 15 seconds.
		Combined Graph: Ensured that Google Charts will always select a solid line of a unique color for each line when there are many datasets.
	v0.8.1 - 15 August 2024 (Steve)
		Fixed an error where graph_parser.py was overwritten.
	v0.8.0 - 15 August 2024 (Steve)
		Added 'Past X hours' option to time period selection.
		Changed deviceIP selection input so blank entry selects all instead of having to type 'All'
		Added graph for each attack ID.
		Added a graph that combines all Attack IDs with checkboxes to select individual attacks. 
		Updated launch.json for easier troubleshooting
	v0.7.0 - (Prateek)
	v0.6.0 - 8 July 2024 (Steve)
		Added graph functionality
		Added error handling for missing libraries
	v0.5.0 - 26 June 2024 - Restructure code (Egor)
		Added main.py
		Added collector.py
		Added parser.py (need to qa, do not have data to test)
	v0.4.1 - 26 June 2024 (Steve)
		Output has been moved to the folder ./Output/
		Removed commented lines after reviewing with the team.
	v0.4.0 - 25 June 2024 - Initial Dev Build (Steve)
		Merged my clsVision module into Prateek's code.

