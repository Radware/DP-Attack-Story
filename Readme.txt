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

