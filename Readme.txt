#DP-Attack-Story

# Owners

	Prateek Vishwanath - prateek.vishwanath@radware.com
	Steve Harris - steven.harris@radware.com
	Egor Egorov - egore@radware.com

# About

	This script will pull DefensePro attack details through Vision/CyberController and from DP directly. It uses these details to generate a user friendly report.

# Prerequesites

	Requires the tabulate library. 'pip install tabulate' to download
	Requires the requests library. 'pip install requests' to download

# How to run

	1. Run the script 
		python csv-report.py
	2. Enter Vision/CC login credentials
	3. Enter DP IP 
	4. Enter start and end times
	5. View your report under .\Output\

# Version Control
v0.8.3 - 15 August 2024 (Steve)
	Combined Graph: Added Attack Name to dataset names
	Combined Graph: Selecting a Both/Bps/Pps will now check/uncheck the appropriate boxes.
	Combined Graph: Datapoints are now be rounded to the nearest 15 seconds.
	Combined Graph: Ensured that Google Charts will always select a solid line of a unique color for each line when there are many datasets.
v0.8.1 - 15 August 2024 (Steve)
	Fixed an error where graph_parser.py was overwritten.
v0.8.0 - 15 August 2024 (Steve)
	Added 'Past X hours' option to time period selection.
	Changed deviceIP selection input so blank entry selects all instead of having to type 'All'
	Added graph for each attack ID.
	Added a graph that combines all Attack IDs with checkboxes to select individual attacks. 
	Updated launch.json for easier troubleshooting
v0.7.0 - ? (Prateek)
v0.6.0 - 8 July 2024 (Steve)
	Added graph functionality
	Added error handling for missing libraries

v0.5.0 - 26 June 2024 - Restructure code (Egor)
	Added main.py
	Added collector.py
	Added parser.py (need to qa, do not have data to test)

v0.4.1 - 26 June 2024 (Steve)
	Output has been moved to the folder ./Output/
	Removed commented lines after reviewing with team.

v0.4.0 - 25 June 2024 - Initial Dev Build (Steve)
	Merged my clsVision module into Prateek's code.



