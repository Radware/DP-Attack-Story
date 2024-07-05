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

v0.5.0 - 26 June 2024 - Restructure code (Egor)
	Added main.py
	Added collector.py
	Added parser.py (need to qa, do not have data to test)

v0.4.1 - 26 June 2024 
	Output has been moved to the folder ./Output/
	Removed commented lines after reviewing with team.

v0.4.0 - 25 June 2024 - Initial Dev Build
	Steve: I merged my clsVision module into Prateek's code.



