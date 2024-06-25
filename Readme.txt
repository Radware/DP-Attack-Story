#DP-Attack-Story

# Owners

	Prateek Vishwanath - prateek.vishwanath@radware.com
	Steve Harris - steven.harris@radware.com
	Egor Egorov - egore@radware.com

# About

	This script will pull DefensePro attack details through Vision/CyberController and from DP directly. It uses these details to generate a user friendly report.

# Prerequesites

	Requires the tabulate library. 'pip install tabulate' to download

# How to run

	1. Run the script 
		python csv-report.py
	2. Enter Vision/CC login credentials
	3. Enter DP IP 
	4. Enter start and end times
	5. View your report under .\Output\

# Version Control

v0.4.0 - Initial Dev Build
	Steve: I merged my clsVision module into Prateek's code.
