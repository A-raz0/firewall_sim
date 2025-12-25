# Firewall Simulator

My first security based project, a firewall simulation. Built using python.
This project simulated how a firewall decides to allow or deny network traffic.
Using random, the program generates random packets which represent network requests, it then checks the request based on the rules provided and decides whether to allow or deny the request.
Simulates 100 random packets and prints each decision for each individual packet, then prints out a summary of the 100 decisions made.

## Features 
Generates random packets with:
Source IP address (e.g., '192.168.1.7')
Protocol ('TCP or 'UDP')
Destination port (random 1–100)
Packet size (random 20–1500 bytes)
Checks packets against a rule list top to bottom
Uses a default policy (allow) if no rules match
Tracks how many packets were allowed vs denied
Tracks which rules matched most often (hit counts) 

## Run
In terminal run:
python3 firewall.py
