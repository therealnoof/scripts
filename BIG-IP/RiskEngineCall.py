#!/usr/bin/env python

### F5 Networks: Author: Arnulfo Hernandez - Solutions Engineer
### This is a script demostrating an API call to a risk engine
### and then parsing the payload and looking for a base level security match
### if theres a match, the script logs into the BIG-IP and kills all APM sessions
### This could supplement IAP on APM when dealing with VDI
### VDI does not fire the HTTP Connector so we cant utilize the per-request flow protections


import requests
import json
from f5.bigip import ManagementRoot

### Run a call to our Risk Engine API server and place the payload into a variable
response = requests.get("http://x.x.x.x:5000/api/people")

### Parse the variable JSON payload and pull the Hanscom base level status
### Place base level status in variable deltaLevel
apiresults = response.json()
deltaLevel = apiresults[0]["fname"]
lockDown = "Delta"

### Logic to determine if base level status "Delta" is a match
### if a match occurs then send a call to APM to terminate all user sessions
print("The current FPCON level at Hanscom is: " + deltaLevel)

if deltaLevel == lockDown:
    mgmt = ManagementRoot("x.x.x.x",'admin','******')
    x = mgmt.tm.util.bash.exec_cmd('run', utilCmdArgs='-c "/usr/bin/sessiondump --delete all"')
    print("FPCON level is Delta, terminating all sessions.")
    print(x.commandResult)
    


