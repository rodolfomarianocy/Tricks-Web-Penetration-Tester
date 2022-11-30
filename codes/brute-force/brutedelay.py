import requests, argparse, sys, threading, time
from argparse import RawTextHelpFormatter

def msg():
    banner ="""
___.                 __             .___     .__                
\_ |_________ __ ___/  |_  ____   __| _/____ |  | _____  ___.__.
 | __ \_  __ \  |  \   __\/ __ \ / __ |/ __ \|  | \__  \<   |  |
 | \_\ \  | \/  |  /|  | \  ___// /_/ \  ___/|  |__/ __ \\___   |
 |___  /__|  |____/ |__|  \___  >____ |\___  >____(____  / ____|
     \/                       \/     \/    \/          \/\/     
    """
    return print(banner)
    
def main(url, filetxt, delay, user_agent):
    attempt = 0
    file = open(filetxt, 'r')
    lines = file.readlines()
    msg()
    print(f"\nurl: {url}\nfile: {filetxt}\ndelay: {delay}\nuser-Agent: {user_agent}\n")
    for line in lines:
        attempt += 1
        endpoint = url+line
        print("Request Number ["+str(attempt)+"] in "+endpoint,end="")
        
        response = requests.get(endpoint, headers={"User-Agent":f"{user_agent}"})
        if (response.status_code == 200):
            print(response.text)
        else:
            print(response.status_code,(response.headers['Server']))
        time.sleep(delay)

args = None
parser = argparse.ArgumentParser(formatter_class=RawTextHelpFormatter, usage="python brutedelay.py -u http://example.com/api/v1/user= -f users.txt -a Mozilla/5.0 -d 30")
parser.add_argument('-u','--url', dest='url', action='store', type=str, help='insert endpoint', required=True)
parser.add_argument('-a','--user_agent', dest='user_agent', action='store', type=str, help='insert User-Agent', required=True)
parser.add_argument('-d','--delay', dest='delay', action='store', type=int, help='insert delay in seconds', required=True)
parser.add_argument('-f','--file', dest='filetxt', action='store', type=str, help='insert file in seconds', required=True)
args=parser.parse_args()
main(args.url, args.filetxt, args.delay, args.user_agent)