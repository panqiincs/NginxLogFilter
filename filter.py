#!/usr/bin/python3

import sys
import os
import re

# ADDRESS filter
def addr_filter(addr):
    # omit some addresses
    if re.search(r"^117.140.3", addr):
        return False
    return True

# REQUEST filter
def request_filter(request):
    slices = request.split(' ')
    method = slices[0]
    url    = slices[1]

    if method != 'GET':
        return False
    if re.search(r"^\/css", url):
        return False
    if re.search(r"^\/images", url):
        return False
    if re.search(r"^\/js", url):
        return False
    if re.search(r"^\/lib", url):
        return False
    if re.search(r"^\/atom.xml", url):
        return False
    if re.search(r"^\/robots.txt", url):
        return False

    return True

# STATUS filter
def status_filter(status):
    if (status == '200'):
        return True
    return False

# USER-AGENT filter
def agent_filter(agent):
    if re.search(r"[Bb]ot", agent):
        return False
    if re.search(r"[Ss]pider", agent):
        return False
    if re.search(r"Embedly", agent):
        return False
    return True

# EXTRACT information from a record
def extract_info(line):
    splits = line.split('"')
    # remote_addr
    addr = splits[0].split(' ')[0]
    # time_local
    time = splits[0].split(' ')[3][1:]
    # request
    request = splits[1]
    # status
    status = splits[2].lstrip().split(' ')[0]
    # bytes_sent
    # bytes = splits[2].lstrip().split(' ')[1]
    # http_referer
    # referer = splits[3]
    # user_agent
    agent = splits[5]

    info = [addr, time, request, status, agent]
    return info



# Run the program:
# $ ./filter.py access.log > result.txt
#
if len(sys.argv) != 2:
    print("Usage: ./filter.py access.log")
    sys.exit()

fh = open(sys.argv[1], 'r')

while True:
    line = fh.readline()
    if not line:
        break
    info = extract_info(line)

    status = info[3]
    if status_filter(status) == False:
        continue
    request = info[2]
    if request_filter(request) == False:
        continue
    agent = info[4]
    if agent_filter(agent) == False:
        continue
    addr = info[0]
    if addr_filter(addr) == False:
        continue

    # Only show visitor's ip and target page
    print(addr, request.split(' ')[1])

fh.close()
