#!/usr/bin/python3

import sys
import os
import re

# ADDRESS filter
def addr_filter(addr):
    # Omit some addresses
    ips = (re.search(r"^117.140.3", addr) != None) or \
          (re.search(r"^45.77.182.191", addr) != None)
    if ips:
        return False
    return True

# STATUS filter
def status_filter(status):
    if (status == '200'):
        return True
    return False

# USER-AGENT filter
def agent_filter(agent):
    # Exclude robots, spiders and crawlers
    if re.search(r"[Bb]ot", agent):
        return False
    if re.search(r"[Ss]pider", agent):
        return False
    if re.search(r"[Cc]rawler", agent):
        return False
    if re.search(r"[Ff]etcher", agent):
        return False
    # Empty user-agent
    if re.search(r"^\-", agent):
        return False
    # DNS
    if re.search(r"DNS", agent):
        return False

    return True

# If   STATUS != 200
#   or AGENT  == spider
#   or ADDR   == local
# return False
def easy_filter(info):
    status = info[3]
    if status_filter(status) == False:
        return False
    agent = info[4]
    if agent_filter(agent) == False:
        return False
    addr = info[0]
    if addr_filter(addr) == False:
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
    # http_user_agent
    agent = splits[5]
    # all info
    info = [addr, time, request, status, agent]

    return info


# Run the program:
# $ ./filter.py access.log > result.txt
#
if len(sys.argv) != 2:
    print("Usage: ./filter.py access.log")
    sys.exit()

fin = open(sys.argv[1], 'r')
#
# First traverse, find ips which load javascript
valid_user = set()
while True:
    line = fin.readline()
    if not line:
        break

    info = extract_info(line)
    if easy_filter(info) == False:
        continue

    addr = info[0]
    request = info[2]
    slices = request.split(' ')
    method = slices[0]
    url    = slices[1]
    # Method GET
    if method != 'GET':
        continue
    runjs = re.search(r"^\/js\/.*\.js", url) or \
            re.search(r"^\/lib\/.*\.js", url)
    if runjs:
        if addr not in valid_user:
            valid_user.add(addr)

#
# Second traverse, print REAL users
fin.seek(0)
while True:
    line = fin.readline()
    if not line:
        break

    info = extract_info(line)
    if easy_filter(info) == False:
        continue

    addr = info[0]
    request = info[2]
    slices = request.split(' ')
    method = slices[0]
    url    = slices[1]
    # Method GET
    if method != 'GET':
        continue
    if addr not in valid_user:
        continue
    # Interested pages
    pages = (re.search(r"^\/$", url) != None) or \
            (re.search(r"^\/20", url) != None) or \
            (re.search(r"^\/archives", url) != None) or \
            (re.search(r"^\/categories", url) != None) or \
            (re.search(r"^\/tags", url) != None) or \
            (re.search(r"^\/series", url) != None) or \
            (re.search(r"^\/about", url) != None) or \
            (re.search(r"^\/page", url) != None)
    if pages == False:
        continue

    print('{:16s}'.format(addr), end=' ')

    time = info[1]
    print('{:20s}'.format(time), end=' ')

    url = request.split(' ')[1]
    pos = url.find('?')
    if pos != -1:
        url = url[:pos]
    print(' ', url)

fin.close()
