#!/usr/bin/python3

import sys
import os
import re

# ADDRESS filter
def addr_filter(addr):
    # omit some addresses
    ips = (re.search(r"^117.140.3", addr) != None) or \
          (re.search(r"^45.77.182.191", addr) != None)
    if ips:
        return False
    return True

# REQUEST filter
def request_filter(request):
    slices = request.split(' ')
    method = slices[0]
    url    = slices[1]
    # Method GET
    if method != 'GET':
        return False
    # Interested pages
    pages = (re.search(r"^\/$", url) != None) or \
            (re.search(r"^\/20", url) != None) or \
            (re.search(r"^\/archives", url) != None) or \
            (re.search(r"^\/categories", url) != None) or \
            (re.search(r"^\/tags", url) != None) or \
            (re.search(r"^\/series", url) != None) or \
            (re.search(r"^\/about", url) != None) or \
            (re.search(r"^\/page", url) != None)
    if pages:
        return True
    return False

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
    # Other conditions
    if re.search(r"Embedly", agent):
        return False
    if re.search(r"DNS", agent):
        return False
    if re.search(r"ZhihuDaily", agent):
        return False
    if re.search(r"Disqus", agent):
        return False
    if re.search(r"Go-http-client", agent):
        return False
    if re.search(r"[Gg]oogle", agent):
        return False
    if re.search(r"[Cc]loudflare", agent):
        return False
    if re.search(r"python-requests", agent):
        return False
    if re.search(r"zgrab", agent):
        return False
    if re.search(r"Feedly", agent):
        return False
    if re.search(r"Detection", agent):
        return False
    if re.search(r"[Ss]crapy", agent):
        return False
    if re.search(r"[Ww]get", agent):
        return False
    if re.search(r"evc-batch", agent):
        return False
    if re.search(r"[Rr]uby", agent):
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
    # body_bytes_sent
    # bytes = splits[2].lstrip().split(' ')[1]
    # http_referer
    # referer = splits[3]
    # http_user_agent
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

valid_user = set()

#
# First traverse, find ips which load javascript
while True:
    line = fh.readline()
    if not line:
        break
    info = extract_info(line)

    status = info[3]
    if status_filter(status) == False:
        continue
    agent = info[4]
    if agent_filter(agent) == False:
        continue
    addr = info[0]
    if addr_filter(addr) == False:
        continue
    request = info[2]
    slices = request.split(' ')
    method = slices[0]
    url    = slices[1]
    # Method GET
    if method != 'GET':
        continue
    if re.search(r"^\/js", url):
        if addr not in valid_user:
            valid_user.add(addr)

fh.close()


fh = open(sys.argv[1], 'r')
#
# Second traverse, print REAL users
while True:
    line = fh.readline()
    if not line:
        break
    info = extract_info(line)

    status = info[3]
    if status_filter(status) == False:
        continue
    agent = info[4]
    if agent_filter(agent) == False:
        continue
    addr = info[0]
    if addr_filter(addr) == False:
        continue

    request = info[2]
    slices = request.split(' ')
    method = slices[0]
    url    = slices[1]
    # Method GET
    if method != 'GET':
        continue
    if addr not in valid_user:
        continue
    #print(addr)
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

    time = info[1]
    # print IP
    print('{:16s}'.format(addr), end=' ')
    # print TIME
    print('{:20s}'.format(time), end=' ')
    # print URL
    url = request.split(' ')[1]
    pos = url.find('?')
    if pos != -1:
        url = url[:pos]
    print(' ', url)
    #print(' ', url, end='         ')
    #print(agent)

fh.close()
