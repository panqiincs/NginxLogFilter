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

# EXTRACT information from a record
def extract_info(line):
    splits = line.split('"')
    addr = splits[0].split(' ')[0]               # remote_addr
    time = splits[0].split(' ')[3][1:]           # time_local
    request = splits[1]                          # request
    status = splits[2].lstrip().split(' ')[0]    # status
    agent = splits[5]                            # http_user_agent
    info = [addr, time, request, status, agent]  # all info
    return info

def get_record_list():
    fin = open(sys.argv[1], 'r')
    res = list()
    while True:
        line = fin.readline()
        if not line:
            break
        info = extract_info(line)

        status = info[3]
        if status != '200':
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
        if method != 'GET':
            continue
        url = slices[1]
        pos = url.find('?')
        if pos != -1:
            url = url[:pos]

        time = info[1]

        item = (addr, time, url)
        res.append(item)

    fin.close()
    return res


def run():
    if len(sys.argv) != 2:
        print("Usage: ./filter.py access.log")
        sys.exit()

    rlist = get_record_list()
    # First traverse, find ips which load javascript
    valid_user = set()
    for i in range(len(rlist)):
        url = rlist[i][2]
        addr = rlist[i][0]
        runjs = re.search(r"^\/js\/.*\.js", url) or \
                re.search(r"^\/lib\/.*\.js", url)
        if runjs:
            if addr not in valid_user:
                valid_user.add(addr)

    for i in range(len(rlist)):
        addr = rlist[i][0]
        if addr not in valid_user:
            continue
        url = rlist[i][2]
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
        time = rlist[i][1]
        print('{:20s}'.format(time), end=' ')
        print(' ', url)

if __name__ == "__main__":
    run()
