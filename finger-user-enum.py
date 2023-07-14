#!/usr/bin/env python3
import socket
import select
import argparse
import time
import os
import sys
import multiprocessing

VERSION = "1.0"
debug = False
verbose = False
max_procs = 5
finger_port = 79
usernames = []
hosts = []
recursive_flag = True
relayserver = None
query_timeout = 5
start_time = time.time()
end_time = None
kill_child_string = "\x00"


def send_data(sock, data):
    sock.send(data.encode())


def receive_data(sock):
    return sock.recv(10000).decode()


def handle_child(line):
    try:
        host, username = line.split('\t')
    except ValueError:
        return

    if line == kill_child_string:
        return

    try:
        connect_host = relayserver if relayserver else host
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(query_timeout)
        s.connect((connect_host, finger_port))
        if relayserver:
            send_data(s, f"{username}@{host}\r\n")
        else:
            send_data(s, f"{username}\r\n")
        response = receive_data(s)
        s.close()
    except socket.timeout:
        print(f"[Child {os.getpid()}] Timeout for username {username} on host {host}")
        return
    except (socket.error, socket.herror, socket.gaierror) as e:
        print(f"[Child {os.getpid()}] Error connecting to {host}:{finger_port}: {e}")
        return

    trace = f"[Child {os.getpid()}] {username}@{host}: "
    if response and response.strip() != 'f':
        if "Login       Name" in response:
            lines = response.splitlines()
            for i, line in enumerate(lines):
                if username in line:
                    username_info = line.replace("\r", "").replace("\n", "")
                    print(trace + username_info)
                    break
            else:
                print(trace + "<no such user>")
        else:
            response = response.replace("\r", "").replace("\n", "")
            print(trace + response)
    else:
        print(trace + "<no such user>")


def generate_queries():
    for username in usernames:
        for host in hosts:
            yield f"{host}\t{username}"


def main():
    global debug, verbose, finger_port, recursive_flag, relayserver, query_timeout
    global max_procs, usernames, hosts

    parser = argparse.ArgumentParser(description="finger-user-enum - Brute Force Username via Finger Service")
    parser.add_argument("-m", type=int, default=max_procs, help="Maximum number of resolver processes (default: %(default)s)")
    parser.add_argument("-u", help="Check if user exists on remote system")
    parser.add_argument("-U", help="File of usernames to check via finger service")
    parser.add_argument("-t", help="Server host running finger service")
    parser.add_argument("-T", help="File of hostnames running the finger service")
    parser.add_argument("-r", help="Relay. Intermediate server which allows relaying of finger requests.")
    parser.add_argument("-p", type=int, default=finger_port, help="TCP port on which finger service runs (default: %(default)s)")
    parser.add_argument("-d", action="store_true", help="Debugging output")
    parser.add_argument("-s", type=int, default=query_timeout, help="Wait a maximum of n seconds for reply (default: %(default)s)")
    parser.add_argument("-v", action="store_true", help="Verbose")
    args = parser.parse_args()

    debug = args.d
    verbose = args.v
    max_procs = args.m
    finger_port = args.p
    relayserver = args.r
    query_timeout = args.s

    if args.u:
        usernames.append(args.u)

    if args.U:
        with open(args.U, 'r') as file:
            usernames.extend([line.strip() for line in file])

    if args.t:
        hosts.append(args.t)

    if args.T:
        with open(args.T, 'r') as file:
            hosts.extend([line.strip() for line in file])

    global start_time, end_time
    start_time = time.time()

    print(f"Starting finger-user-enum v{VERSION}")
    print()
    print(" ----------------------------------------------------------")
    print("|                   Scan Information                       |")
    print(" ----------------------------------------------------------")
    print()
    print(f"Worker Processes ......... {max_procs}")
    print(f"Targets file ............. {args.T}" if args.T else "")
    print(f"Usernames file ........... {args.U}" if args.U else "")
    print(f"Target count ............. {len(hosts)}" if hosts else "")
    print(f"Username count ........... {len(usernames)}" if usernames else "")
    print(f"Target TCP port .......... {finger_port}")
    print(f"Query timeout ............ {query_timeout} secs")
    print(f"Relay Server ............. {relayserver}" if relayserver else "Relay Server ............. Not used")
    print()
    print(f"######## Scan started at {time.ctime()} #########")

    pool = multiprocessing.Pool(max_procs)
    pool.map(handle_child, generate_queries())

    print(f"######## Scan completed at {time.ctime()} #########")
    print(f"{len(hosts) * len(usernames)} queries in {time.time() - start_time:.1f} seconds "
          f"({(len(hosts) * len(usernames)) / (time.time() - start_time):.1f} queries / sec)")


if __name__ == "__main__":
    main()
