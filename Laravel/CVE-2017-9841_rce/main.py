import sys
import argparse
import time
from modules.executor import Executor
from modules.banner import Banner

parser = argparse.ArgumentParser(
        prog='tool', 
        formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=40)
)
parser.add_argument('--file', help='Input your target host lists',metavar='<hostnames.txt>',  required=False)
parser.add_argument('--range', help='Set range IP Eg.: 192.168.15.1,192.168.15.100',  metavar='<ip-start>,<ip-end>', required=False)
parser.add_argument('--single', help='Single hostname Eg.: mytarget.com', required=False)
arg_menu = parser.parse_args()

if not (arg_menu.file or arg_menu.range or arg_menu.single):
    exit(parser.print_help())

print(Banner.b())
time.sleep(2) # sleep j0k3r =P

HOSTNAME_FILE = arg_menu.file
RANGE_IP = arg_menu.range
SINGLE = arg_menu.single

if RANGE_IP:
    range_split = RANGE_IP.split(',')
    first_octet = range_split[0]
    second_octet = range_split[1]
    ex = Executor()
    ex.start_from_ip(first_octet, second_octet)

if HOSTNAME_FILE:
    list_domains = []
    ex = Executor()
    f = open(HOSTNAME_FILE, 'r')
    for line in f.readlines():
        l = line.strip('\n')
        list_domains.append(l)
    ex.start_urls(list_domains)
