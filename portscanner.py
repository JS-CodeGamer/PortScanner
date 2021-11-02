import socket
import os, sys
from datetime import datetime
import platform


# Check if ip is valid
def check_ip(ip):

  ip = ip.split(".")
  if len(ip) != 4:
      raise ValueError("Not valid IPv4 address.")

  for byte in ip:
    if int(byte) > 255:
      raise ValueError("Not valid IPv4 address.")

  return ip


# Parse input ips or hostnames into list of ips
def ip_parse(ip_str):

  try:
    if len(ip_str.split("/")) == 2:
      base_ip, subnet = tuple(ip_str.split("/"))
      subnet = int(subnet)
    elif len(ip_str.split("/")) == 1:
      base_ip, subnet = ip_str, 32
    bytes = check_ip(base_ip)
  except:
    try:
      return [socket.gethostbyname(base_ip)]
    except:
      raise ValueError("Not valid IPv4 address or domainname.")

  var_bytes = int(4 - subnet/8)
  for i in range(var_bytes)[::-1]:
    var_bit_len = min(32 - subnet, 8)
    subnet += var_bit_len
    if var_bit_len != 0:
      bytes[i] = [i in range(2**var_bit_len)]
  del subnet
  del var_bytes

  ips = []
  for b1 in bytes[0]:
    for b2 in bytes[1]:
      for b3 in bytes[2]:
         for b4 in bytes[3]:
            ips.append(f"{b1}.{b2}.{b3}.{b4}")

  return ips


# parse list of inputs into list of ports
def port_parse(ports):

  port_list = []
  if ports != [""]:

    for _input in ports:
      if len(_input.split("-")) == 1:
        port_list.append(int(_input.strip()))
      elif len(_input.split("-")) == 2:
        lbound = _input.split("-")[0].strip()
        ubound = _input.split("-")[1].strip()
        port_list.extend(range(lbound, ubound))

        del lbound
        del ubound

    return port_list

  else:
    return list(range(101))


# ping and check if an ip is online
def ping(ip):

  _os = platform.system()
  if (_os == "Windows"):
    ping_comm = "ping -n 1 "
  else:
    ping_comm = "ping -c 1 "

  ping_comm = ping_comm + ip
  response = os.popen(ping_comm)
  del ping_comm

  for line in response.readlines():
    if (line.count("0% loss") | line.count("0% packet loss")):
      return 0

  return 1


# scan if given ports are available for communication
def port_scan(ip, ports):

  open_ports = []

  for curr_port in ports:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socket.setdefaulttimeout(0.1)

    try:
      if curr_port in range(75, 85):
        conn = sock.connect_ex((ip, curr_port))
      conn = sock.connect_ex((ip, curr_port))
      socket.setdefaulttimeout(0.1)
      if conn == 0 :
        open_ports.append(curr_port)
      sock.close()

    except:
      pass

  return open_ports


t1 = datetime.now()
targets = [ip.strip() for ip in input("Enter host ips to be scanned: ").split(",")]

targets_ip = []
for target in targets:
   targets_ip.extend(ip_parse(target))
targets = targets_ip
del targets_ip

ports = [port.strip() for port in input("Enter range/list of ports to be scaned(default = 0-100): ").split(",")]
ports = port_parse(ports)

print('Starting scan.')
t1 = datetime.now()
print("Scanning in Progress...")
for target in targets:
  if ping(target) == 1:
    print ("\033[31m[-]", target, "\033[0mis offline.")
  elif ping(target) == 0:
    print ("\033[32m[+]", target, "\033[0mis online.")
    print("    Checking ports for conections...")
    open_ports = port_scan(target, ports)
    for port in open_ports:
      print("    Port {port} is open for connections.")


t2 = datetime.now()
time_t = t2 - t1
print ("Scanning completed in: ", time_t)
