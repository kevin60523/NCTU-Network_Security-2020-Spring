from os import listdir
from os.path import isfile, join
import gc

import pandas as pd
import numpy as np

from collections import Counter
import sys

attack_sceniro = ['', '', '', '', '']
folder_path = sys.argv[1]

json_files = [join(folder_path, f) for f in listdir(folder_path) if isfile(join(folder_path, f))]

file_len = np.zeros(len(json_files))
rdp_port_count = np.zeros(len(json_files))
dns_port_count = np.zeros(len(json_files))
total_port_count = np.zeros(len(json_files))
total_ip_count = np.zeros(len(json_files))

for file_count in range(len(json_files)):
    df = pd.read_json(json_files[file_count], lines=True)
    gc.collect()
    port_count = Counter()
    ip_count = Counter()
    
    for line_count in range(len(df)):
        # dns port
        try:
            if df['_source'][line_count]['destination']['port'] == 22:  
                dns_port_count[file_count] += 1                      
        except Exception:
            pass
        # rdp port
        try:
            if df['_source'][line_count]['destination']['port'] == 3389:  
                rdp_port_count[file_count] += 1                      
        except Exception:
            pass
        # all ip
        try:
            ip_count[df['_source'][line_count]['destination']['ip']] += 1                      
        except Exception:
            pass

        # all port
        try:
            port_count[df['_source'][line_count]['destination']['port']] += 1                      
        except Exception:
            pass
    
    total_port_count[file_count] = len(port_count)
    total_ip_count[file_count] = len(ip_count)
    file_len[file_count] = len(df)

    df = pd.DataFrame(None)
    gc.collect()

rdp_port_count /= file_len
dns_port_count /= file_len
total_port_count /= file_len
total_ip_count /= file_len

rdp_idx = np.argmax(rdp_port_count)
dns_port_count[rdp_idx] = 0
total_port_count[rdp_idx] = 0
total_ip_count[rdp_idx] = 0
ddos_idx = np.argmax(dns_port_count)
total_port_count[ddos_idx] = 0
total_ip_count[ddos_idx] = 0
port_idx = np.argmax(total_port_count)
total_ip_count[port_idx] = 0
ip_idx = np.argmax(total_ip_count)

attack_sceniro[rdp_idx] = 'RDP Brute-Force'
attack_sceniro[ddos_idx] = 'DDos'
attack_sceniro[port_idx ] = 'Port Scan'
attack_sceniro[ip_idx] = 'IP Scan'

for i in range(len(json_files)):
    if(attack_sceniro[i] == ''):
        attack_sceniro[i] = 'C&C'
    print('{}: {}'.format(json_files[i].split('/')[-1], attack_sceniro[i]))