import yaml

from scapy.all import *
import random


from exercises import flow_generator
from exercises.utils.solutions import solutions

if __name__ == "__main__":
    # Create the pcap_output directory if it doesn't exist yet:
    os.makedirs('pcap_output', exist_ok=True)
    os.makedirs('solutions', exist_ok=True)

    with open('exercise_specification.yaml') as f:
        configurations = yaml.safe_load(f)

    #set seed
    random.seed(configurations['seed'])
    # generate flows from templates
    all_packets = []
    for flow_id, flow_conf in enumerate(configurations['flow_list']):
        packets = flow_generator(flow_id, flow_conf['flow_template'])
        all_packets.extend(packets)

    # sort packets by time
    all_packets.sort(key=lambda p: getattr(p, "time", 0.0))


    wrpcap('pcap_output/exercise.pcap', all_packets)
    solutions.save_on_file('solutions/exercise_solutions.txt')

