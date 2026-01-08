import yaml

from scapy.all import *
import random


from wireshark_exercise_generator.exercises import flow_generator
from wireshark_exercise_generator.exercises.utils.solutions import solutions

if __name__ == "__main__":
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument("-f", "--flow-spec-file", type=str,
                            help="Path to exercise specification file",
                            default='examples/exercise_specification.yaml')
    arg_parser.add_argument("-o", "--out-filename", type=str,
                            help="Output filename_prefix", default='exercise' )
    arg_parser.add_argument("--seed", type=int,
                            help="Random seed overriding the seed in the flow specification file (if it exists)")
    args = arg_parser.parse_args()

    # Create the pcap_output directory if it doesn't exist yet:
    os.makedirs('out/pcap_output', exist_ok=True)
    os.makedirs('out/solutions', exist_ok=True)

    with open(args.flow_spec_file) as f:
        configurations = yaml.safe_load(f)

    #set seed
    seed = configurations['seed'] if 'seed' in configurations else args.seed
    random.seed(seed)

    # generate flows from templates
    all_packets = []
    for flow_id, flow_conf in enumerate(configurations['flow_list']):
        packets = flow_generator(flow_id, flow_conf['flow_template'])
        all_packets.extend(packets)

    # sort packets by time
    all_packets.sort(key=lambda p: getattr(p, "time", 0.0))


    wrpcap(f'out/pcap_output/{args.out_filename}.pcap', all_packets)
    solutions.save_on_file(f'out/solutions/{args.out_filename}_solutions.txt')

