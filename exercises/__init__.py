import logging

from exercises.base_tcp_v3 import tcp_client_server_flow_generator
from exercises.http_exercise import http_flow_generator




_flow_template_to_generator = {'http_request_reply': http_flow_generator,
                               'tcp_client_server': tcp_client_server_flow_generator,
                               'ping': None}

def flow_generator(flow_gen_id, flow_template_params):
    # Check that the flow generator exists
    flow_type = flow_template_params['flow_generator'].lower()
    if flow_type not in _flow_template_to_generator:
        logging.error(f"Unknown flow_generator: {flow_template_params['flow_generator']}")
        raise ValueError(f"Unknown flow_generator: {flow_template_params['flow_generator']}")


    #flow_type = flow_template_params['flow_generator'].lower()
    flows_to_generate = flow_template_params.get('flows_to_generate', 1)
    flow_tag = flow_template_params.get('tag', f'{flow_type}-{flow_gen_id}')

    if flows_to_generate > 1:
        # remove client and server ports from flow parameters
        # they will be added automatically by the generator function
        flow_template_params['flow_parameters'].pop('client_port')
        flow_template_params['flow_parameters'].pop('server_port')


    # generate flows
    packet_list = []
    for i in range(flows_to_generate):
        # copy to avoid modifying the original (Note
        # that it is a shallow copy, values must be immutable)
        flow_params = flow_template_params['flow_parameters'].copy()
        flow_packets = _flow_template_to_generator[flow_type](flow_params)   # key error should not happen
        packet_list.extend(flow_packets)
        print(f"Generated flow {flow_tag}-{i} with {len(flow_packets)} packets")

    return packet_list
