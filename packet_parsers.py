# Parse Ethernet header
def parse_ethernet_header(hex_data):
    dest_mac = ':'.join(hex_data[i:i+2] for i in range(0, 12, 2))
    source_mac = ':'.join(hex_data[i:i+2] for i in range(12, 24, 2))
    ether_type = hex_data[24:28]

    print(f"Ethernet Header:")
    print(f"  {'Destination MAC:':<25} {hex_data[0:12]:<20} | {dest_mac}")
    print(f"  {'Source MAC:':<25} {hex_data[12:24]:<20} | {source_mac}")
    print(f"  {'EtherType:':<25} {ether_type:<20} | {int(ether_type, 16)}")

    payload = hex_data[28:]

    # Route payload based on EtherType
    if ether_type == "0806":  # ARP
        ether_type, payload = parse_arp_header(payload)
    elif ether_type == "0800": # IPv4
        ether_type, payload = parse_ipv4_header(payload)
    elif ether_type == "86DD": #IPv6
        ether_type, payload = parse_ipv6_header(payload)
    else:
        print(f"  {'Unknown EtherType:':<25} {ether_type:<20} | {int(ether_type, 16)}")
        print("  No parser available for this EtherType.")

    return ether_type, payload


# Parse ARP header
def parse_arp_header(hex_data):
    hardware_type = int(hex_data[:4], 16)

    print(f"ARP Header:")
    print(f"  {'Hardware Type:':<25} {hex_data[:4]:<20} | {hardware_type}")


# Create a IPv4 Address from Hex
def convert_hex_to_ipv4(hex_data):
    decimal_value = int(hex_data, 16)

    octet1 = (decimal_value >> 24) & 255
    octet2 = (decimal_value >> 16) & 255
    octet3 = (decimal_value >> 8) & 255
    octet4 = decimal_value & 255

    return f"{octet1}.{octet2}.{octet3}.{octet4}"


# Create a IPv6 Address from Hex
def convert_hex_to_ipv6(hex_data):
    return ":".join(hex_data[i:i+4] for i in range(0, 32, 4))


# Parse IPv4 header
def parse_ipv4_header(hex_data):
    version_hex = hex_data[0:1]
    ihl_hex = hex_data[1:2]
    type_of_service_hex = hex_data[2:4]
    total_length_hex = hex_data[4:8]
    identification_hex = hex_data[8:12]
    flags_fragment_offset_hex = hex_data[12:16]
    ttl_hex = hex_data[16:18]
    protocol_hex = hex_data[18:20]
    checksum_hex = hex_data[20:24]
    source_ip_hex = hex_data[24:32]
    destination_ip_hex = hex_data[32:40]
    
    version = int(version_hex, 16)
    ihl = int(ihl_hex, 16)
    header_length_bytes = ihl * 4
    header_length_hex = header_length_bytes * 2
    
    type_of_service = int(type_of_service_hex, 16)
    total_length = int(total_length_hex, 16)
    identification = int(identification_hex, 16)
    
    fl_fr_off = int(flags_fragment_offset_hex, 16)
    flag = (fl_fr_off >> 13) & 0x7
    reserved = (flag >> 2) & 0x1
    df = (flag >> 1) & 0x1
    mf = flag & 0x1
    fragment_offset = fl_fr_off & 0x1FFF
    
    ttl = int(ttl_hex, 16)
    protocol = int(protocol_hex, 16)
    
    source_ip = convert_hex_to_ipv4(source_ip_hex)
    destin_ip = convert_hex_to_ipv4(destination_ip_hex)
    
    # print information
    print(f"IPv4 Header:")
    print(f"  {'Version:':<25} {version_hex:<20} | {version}")
    print(f"  {'Header Length:':<25} {ihl_hex:<20} | {ihl}")
    print(f"  {'Total Length:':<25} {total_length_hex:<20} | {total_length}")
    print(f"  {'Flags & Frag Offset:':<25} {flags_fragment_offset_hex:<20} | {fl_fr_off}")
    print(f"    {'Reserved:':<5} {reserved}")
    print(f"    {'DF (Do not Fragment):':<5} {df}")
    print(f"    {'MF (More Fragments):':<5} {mf}")
    print(f"    {'Fragment Offset:':<5} {hex(fragment_offset)} | {fragment_offset}")
    print(f"  {'Protocol:':<25} {protocol_hex:<20} | {protocol}")
    print(f"  {'Source IP::':<25} {source_ip_hex:<20} | {source_ip}")
    print(f"  {'Destination IP:':<25} {destination_ip_hex:<20} | {destin_ip}")
    
    payload = hex_data[header_length_hex:]
    
    return protocol, payload
    

def parse_ipv6_header(hex_data):
    version_hex = hex_data[0:1]
    traffic_hex = hex_data[1:3]
    flow_hex = hex_data[3:8]
    payload_length_hex = hex_data[8:12]
    next_header_hex = hex_data[12:14]
    hop_limit_hex = hex_data[14:16]
    source_ip_hex = hex_data[16:48]
    destination_ip_hex = hex_data[48:80]

    # version_traffic_flow = int(version_traffic_flow_hex, 16)
    version = int(version_hex, 16)
    traffic_class = int(traffic_hex, 16)
    flow_labal = int(flow_hex, 16)

    payload_length = int(payload_length_hex, 16)
    next_header = int(next_header_hex, 16) 
    hop_limit = int(hop_limit_hex, 16)

    source_ip = convert_hex_to_ipv6(source_ip_hex)
    destin_ip = convert_hex_to_ipv6(destination_ip_hex)
    
    # print information
    print(f"IPv6 Header:")
    print(f"  {'Version:':<25} {version_hex:<20} | {version}")
    print(f"  {'Header Length:':<25} {traffic_hex:<20} | {traffic_class}")
    print(f"  {'Flow Label:':<25} {flow_hex:<20} | {flow_labal}")
    print(f"  {'Payload Length:':<25} {payload_length_hex:<20} | {payload_length}")
    print(f"  {'Next Header:':<25} {next_header_hex:<20} | {next_header}")
    print(f"  {'Hop Limit:':<25} {hop_limit_hex:<20} | {hop_limit}")
    print(f"  {'Source IP::':<25} {source_ip_hex:<20} | {source_ip}")
    print(f"  {'Destination IP:':<25} {destination_ip_hex:<20} | {destin_ip}")
    
    payload = hex_data[80:]
    
    return next_header, payload

def parse_icmp_header(hex_data):
    type_hex = hex_data[0:2]
    code_hex = hex_data[2:4]
    checksum_hex = hex_data[4:8]
    rest_of_header_hex = hex_data[8:]
    
    type_header = int(type_hex, 16)
    code = int(code_hex, 16)
    checksum = int(checksum_hex, 16)
    
    # print information
    print(f"ICMP Header:")
    print(f"  {'Type:':<25} {type_hex:<20} | {type_header}")
    print(f"  {'Code:':<25} {code_hex:<20} | {code}")
    print(f"  {'Checksum:':<25} {checksum_hex:<20} | {checksum}")
    print(f"  {'Payload:':<25} {rest_of_header_hex:<20}")
    
    
def parse_icmpv6_header(hex_data):
    type_hex = hex_data[0:2]
    code_hex = hex_data[2:4]
    checksum_hex = hex_data[4:8]
    rest_of_header_hex = hex_data[8:]
    
    type_header = int(type_hex, 16)
    code = int(code_hex, 16)
    checksum = int(checksum_hex, 16)
    
    # print information
    print(f"ICMPv6 Header:")
    print(f"  {'Type:':<25} {type_hex:<20} | {type_header}")
    print(f"  {'Code:':<25} {code_hex:<20} | {code}")
    print(f"  {'Checksum:':<25} {checksum_hex:<20} | {checksum}")
    print(f"  {'Payload:':<25} {rest_of_header_hex:<20}")
    

def parse_tcp_header(hex_data):
    source_port_hex = hex_data[0:4]
    destination_port_hex = hex_data[4:8]
    seq_number_hex = hex_data[8:16]
    ack_number_hex = hex_data[16:24]
    doff_res_flag_hex = hex_data[24:28]
    window_size_hex = hex_data[28:32]
    checksum_hex = hex_data[32:36]
    urgent_pointer_hex = hex_data[36:40]

    source_port = int(source_port_hex, 16)
    destin_port = int(destination_port_hex, 16)
    seq_number = int(seq_number_hex, 16)
    ack_number = int(ack_number_hex, 16)
    
    doff_res_flag = int(doff_res_flag_hex, 16)
    data_offset = (doff_res_flag >> 12) & 0xF
    data_offset_bytes = data_offset * 4
    res_hex = doff_res_flag_hex[1:2]
    res = (doff_res_flag >> 9) & 0x7
    flags_hex = doff_res_flag_hex[2:]
    flags = doff_res_flag & 0x1FF

    ns = (flags >> 8) & 0x1
    cwr = (flags >> 7) & 0x1
    ece = (flags >> 6) & 0x1
    urg = (flags >> 5) & 0x1
    ack = (flags >> 4) & 0x1
    psh = (flags >> 3) & 0x1
    rst = (flags >> 2) & 0x1
    syn = (flags >> 1) & 0x1
    fin = flags & 0x1

    window_size = int(window_size_hex, 16) 
    checksum = int(checksum_hex, 16)
    urgent_pointer = int(urgent_pointer_hex, 16)

    header_length_bytes = data_offset * 4
    header_length_hex = header_length_bytes * 2    

    data_hex = hex_data[header_length_hex:]
    
    # print information
    print(f"TCP Header:")
    print(f"  {'Source Port:':<25} {source_port_hex:<20} | {source_port}")
    print(f"  {'Destination Port:':<25} {destination_port_hex:<20} | {destin_port}")
    print(f"  {'Sequence Number:':<25} {seq_number_hex:<20} | {seq_number}")
    print(f"  {'Acknowledgement Number:':<25} {ack_number_hex:<20} | {ack_number:<20}")
    print(f"  {'Data Offset:':<25} {data_offset:<20} | {data_offset_bytes} bytes")
    print(f"  {'Reserved:':<25} {res_hex:<20} | {res:<20}")
    print(f"  {'Flags:':<25} {flags_hex:<20} | {flags:<20}")
    print(f"    {'NS:':<5} {ns}")
    print(f"    {'CWR:':<5} {cwr}")
    print(f"    {'ECE:':<5} {ece}")
    print(f"    {'URG:':<5} {urg}")
    print(f"    {'ACK:':<5} {ack}")
    print(f"    {'PSH:':<5} {psh}")
    print(f"    {'RST:':<5} {rst}")
    print(f"    {'SYN:':<5} {syn}")
    print(f"    {'FIN:':<5} {fin}")
    print(f"  {'Window Size:':<25} {window_size_hex:<20} | {window_size:<20}")
    print(f"  {'Checksum:':<25} {checksum_hex:<20} | {checksum:<20}")
    print(f"  {'Urget Pointer:':<25} {urgent_pointer_hex:<20} | {urgent_pointer:<20}")
    print(f"  {'Payload:':<25} {data_hex}")


def parse_udp_header(hex_data):
    source_port_hex = hex_data[0:4]
    destination_port_hex = hex_data[4:8]
    length_hex = hex_data[8:12]
    checksum_hex = hex_data[12:16]
    payload_hex = hex_data[16:]
    
    source_port = int(source_port_hex, 16)
    destin_port = int(destination_port_hex, 16)
    length = int(length_hex, 16)
    checksum = int(checksum_hex, 16)
    
    # print information
    print(f"UDP Header:")
    print(f"  {'Source Port:':<25} {source_port_hex:<20} | {source_port}")
    print(f"  {'Destination Port:':<25} {destination_port_hex:<20} | {destin_port}")
    print(f"  {'Length:':<25} {length_hex:<20} | {length}")
    print(f"  {'Checksum:':<25} {checksum_hex:<20} | {checksum}")
    print(f"  {'Payload:':<25} {payload_hex:<20}")


def parse_dns_header(hex_data):
    transaction_id_hex = hex_data[0:4]
    flags_hex = hex_data[4:8]
    questions_hex = hex_data[8:12]
    answer_rr_hex = hex_data[12:16]
    authority_rr_hex = hex_data[16:20]
    additional_rr_hex = hex_data[20:24]
    payload_hex = hex_data[24:]

    transaction_id = int(transaction_id_hex, 16)
    flags = int(flags_hex, 16)
    questions = int(questions_hex, 16)
    answer_rr = int(answer_rr_hex, 16)
    authority_rr = int(authority_rr_hex, 16)
    additional_rr = int(additional_rr_hex, 16)
    
    # print information
    print(f"DNS Header:")
    print(f"  {'Transaction ID:':<25} {transaction_id_hex:<20} | {transaction_id}")
    print(f"  {'Flags:':<25} {flags_hex:<20} | {flags}")
    print(f"  {'Questions:':<25} {questions_hex:<20} | {questions}")
    print(f"  {'Answer RR:':<25} {answer_rr_hex:<20} | {answer_rr}")
    print(f"  {'Authority:':<25} {authority_rr_hex:<20} | {authority_rr}")
    print(f"  {'Additional RR:':<25} {additional_rr_hex:<20} | {additional_rr}")
    print(f"  {'Payload:':<25} {payload_hex:<20}")
    






    
    