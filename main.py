import socket
import textwrap
import struct


TAB_1 = '\t   '
TAB_2 = '\t\t   '
TAB_3 = '\t\t\t   '
TAB_1 = '\t\t\t\t   '

DATA_TAB_1 = '\t '
DATA_TAB_2 = '\t\t '
DATA_TAB_3 = '\t\t\t '
DATA_TAB_1 = '\t\t\t\t '


def main():
     conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

     while(1):
        raw_data, addr = conn.recvfrom(65535)
        dest_mac, src_mac, eth_proto, data = frame(raw_data)
        print('\nEthernet frame')
        print(TAB_1 + f'Destination: [{dest_mac}], Source: [{src_mac}], Protocol: [{eth_proto}]')
        
        if eth_proto == 8:
            version, header_length, ttl, proto, src, target, data = ipv4_packet(data)
            #version, header_length, ttl , proto, src, target, data = ipv4(data)
            print(TAB_1 + 'IPv4')
            print(TAB_2 + f'Version: {version}, Header Length {header_length}, TTL {ttl}')
            print(TAB_2 + f'Protocol: {proto}, Source {src}, Target {target}')

            if proto == 1:
                icmp, code, checksum, data = icmp_packet(data)
                print(TAB_1 + 'ICMP')
                print(TAB_2 + f'Type: {icmp_type}, Code {code}, Checksum {checksum}')
                print(TAB_2 + f'Data: {data}')
            elif proto == 6:
                (src_port, dest_port, sequence, ackm, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data) = tcp_segment(data)
                print(TAB_1 + 'TCP')
                print(TAB_2 + f'Source: {src_port}, Destination {dest_port}, Sequence {sequence}, Acknowledgement {ackm}')
                print(TAB_2 + f'URG: {flag_urg}, ACK {flag_ack}, PSH {flag_psh}, RST {flag_rst}, SYN {flag_syn}, FIN {flag_fin}')
                print(TAB_2 + f'DATA {data}')
            else:
                print(TAB_2 + "DATA")
                print(DATA_TAB_2 + f'{data}')



def frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac(dest_mac), get_mac(src_mac), socket.htons(proto), data[14:]


def get_mac(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    mac_addr = ":".join(bytes_str).upper()
    return mac_addr


def ipv4_packet(data):
    version_header_length = data[0]
    version =  version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl , proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20 ])
    return [version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]]


def ipv4(addr):
    return ".".join(map(str, addr))


def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]


def tcp_segment(data):
    (src_port, dest_port, sequence, ackm, offset_reserved_flag) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flag >> 12) * 4
    flag_urg = (offset_reserved_flag & 32) >> 5
    flag_ack = (offset_reserved_flag & 16) >> 5
    flag_psh = (offset_reserved_flag & 8) >> 5
    flag_rst = (offset_reserved_flag & 4) >> 5
    flag_syn = (offset_reserved_flag & 2) >> 5
    flag_fin = offset_reserved_flag & 1

    return src_port, dest_port, sequence, ackm, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:] 

main()
