import argparse
import re
import socket
import struct
from multiprocessing.dummy import Pool

dns_packet = b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x01\x31\x01\x30" \
             b"\x01\x30\x01\x30\x01\x30\x01\x30\x01\x30\x01\x30\x01\x30\x01\x30" \
             b"\x01\x30\x01\x30\x01\x30\x01\x30\x01\x30\x01\x30\x01\x30\x01\x30" \
             b"\x01\x30\x01\x30\x01\x30\x01\x30\x01\x30\x01\x30\x01\x30\x01\x30" \
             b"\x01\x30\x01\x30\x01\x30\x01\x38\x01\x65\x01\x66\x03\x69\x70\x36" \
             b"\x04\x61\x72\x70\x61\x00\x00\x0c\x00\x01"

tcp_protocols = {'pop3': (b'AUTH', re.compile(b'^\+')),
                 'dns': (struct.pack('!H', len(dns_packet)) + dns_packet, re.compile(b'^.{2}\x00\x01')),
                 'http': (b'\0', re.compile(b'^HTTP')),
                 'smtp': (b'EHLO', re.compile(b'^\d{3}'))
                 }

udp_protocols = {'dns': (dns_packet, re.compile(b'\x00\x01')),
                 'sntp': (b'\x1b' + 47 * b'\0', re.compile(b'^\x1c'))
                 }


def scan_tcp_port(port):
    result = ''
    for protocol, payload in tcp_protocols.items():
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            try:
                s.connect((host, port))
                result = f'{port} is open TCP port'
                try:
                    s.send(payload[0])
                    if re.match(payload[1], s.recv(1024)):
                        print(result + f' with protocol {protocol}')
                        return
                except socket.error:
                    continue
            except (socket.timeout, socket.error):
                return
    print(result)


def scan_udp_port(port):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(1)
        for protocol, payload in udp_protocols.items():
            s.sendto(payload[0], (host, port))
            try:
                received = s.recv(1024)
                result = f'{port} is open UDP port'
                if re.match(payload[1], received):
                    print(result + f' with protocol {protocol}')
                    return
                print(result)
            except (socket.timeout, socket.error):
                continue


def create_arg_parser():
    parser = argparse.ArgumentParser(description='TCP and UDP port scanner')
    parser.add_argument('host', type=str, help='ip address or a host name of target')
    parser.add_argument('--start', '-s', type=int, help='start of range', default=1)
    parser.add_argument('--end', '-e', type=int, help='end of range', default=500)
    parser.add_argument('--tcp', '-t', action='store_true', help='scan tcp ports')
    parser.add_argument('--udp', '-u', action='store_true', help='scan udp ports')
    return parser


if __name__ == '__main__':
    args = create_arg_parser().parse_args()
    host = args.host
    pool = Pool(50)
    if args.tcp:
        pool.imap(scan_tcp_port, range(args.start, args.end))
    if args.udp:
        pool.imap(scan_udp_port, range(args.start, args.end))
    pool.close()
    pool.join()
