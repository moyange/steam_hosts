import dns.message
import dns.edns
import dns.query
import dns.rdatatype
import ipaddress
import argparse
from tqdm import tqdm


def convert_cidr(cidr):
    ipv4 = ipaddress.IPv4Network(cidr)
    address = ipv4.network_address.packed
    mask = ipv4.netmask.packed
    return address + mask


def resolve(domain, record_type='A'):
    """解析域名，支持 A 记录(IPv4) 和 AAAA 记录(IPv6)"""
    opt = dns.edns.GenericOption(dns.edns.ECS, convert_cidr(CIDR))
    request = dns.message.make_query(domain, record_type)
    request.use_edns(edns=True, options=[opt])
    response = dns.query.https(request, DOH_SERVER)
    
    ips = []
    for answer in response.answer:
        if answer.rdtype == (dns.rdatatype.A if record_type == 'A' else dns.rdatatype.AAAA):
            for item in answer.items:
                ips.append(item.address)
    return ips


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--cidr', default='127.0.0.0/8', const='127.0.0.0/8', nargs='?',
                        help='CIDR for the target area')
    parser.add_argument('-s', '--server', default='https://dns.alidns.com/dns-query', const='https://dns.alidns.com/dns-query',
                        nargs='?', help='DoH Server (Must support ECS)', required=False)
    parser.add_argument('-o', '--output', default='./hosts', const='./hosts', nargs='?', help='output file', )
    parser.add_argument('-d', '--domains', default='./domains.txt', const='./domains.txt', nargs='?',
                        help='domain list file', required=False)
    parser.add_argument('-6', '--ipv6', action='store_true', help='Enable IPv6 resolution (AAAA records)')
    return parser.parse_args()


global OUTPUT_FILE
global CIDR
global DOH_SERVER
if __name__ == "__main__":
    args = parse_args()
    CIDR = args.cidr if args.cidr else '127.0.0.0/8'
    DOH_SERVER = args.server if args.server else 'https://dns.alidns.com/dns-query'
    OUTPUT_FILE = args.output if args.output else './hosts'
    INPUT_FILE = args.domains if args.domains else './domains.txt'
    ENABLE_IPV6 = args.ipv6

    with open(INPUT_FILE, 'r') as f:
        DOMAINS = f.read().splitlines()
        with open(OUTPUT_FILE, "w") as hosts_file:
            pbar = tqdm(total=len(DOMAINS), desc='Progress', leave=True, ncols=100, unit_scale=True)
            for domain in DOMAINS:
                try:
                    # 获取 IPv4 地址
                    ipv4_list = resolve(domain, 'A')
                    for ipv4 in ipv4_list:
                        hosts_file.write(f"{ipv4:{15}}\t{domain}\n")
                    
                    # 如果启用 IPv6，获取 IPv6 地址
                    if ENABLE_IPV6:
                        ipv6_list = resolve(domain, 'AAAA')
                        for ipv6 in ipv6_list:
                            hosts_file.write(f"{ipv6:{39}}\t{domain}\n")
                            
                except Exception as e:
                    print(f"Error resolving {domain}: {e}")
                pbar.update(1)
            pbar.close()
