import socket
import struct

def main():
	HOST = socket.gethostbyname(socket.gethostname())
	conn = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_IP)
	conn.bind((HOST, 0))
	conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
	conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
	while True:
		raw_data, addr = conn.recvfrom(65536)
		(version, hl, ttl, proto, src, dest, data) = ipv4_packet(raw_data)
		if proto == 6:
			print("\t IPV4 PACAKET: ")
			print("\t\t version: {}, hl: {}, ttl:{}".format(version, hl, ttl))
			print("\t\t proto: {}, src: {}, dest:{}".format(proto, src, dest))
			src_port, dest_port, seq, ack, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, tcp_data = tcp_open(data)
			print("TCP info:")
			print("\t src_port: {}, dest_port: {}\n".format(src_port, dest_port))

"""def ethernet_frame(data):
	dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
	return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

def get_mac_addr(bytes_addr):
	return ':'.join(map('{:02x}'.format, bytes_addr)).upper()
"""

def ipv4_packet(data):
	version_header_length = data[0]
	version = version_header_length >> 4
	hl = (version_header_length&15)*4
	ttl, proto, src, dest = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
	return version, hl, ttl, proto, ipv4(src), ipv4(dest),data[hl:]

def ipv4(addr):
	return '.'.join(map(str, addr))

def tcp_open(data):
	(src_port, dest_port, seq, ack, offlag) = struct.unpack('! H H L L H', data[:14])
	offset = (offlag>>12)*4
	flag_urg = (offlag&32)>>5
	flag_ack = (offlag&16)>>4
	flag_psh = (offlag&8)>>3
	flag_rst = (offlag&4)>>2
	flag_syn = (offlag&2)>>1
	flag_fin = (offlag&1)
	return src_port, dest_port, seq, ack, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

main()