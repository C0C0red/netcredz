# NetCredz v0.0.1 - alpha
# Created by Joey Melo - Inspired by Pcredz from Laurent Gaffie https://github.com/lgandx/PCredz/
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.

import socket
import struct
import re
from urllib.parse import unquote
import argparse, sys
import traceback
from base64 import b64decode
import time
import hashlib
import codecs

CAPTURE_PROTOCOLS = [
	"ntlm",
	"ldap",
	"http",
	"smtp",
	"snmp",
	"telnet",
	"ftp",
	"kerberos",
	"dhcpv6",
	"llmnr"
]

class InvalidProtocolException(Exception):
	def __init__(self, protocol):
		self._protocol = protocol
		super().__init__(f"Invalid capture filter: \"{protocol}\". Valid options are {','.join(CAPTURE_PROTOCOLS)}")

class Color:
	def __init__(self):
		self.RED = "\033[31m"
		self.GREEN = "\033[32m"
		self.YELLOW = "\033[33m"
		self.BLUE = "\033[34m"
		self.PURPLE = "\033[35m"
		self.RESET = "\033[0m"
	
class Logger:
	def __init__(self, verbosity: int, debug: bool):
		self._verbosity = verbosity
		self._debug = debug
		self._color = Color()

	def error(self, string: str, verbosity = 1):
		if self._verbosity >= verbosity:
			print(self._color.RED + "[X] " + self._color.RESET + string)
		if self._debug:
			print(self._color.PURPLE + "[DEBUG] " + self._color.RESET + traceback.format_exc())

	def success(self, string: str, verbosity = 0):
		if self._verbosity >= verbosity:
			print(self._color.GREEN + "[+] " + self._color.RESET + string)

	def fail(self, string: str, verbosity = 0):
		if self._verbosity >= verbosity:
			print(self._color.YELLOW + "[-] " + self._color.RESET + string)

	def info(self, string: str, verbosity = 0):
		if self._verbosity >= verbosity:
			print(self._color.BLUE + "[*] " + self._color.RESET + string)

	def plain(self, string: str, verbosity = 0):
		if self._verbosity >= verbosity:
			print(string)
		elif self._verbosity == 1:
			print(self._color.YELLOW + "[!] " + self._color.RESET + "Skipping data previously captured. Increase verbosity (-v) or check log file to display data.")

class Capture:
	def __init__(self, interface: str, filters: list, regex: str):
		self._interface = interface
		self._filters = CAPTURE_PROTOCOLS if "all" in filters else filters
		self._parser_map = {}
		self._parser_map.update({protocol: "parse_" + protocol for protocol in CAPTURE_PROTOCOLS if protocol != "all"})
		self._seen_packets = {}
		self._regex = regex

		try:
			self._socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
			self._socket.bind((self._interface, 0))
		except PermissionError:
			log.fail("Administrative privileges are required capture traffic.")
			exit(1)
		except Exception as e:
			log.error(str(e))
			return None

	def _is_duplicate(self, packet):
		packet_hash = hashlib.sha256(packet).hexdigest()
		current_time = time.time()

		# Remove entries from the cache older than 5 seconds
		for h in list(self._seen_packets):
			if current_time - self._seen_packets[h] > 5:
				del self._seen_packets[h]

		if packet_hash in self._seen_packets:
			return True
		else:
			self._seen_packets[packet_hash] = current_time
			return False

	def _parse_packet(self, packet):
		# Skip duplicate packets
		try:
			if self._is_duplicate(packet):
				return

			packet_parser = PacketParser(packet)
			for protocol in self._filters:
				method = self._parser_map[protocol]
				parse = getattr(packet_parser, method)
				parse()
			if self._regex:
				packet_parser.parse_regex(self._regex)

		except KeyboardInterrupt:
				exit()

		except TypeError:
			log.error("TypeError occurred while parsing packet - likely NoneType error with re.findall")
			return

		except AttributeError:
			log.error("AttributeError occurred while parsing packet - likely an error with re.findall") 
			return

		except UnboundLocalError:
			log.error("UnboundLocalError occurred while parsing packet - src_port likely not found")
			return

		except Exception as e:
			log.error(str(e))

	def listen(self):
		while True:
			packet, _ = self._socket.recvfrom(0x10000)
			self._parse_packet(packet)

	def parse_file(self, pcap_file):
		pcap_header = pcap_file[:24]
		magic_number = struct.unpack('I', pcap_header[0:4])[0]
		
		# Check if file is PCAP format
		if magic_number != 0xa1b2c3d4:
			log.fail("Invalid PCAP file format")
			exit(1)
			
		offset = 24  # Skip global header
		while offset < len(pcap_file):
			packet_header = pcap_file[offset:offset+16]
			packet_len = struct.unpack('I', packet_header[8:12])[0]
			
			packet_data = pcap_file[offset+16:offset+16+packet_len]
			
			self._parse_packet(packet_data)

			offset += 16 + packet_len
				
class PacketParser:
	def __init__(self, packet):
		self._src_port = None
		self._dest_port = None
		self._data = None
		self._src_ip = None
		self._dest_ip = None
		self._traffic = None

		dest_mac, src_mac, eth_type, frame_data = self._parse_ethernet_frame(packet)

		# IPv4
		if eth_type == 0x08:
			
			version, header_length, ttl, protocol, src_ip, dest_ip, data = self._parse_ipv4_packet(frame_data)
			self._src_ip = src_ip
			self._dest_ip = dest_ip

			# TCP
			if protocol == 0x06:
				src_port, dest_port, payload = self._parse_tcp_packet(data)

			# UDP
			elif protocol == 0x11:
				src_port, dest_port, payload = self._parse_udp_packet(data)

			self._src_port = src_port
			self._dest_port = dest_port
			self._data = payload
			self._traffic = f"{self._src_ip}:{self._src_port} --> {self._dest_ip}:{self._dest_port}"

		# IPv6 -- to be implemented
		elif eth_type == 0x86DD:
			pass

		"""
		To Do: add support to these protocols
		protocols =	{
			6:'tcp',
			17:'udp',
			1:'icmp',
			2:'igmp',
			3:'ggp',
			4:'ipcap',
			5:'ipstream',
			8:'egp',
			9:'igrp',
			29:'ipv6oipv4',
			}
		"""

	def _parse_ethernet_frame(self, frame):
		dest_mac, src_mac, eth_type = struct.unpack("! 6s 6s H", frame[:14])
		return dest_mac, src_mac, socket.ntohs(eth_type), frame[14:]

	def _parse_ipv4_packet(self, frame_data):
		ip_header = struct.unpack("!BBHHHBBH4s4s", frame_data[:20])
		version_and_length = ip_header[0]
		version = version_and_length >> 4
		header_length = (version_and_length & 0xF) * 4
		ttl = ip_header[5]
		protocol = ip_header[6]
		src_ip = socket.inet_ntoa(ip_header[8])
		dest_ip = socket.inet_ntoa(ip_header[9])
		data = frame_data[header_length:]
		return version, header_length, ttl, protocol, src_ip, dest_ip, data

	def _parse_tcp_packet(self, data):
		tcp_header = struct.unpack("!HHLLBBHHH", data[:20])
		src_port = tcp_header[0]
		dest_port = tcp_header[1]
		return src_port, dest_port, data[20:]

	def _parse_udp_packet(self, data):
		udp_header = struct.unpack("!HHHH", data[:8])
		src_port = udp_header[0]
		dest_port = udp_header[1]
		length = udp_header[2] # not in use
		checksum = udp_header[3] # not in use
		return src_port, dest_port, data[8:]

	def parse_ntlm(self):
		ntlmssp1 = re.findall(b"NTLMSSP\x00\x01\x00\x00\x00.*[^EOF]*", self._data)
		ntlmssp2 = re.findall(b"NTLMSSP\x00\x02\x00\x00\x00.*[^EOF]*", self._data,re.DOTALL)
		ntlmssp3 = re.findall(b"NTLMSSP\x00\x03\x00\x00\x00.*[^EOF]*", self._data,re.DOTALL)
		
		if ntlmssp2:
			global chall
			chall = ntlmssp2[0][24:32]

		if ntlmssp3:
			data = ntlmssp3[0]
			packet_len = len(data)
			if packet_len > 0:
				sspi_start = data[:]
				lm_hash_len = struct.unpack("<H", data[14:16])[0]
				lm_hash_offset = struct.unpack("<H", data[16:18])[0]
				lm_hash = sspi_start[lm_hash_offset:lm_hash_offset + lm_hash_len]
				nt_hash_len = struct.unpack("<H", data[22:24])[0]
				nt_hash_offset = struct.unpack("<H", data[24:26])[0]
				nt_hash = sspi_start[nt_hash_offset:nt_hash_offset + nt_hash_len]
				domain_len = struct.unpack("<H", data[30:32])[0]
				domain_offset = struct.unpack("<H", data[32:34])[0]
				domain = sspi_start[domain_offset:domain_offset + domain_len].replace(b"\x00", b"")
				user_len = struct.unpack("<H", data[38:40])[0]
				user_offset = struct.unpack("<H", data[40:42])[0]
				user = sspi_start[user_offset:user_offset + user_len].replace(b"\x00", b"")

			if nt_hash_len == 24:				
				ntlm_hash = "%s::%s:%s:%s:%s" % (user.decode(), domain.decode(), lm_hash.hex(), nt_hash.hex(), chall.hex())
				storage.save("NTLMv1 hash captured", self._traffic, ntlm_hash)

			if nt_hash_len > 60:
				ntlm_hash = "%s::%s:%s:%s:%s" % (user.decode(), domain.decode(), chall.hex(), nt_hash[:16].hex(), nt_hash[16:].hex())
				storage.save("NTLMv2 hash captured", self._traffic, ntlm_hash)

	def parse_ldap(self):
		# Parses LDAP cleartext queries, not NTLM. There is parse_ntlm() for that
		ldap_bind = re.search(b"\x30....\x60.\x02\x01\x03.*", self._data, re.DOTALL)

		if ldap_bind:
			ldap_message = ldap_bind.group(0)
			message_len = ldap_message[1]
			message_id = ldap_message[2:5]
			bind_len = ldap_message[6]
			ldap_version = ldap_message[7:10]
			dn_len = ldap_message[11]
			dn_string = ldap_message[12:12+dn_len].decode()
			auth_len = ldap_message[12+dn_len+1]
			auth_data = ldap_message[12+dn_len+2:12+dn_len+2+auth_len].decode() 

			if dn_string and auth_data:
				ldap_auth_data = "DN: " + dn_string + "\nPassword: " + auth_data
				storage.save("LDAP bind string captured", self._traffic, ldap_auth_data)

		pass

	def parse_http(self):
		# Parse request verb (method) and Host header
		http_request = {"method":"", "host":"", "header":""}

		try:
			methods = ["GET", "POST", "PUT", "DELETE", "PATCH"]
			pattern = (r"(" + "|".join(f"{method} [^\n]+" for method in methods) + r")").encode("utf-8")
			method = re.findall(pattern, self._data)[0]
			host = re.findall(b"(Host: [^\n]+)", self._data)[0]
			http_request["method"] = method.decode().strip()
			http_request["host"] = host.decode().strip()
		except IndexError:
			# IndexError means no data was found matching the criteria in this case, so we ignore it
			pass

		# Search common auth strings
		common_username_forms = ["log","login","wpname","ahd_username","unickname","nickname","user","user_name","alias","pseudo","email","username","_username","userid","form_loginname","loginname","login_id","loginid","session_key","sessionkey","pop_login","uid","id","user_id","screename","uname","ulogin","acctname","account","member","mailaddress","membername","login_username","login_email","loginusername","loginemail","uin","sign-in","j_username"]
		common_password_forms = ["ahd_password","pass","password","_password","passwd","session_password","sessionpassword","login_password","loginpassword","form_pw","pw","userpassword","pwd","upassword","login_passwordpasswort","passwrd","wppassword","upasswd","j_password"]
		http_username = re.search("|".join(common_username_forms).encode(), self._data)
		http_password = re.search("|".join(common_password_forms).encode(), self._data)
		http_negotiate_authz = re.findall(b'(?<=Authorization: Negotiate )[^\\r]*', self._data)
		http_negotiate_www = re.findall(b'(?<=WWW-Authenticate: Negotiate )[^\\r]*', self._data)
		basic64 = re.findall(b'(?<=Authorization: Basic )[^\n]*', self._data)
		http_ntlm2 = re.findall(b'(?<=WWW-Authenticate: NTLM )[^\\r]*', self._data)
		http_ntlm3 = re.findall(b'(?<=Authorization: NTLM )[^\\r]*', self._data)
		ctx1_usr = re.findall(b'<Username>(.*?)</Username><Password encoding="ctx1">', self._data)
		ctx1_pwd = re.findall(b'<Password encoding="ctx1">(.*?)</Password>', self._data)

		# Parse common form auth
		http_user = []
		http_pass = []
		if http_username:
			pattern = (r"\b(?:" + "|".join(map(re.escape, common_username_forms)) + r")\b").encode("utf-8")
			form_fields = re.findall(pattern, self._data, re.IGNORECASE)
			for field in form_fields:
				username = re.findall(b"(%s=[^&]+)" % field, self._data)
				if username:
					http_user.append(username[0].decode())

		if http_password:
			pattern = (r"\b(?:" + "|".join(map(re.escape, common_password_forms)) + r")\b").encode("utf-8")
			form_fields = re.findall(pattern, self._data, re.IGNORECASE)
			form_fields = re.findall(pattern, self._data, re.IGNORECASE)
			for field in form_fields:
				password = re.findall(b"(%s=[^&]+)" % field, self._data)
				if password:
					http_pass.append(password[0].decode())

		if http_user or http_pass:
			request = f'{http_request["method"]}\n{http_request["host"]}\nPossible username(s): {"&".join(http_user)}\nPossible password(s): {"&".join(http_pass)}'
			storage.save("Potential HTTP authentication captured", self._traffic, request)

		# Parse common auth headers
		if http_negotiate_authz:
			http_request["header"] = http_negotiate_authz[0].decode()
			request = f'{http_request["method"]}\n{http_request["host"]}\nAuthorization: Negotiate {http_request["header"]}'
			storage.save("HTTP authentication header captured", self._traffic, request)

		if http_negotiate_www:
			http_request["header"] = http_negotiate_www[0].decode()
			request = f'{http_request["method"]}\n{http_request["host"]}\nWWW-Authenticate: Negotiate {http_request["header"]}'
			storage.save("HTTP authentication header captured", self._traffic, request)

		if basic64:
			http_request["header"] = basic64[0].decode()
			request = f'{http_request["method"]}\n{http_request["host"]}\nAuthorization: Basic {http_request["header"]}'
			storage.save("HTTP authentication header captured", self._traffic, request)

		if http_ntlm2:
			http_request["header"] = http_ntlm2[0].decode()
			request = f'{http_request["method"]}\n{http_request["host"]}\nWWW-Authenticate: NTLM {http_request["header"]}'
			storage.save("HTTP authentication header captured", self._traffic, request)

		if http_ntlm3:
			http_request["header"] = http_ntlm3[0].decode()
			request = f'{http_request["method"]}\n{http_request["host"]}\nAuthorization: NTLM {http_request["header"]}'
			storage.save("HTTP authentication header captured", self._traffic, request)

		# Parse ctx auth
		if ctx1_usr and ctx1_pwd:
			try:
				request = f'{http_request["method"]}\n{http_request["host"]}\nUsername: {ctx1_usr[0]}\nPassword: {ctx1_pwd[0]}'
				storage.save("CTX authentication captured", self._traffic, request)
			except IndexError:
				pass

	def parse_smtp(self):
		# Gotta handle package duplication and ntlm auth
		global smtp_auth
		try:
			smtp_auth
		except:
			smtp_auth = False
		
		smtp_auth_header = re.search(b'AUTH LOGIN|AUTH PLAIN|AUTH NTLM', self._data)
		if smtp_auth_header:
			smtp_auth = True

		if smtp_auth:
			try:
				auth_data = b64decode(self._data[12:].split(b"\n")[0]).decode()
				if auth_data:
					storage.save("SMTP authentication data captured", self._traffic, auth_data)
			except:
				pass


	def parse_snmp(self):
		snmp_version = self._data[4:5]
		if snmp_version == b"\x00":
			str_len = struct.unpack('<b',self._data[6:7])[0]
			snmp_string = self._data[7:7+str_len].decode('latin-1')
			storage.save("SNMPv1 string captured", self._traffic, snmp_string)
		if self._data[3:5] == b"\x01\x01":
			str_len = struct.unpack('<b',self._data[6:7])[0]
			snmp_string = self._data[7:7+str_len].decode('latin-1')
			storage.save("SNMPv2 string captured", self._traffic, snmp_string)

	def parse_telnet(self):
		if self._dest_port == 23:
			if self._data[:5] == b'\x01\x01\x08\x0a\xf8':
				telnet_msg = self._data[12:].decode()
				storage.save("Telnet traffic captured", self._traffic, telnet_msg)

	def parse_ftp(self):
		ftp_user = re.findall(b'(?<=USER )[^\r]*', self._data)
		ftp_pass = re.findall(b'(?<=PASS )[^\r]*', self._data)
		
		if ftp_user:
			ftp_user = ftp_user[0].decode()
			storage.save("FTP username captured", self._traffic, ftp_user)
		
		if ftp_pass:
			ftp_pass = ftp_pass[0].decode()
			storage.save("FTP password captured", self._traffic, ftp_pass)

	def parse_kerberos(self):
		# TCP
		msg_type = self._data[19:20]
		enc_type = self._data[41:42]
		message_type = self._data[30:31]
		if msg_type == b"\x0a" and enc_type == b"\x17" and message_type ==b"\x02":
			if self._data[49:53] == b"\xa2\x36\x04\x34" or self._data[49:53] == b"\xa2\x35\x04\x33":
				hash_len = struct.unpack('<b',self._data[50:51])[0]
				if hash_len == 54:
					hash_data = self._data[53:105]
					switch_hash = hash_data[16:]+hash_data[0:16]
					name_len = struct.unpack('<b',self._data[153:154])[0]
					name = self._data[154:154+name_len]
					domain_len = struct.unpack('<b',self._data[154+name_len+3:154+name_len+4])[0]
					domain = self._data[154+name_len+4:154+name_len+4+domain_len]
					build_hash = '$krb5pa$23$%s%s%s%s%s' % (name.decode('latin-1'), "$", domain.decode('latin-1'), "$dummy$", codecs.encode(switch_hash,'hex').decode('latin-1'))
					storage.save("Kerberos hash found", self._traffic, build_hash)
			if self._data[42:46] == b"\xa2\x36\x04\x34" or self._data[42:46] == b"\xa2\x35\x04\x33":
				hash_len = struct.unpack('<b',self._data[45:46])[0]
				hash_data = self._data[46:46+hash_len]
				switch_hash = hash_data[16:]+hash_data[0:16]
				name_len = struct.unpack('<b',self._data[hash_len+94:hash_len+94+1])[0]
				name = self._data[hash_len+95:hash_len+95+name_len]
				domain_len = struct.unpack('<b',self._data[hash_len+95+name_len+3:hash_len+95+name_len+4])[0]
				domain = self._data[hash_len+95+name_len+4:hash_len+95+name_len+4+domain_len]
				build_hash = '$krb5pa$23$%s%s%s%s%s' % (name.decode('latin-1'), "$", domain.decode('latin-1'), "$dummy$", codecs.encode(switch_hash,'hex').decode('latin-1'))
				storage.save("Kerberos hash found", self._traffic, build_hash)

			else:
				hash_data = self._data[48:100]
				switch_hash = hash_data[16:]+hash_data[0:16]
				name_len = struct.unpack('<b',self._data[148:149])[0]
				name = self._data[149:149+name_len]
				domain_len = struct.unpack('<b',self._data[149+name_len+3:149+name_len+4])[0]
				domain = self._data[149+name_len+4:149+name_len+4+domain_len]
				build_hash = '$krb5pa$23$%s%s%s%s%s' % (name.decode('latin-1'), "$", domain.decode('latin-1'), "$dummy$", codecs.encode(switch_hash,'hex').decode('latin-1'))
				storage.save("Kerberos hash found", self._traffic, build_hash)

		#UDP
		msg_type = self._data[17:18]
		enc_type = self._data[39:40]
		if msg_type == b"\x0a" and enc_type == b"\x17":
			if self._data[40:44] == b"\xa2\x36\x04\x34" or self._data[40:44] == b"\xa2\x35\x04\x33":
				hash_len = struct.unpack('<b',self._data[41:42])[0]
				if hash_len == 54:
					hash_data = self._data[44:96]
					switch_hash = hash_data[16:]+hash_data[0:16]
					name_len = struct.unpack('<b',self._data[144:145])[0]
					name = self._data[145:145+name_len]
					domain_len = struct.unpack('<b',self._data[145+name_len+3:145+name_len+4])[0]
					domain = self._data[145+name_len+4:145+name_len+4+domain_len]
					build_hash = '$krb5pa$23$%s%s%s%s%s' % (name.decode('latin-1'), "$", domain.decode('latin-1'), "$dummy$", codecs.encode(switch_hash,'hex').decode('latin-1'))
					storage.save("Kerberos hash found", self._traffic, build_hash)
				if hash_len == 53:
					hash_data = self._data[44:95]
					switch_hash = hash_data[16:]+hash_data[0:16]
					name_len = struct.unpack('<b',self._data[143:144])[0]
					name = self._data[144:144+name_len]
					domain_len = struct.unpack('<b',self._data[144+name_len+3:144+name_len+4])[0]
					domain = self._data[144+name_len+4:144+name_len+4+domain_len]
					build_hash = '$krb5pa$23$%s%s%s%s%s' % (name.decode('latin-1'), "$", domain.decode('latin-1'), "$dummy$", codecs.encode(switch_hash,'hex').decode('latin-1'))
					storage.save("Kerberos hash found", self._traffic, build_hash)

			else:
				hash_len = struct.unpack('<b',self._data[48:49])[0]
				hash_data = self._data[49:49+hash_len]
				switch_hash = hash_data[16:]+hash_data[0:16]
				name_len = struct.unpack('<b',self._data[hash_len+97:hash_len+97+1])[0]
				name = self._data[hash_len+98:hash_len+98+name_len]
				domain_len = struct.unpack('<b',self._data[hash_len+98+name_len+3:hash_len+98+name_len+4])[0]
				domain = self._data[hash_len+98+name_len+4:hash_len+98+name_len+4+domain_len]
				build_hash = '$krb5pa$23$%s%s%s%s%s' % (name.decode('latin-1'), "$", domain.decode('latin-1'), "$dummy$", codecs.encode(switch_hash,'hex').decode('latin-1'))
				storage.save("Kerberos hash found", self._traffic, build_hash)

	def parse_dhcpv6(self):
		dhcpv6_client_port = 546
		dhcpv6_server_port = 547
		if self._src_port == dhcpv6_client_port or self._dest_port == dhcpv6_client_port or self._src_port == dhcpv6_server_port or self._dest_port == dhcpv6_server_port:
			storage.save("DHCPv6 traffic captured", self._traffic, "DHCPv6 identified. Run mitm6.")			

	def parse_llmnr(self):
		llmnr_port = 5355 # UDP
		if self._src_port == llmnr_port or self._dest_port == llmnr_port:
			storage.save("LLMNR traffic captured", self._traffic, "LLMNR identified. Run responder.")

	def parse_regex(self, regex):
		regex = regex.encode("unicode_escape").decode("utf-8").encode()
		matches = re.findall(regex, self._data)
		if matches:
			storage.save("Regex expression captured", self._traffic, str(matches))

class Storage:
	# Maybe change storage to json or simply .txt
	def __init__(self, file: str):
		self._file = file
		self._headers = "message,traffic,data\n"

		try:
			# Try to open the file in read mode to check for headers
			with open(self._file, "r") as f:
				first_line = f.readline()
				if first_line.strip() != self._headers.strip():
					log.fail("Warning: Output file exists but is missing headers. Double check your file path or create a new file.")
					exit(1)

		except FileNotFoundError:
			# File doesn't exist; create it with headers
			with open(self._file, "w") as f:
				f.write(self._headers)
				f.close()

	def save(self, message: str, traffic: str, data: str):
		storage_contents = self.read()

		if traffic not in storage_contents and data not in storage_contents:
			try:
				with open(self._file, "a") as f:
					f.write(f"{message},{traffic},{data}\n")
					f.close()
				log.success(message, 1)
				log.info(traffic, 1)
				log.plain(data)
				log.plain("")
			except Exception as e:
				log.error(str(e))

		else:
				log.success(message, 2)
				log.info(traffic, 2)
				log.plain(data, 2)
				log.plain("", 2)

	def read(self):
		file_contents = open(self._file, "r").read()
		return file_contents


def parse_arguments():
	parser = argparse.ArgumentParser(prog=sys.argv[0], description="NetCredz Traffic Parser")
	
	group = parser.add_mutually_exclusive_group(required=True)
	group.add_argument("-i", "--interface", help="interface")
	group.add_argument("-f", "--file", help="pcap file path", type=argparse.FileType("rb"))
	parser.add_argument("-d", "--debug", action="store_true", required=False, help="debug mode", default=False)
	parser.add_argument("-v", "--verbose", action="count", required=False, help="verbosity level", default=0)
	parser.add_argument("-c", "--capture-methods", dest="filters", required=False, type=lambda s: s.split(','), help="capture methods", default=["all"])
	parser.add_argument("-r", "--regex", required=False, help="regex string")
	parser.add_argument("-o", "--output", help="output log file path (csv)", default="data_captured.csv")

	return parser.parse_args()


def validate_args(args):
	# validate capture methods
	try:
		if "all" in args.filters:
			return

		for protocol in args.filters:
			if protocol not in CAPTURE_PROTOCOLS:
				raise InvalidProtocolException(protocol)

		return

	except InvalidProtocolException as e:
		log.error(str(e))
		
	except Exception as e:
		log.error(str(e))

	exit(1)

if __name__ == "__main__":
	global log
	global storage

	args = parse_arguments()
	log = Logger(args.verbose, args.debug)
	storage = Storage(args.output)

	validate_args(args)

	if args.interface:
		log.info(f"Listening on {args.interface}")
		capture = Capture(args.interface, args.filters, args.regex)
		capture.listen()
	if args.file:
		capture = Capture(None, args.filters, args.regex)
		pcap_file = args.file.read()
		capture.parse_file(pcap_file)