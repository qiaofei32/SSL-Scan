#encoding=utf8

import warnings
warnings.filterwarnings("ignore")
import os
import ssl
import sys
import time
import json
import socket
import struct
import pandas
import hashlib
import thread
import threading
import logging
import numpy
from sklearn.externals import joblib

logging.basicConfig()
logger = logging.getLogger("")
# logger.setLevel(logging.DEBUG)
logger.setLevel(logging.INFO)

global THREAD_NUM
THREAD_NUM = 250

def ip2int(addr):
	return struct.unpack("!I", socket.inet_aton(addr))[0]

def int2ip(addr):
	return socket.inet_ntoa(struct.pack("!I", addr))

def format_fingerprint(finger_print):
	finger_print = list(finger_print)
	result = []
	for index in range(len(finger_print)):
		if index % 2 == 0:
			result.append(finger_print[index] + finger_print[index + 1])
	result = ":".join(result)
	return result.upper()

def get_ssl_cert_info(addr, ssl_version=ssl.PROTOCOL_TLSv1_2):
	try:
		sock = socket.create_connection(addr, timeout=1.0)
		# context = ssl._create_unverified_context()
		context = ssl.SSLContext(protocol=ssl_version)
		# context = ssl.create_default_context()

		context.verify_mode = ssl.CERT_REQUIRED
		# context.verify_mode = ssl.CERT_NONE
		context.load_default_certs()

		sslsock = context.wrap_socket(sock, server_hostname=addr[0])

		cert_info = sslsock.getpeercert(binary_form=False)
		# cert_info = json.dumps(cert_info, indent=2, sort_keys=True)

		cert_fingerprint = sslsock.getpeercert(binary_form=True)
		cert_fingerprint = hashlib.sha1(cert_fingerprint).hexdigest()
		cert_fingerprint = format_fingerprint(cert_fingerprint)

		output = "%-15s %s   %s" %(addr[0], cert_fingerprint, cert_info["subjectAltName"][0][-1])
		logger.info(output)
		return cert_info, cert_fingerprint
	except Exception as e:
		# print e
		return None

def scan_N_addr(ip_list):
	for int_ip in ip_list:
		ip = int2ip(int_ip)
		logger.debug(ip)
		ret = get_ssl_cert_info((ip, 443))
	global NUM_Lock
	NUM_Lock = NUM_Lock -1

def scan_range(ip_s, ip_e):
	global NUM_Lock
	global THREAD_NUM
	int_ip_s = ip2int(ip_s)
	int_ip_e = ip2int(ip_e)
	ip_all_list = range(int_ip_s, int_ip_e)
	logger.debug("IP addr number: %d" %(len(ip_all_list)))
	N = 50
	for i in range(0, len(ip_all_list), N):
		ip_list = ip_all_list[i: i+N]
		while NUM_Lock >= THREAD_NUM:
			time.sleep(0.5)
		# thread.start_new_thread(scan_N_addr, (ip_list, ))
		thread = threading.Thread(target=scan_N_addr, args=(ip_list, ))
		# thread.setDaemon(False)
		thread.start()
		NUM_Lock += 1

if __name__ == "__main__":
	global NUM_Lock
	NUM_Lock = 0
	time_s = time.time()
	logger.info("scan start!")

	df = pandas.read_csv("cn.csv", sep=",")
	values = df.values.tolist()
	# numpy.random.shuffle(values)
	values.reverse()
	file_name = "done.dat"
	if os.path.exists(file_name):
		done_index = joblib.load(file_name)
	else:
		done_index = 0
	for index, row in enumerate(values):
		if index < done_index:continue
		ip_s, ip_e, ip_num, ip_issue = row
		logger.info("scan ip_range: %s --> %s" %(ip_s, ip_e))
		scan_range(ip_s, ip_e)
		joblib.dump(index, file_name, compress=3)

	# ip_s = "180.97.0.0"
	# ip_e = "180.97.33.255"
	# scan_range(ip_s, ip_e)

	time.sleep(5)
	b_stoped = 0
	while NUM_Lock:
		if NUM_Lock <= 5:
			b_stoped += 1
			thread_count = thread._count()
			if thread_count == 0:
				break
			logger.info("thread count: %d" % (thread_count))
		if b_stoped > 120:
			break
		time.sleep(1)
	time_e = time.time()
	logger.info("cost: %ds" %(time_e-time_s))