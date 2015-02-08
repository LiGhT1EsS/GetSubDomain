#!/usr/bin/python
#coding:utf-8

import socket
import itertools
import string
import threading
import time
import sys, getopt, os
import random
from Queue import Queue
import urllib

WorkQueue = Queue()
LogQueue = Queue()
domainLock = threading.Lock()
thread_list = []
MakeFinished = 0
WriteFinished = 0
ScanFinished = 0

class WriteLogFile(threading.Thread):
	def __init__(self, url):
		threading.Thread.__init__(self)
		self.url = url

	def run(self):
		global LogQueue
		global WriteFinished
		global ScanFinished
		filename = self.url + ".txt"
		f = open(filename, "w+")
		while True:
			for i in thread_list:
				if not i.is_alive():
					ScanFinished = 1
				elif i.is_alive():
					ScanFinished = 0
			#print ScanFinished, LogQueue.empty()
			if ScanFinished == 1 and LogQueue.empty():
				break
			data = LogQueue.get()
			if data == "Nothing Found!":
				continue
			f.write(data + "\n")
		f.close()
		WriteFinished = 1

	def stop(self):
		global WriteFinished
		WriteFinished = 1
		try:
			f.close()
		except Exception, e:
			pass



class MakeDomainPrefix(threading.Thread):
	"""docstring for MakeDomainPrefix"""
	def __init__(self, maxlen):
		threading.Thread.__init__(self)
		self.maxlen = maxlen

	def run(self):
		global WorkQueue
		global MakeFinished
		# 生产子域名并放到队列里
		for i in range(1, int(self.maxlen)+1):
			for j in itertools.product(string.ascii_lowercase + string.digits, repeat=i):
				line = ''.join(str(x) for x in j)
				WorkQueue.put(line)
				#print "put " + line
		MakeFinished = 1


class FindSubdomain(threading.Thread):

	def __init__(self, url):
		threading.Thread.__init__(self)
		self.url = url

	def run(self):
		# 从队列中取出并进行操作
		global WorkQueue
		global LogQueue
		global MakeFinished
		global g_http
		#print "thread start!"
		# print WorkQueue.qsize()
		# print MakeFinished
		while True:
			#print "thread_loop"
			# 获得互斥锁
			if domainLock.acquire():
				if WorkQueue.empty() and MakeFinished:
					domainLock.release()
					break

				domain_prefix = WorkQueue.get()
				# 释放锁
				domainLock.release()

			domain = domain_prefix + "." + self.url
			#print "[-] Try " + domain
			try:
				target_addr = socket.getaddrinfo(domain, 'http')[0][4][0]
				# 如果遇到fake ip就pass
				if target_addr == "1.1.1.1":
					pass
				else:
					if g_http == True:
						#print "try 404"
						s = urllib.urlopen('http://'+domain)
						statusCode = s.getcode()
						#print statusCode
						s.close()
						s = None
						#print "close ok"
						if statusCode == 404:
							#print domain
							continue
						else:
							print "[+] Found " + domain
							LogQueue.put(domain+":"+target_addr)
					else:
						# 现在获取到的是真IP
						print "[+] Found " + domain
						# 放到文件队列中等待被写入文件
						LogQueue.put(domain+":"+target_addr)
			except Exception, e:
				pass
			if MakeFinished and WorkQueue.empty():
				break
		#print "thread end"



def usage():
	help_message = \
'''
 -h - Show this messages
 -u - Set the domain, such as qq.com
 -l - Set the subdomain length, default is 4
 -t - Set the thread number, default is 10
 -e - Set if use HTTP code to verify, default is False
'''
	print help_message

makeDomainPrefix = None
writeLogFile = None

def work(url, threadNum, length):
	global makeDomainPrefix
	global writeLogFile

	# 创建生产线程
	makeDomainPrefix = MakeDomainPrefix(length)
	makeDomainPrefix.start()

	# 创建消费线程
	for i in range(int(threadNum)):
		thread_list.append(FindSubdomain(url))
		thread_list[i].start()

	print "[+] Thread init done."

	# 创建写文件线程
	writeLogFile = WriteLogFile(url)
	writeLogFile.start()


g_url = ""
g_thread = 10
g_len = 4
g_http = False


if __name__ == '__main__':
	print \
	'''
		 ____        _     ____                        _       
		/ ___| _   _| |__ |  _ \  ___  _ __ ___   __ _(_)_ __  
		\___ \| | | | '_ \| | | |/ _ \| '_ ` _ \ / _` | | '_ \ 
		 ___) | |_| | |_) | |_| | (_) | | | | | | (_| | | | | |
		|____/ \__,_|_.__/|____/ \___/|_| |_| |_|\__,_|_|_| |_|
		                                 By Lightless                      
	'''
	if len(sys.argv) == 1:
		usage()
		exit()

	try:
		opts, args = getopt.getopt(sys.argv[1:], "u:vl:vt:vhe")
	except Exception, e:
		usage()
		exit()

	for o, a in opts:
		if o == "-u":
			g_url = a
		elif o == "-l":
			g_len = a
		elif o == "-t":
			g_thread = a
		elif o == "-h":
			usage()
			exit()
		elif o == "-e":
			g_http = True

	if g_url == "":
		print "[+] No URL Found!"
		exit()		

	print "[+] Scan start!"
	work(g_url, g_thread, g_len)
	while True:
		time.sleep(1)
		# print "================================="
		# print LogQueue.empty(), WorkQueue.empty()
		# print WriteFinished, ScanFinished, MakeFinished
		# print writeLogFile.is_alive(), makeDomainPrefix.is_alive()
		# for i in thread_list:
		# 	print i.is_alive()
		# print "================================="

		for i in thread_list:
			if i.is_alive():
				ll = 0
			elif not i.is_alive():
				ll = 1
		if ll == 1:
			ScanFinished = 1
			LogQueue.put("Nothing Found!")

		# if ScanFinished == 1 and LogQueue.empty():
		# 	WriteFinished = 1
		if WriteFinished and ScanFinished and MakeFinished:
			break
	print "[+] Scan Finished! Write log to %s.txt" % g_url

	exit()