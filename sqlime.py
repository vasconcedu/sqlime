#!/usr/bin/python

# Author:
# Eduardo Vasconcelos (vasconcedu)
# https://vasconcedu.github.io/
#
# Description:
# $sqlime$ is a fuzzer for HTTP mainly targeted at
# finding SQLi flaws, but it can be used just as 
# successfully for other types of fuzzing too. 
#
# Currently supports a single injection point at 
# each request component at a time (i.e. 1 injection
# point at URL, 1 injection point at body, 1 injection
# point at each header) per execution. 
#
# Burp Intruder-like logging available (CSV output).

import requests 
import os 
import json
import getopt
import sys
import time
import random

"""
Globals, all configurable via command line arguments 
"""

METHOD = 'GET'
WORDLIST_FILE = ''
CSV = ''
LOG_RESPONSES = False
ORIGINAL_URL = ''
ORIGINAL_DATA = ''
ORIGINAL_HEADERS_FILE = ''
ORIGINAL_HEADERS = None
TOTAL_REQUESTS = 0
THROTTLE = 200
JITTER = 1000
GREP = ''

class colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

"""
A n00b's gotta look l33t, right? 
"""

def printBanner():
	print """
   \033[93m.===.\033[0m\033[91m   .dBBBBP   dBBBBP  dBP    dBP dBBBBBBb  dBBBP \033[0m\033[93m.===.\033[0m
   \033[93m: |  \033[0m\033[91m   BP       dBP.BP                   dBP        \033[0m\033[93m: |  \033[0m
   \033[93m`===.\033[0m\033[91m   `BBBBb  dBP.BP  dBP    dBP dBPdBPdBP dBBP    \033[0m\033[93m`===.\033[0m
   \033[93m  | :\033[0m\033[91m      dBP dBP.BB  dBP    dBP dBPdBPdBP dBP      \033[0m\033[93m  | :\033[0m
   \033[93m`==='\033[0m\033[91m dBBBBP' dBBBB'B dBBBBP dBP dBPdBPdBP dBBBBP    \033[0m\033[93m`==='\033[0m
   \033[93m  "  \033[0m\033[91m                                                \033[0m\033[93m  "  \033[0m
	"""
	print 'SQLi HTTP fuzzer (but that ain\'t all!)\t~~ by vasconcedu, 2020'

"""
Logging functions
"""

def logToConsole(url, data, headers):
	print '\t' + url
	for header in headers:
		print '\t{}: {}'.format(header, headers[header])
	print '\t' + data + '\n'
	return

def logToCsv(s):
	if CSV != '':
		csv.write(s)

"""
This will send and log requests, and log responses if LOG_RESPONSES is set to True 
"""

def send(method, position, word, url, data, headers, header=None):
	global TOTAL_REQUESTS
	logToCsv(position + '|' + word + '|' + url + '|' + data + '|' + json.dumps(headers) + '|')
	status = None
	responseLength = None
	responseText = None
	if header != None:
		logToCsv(header + '|')
	else:
		logToCsv('|')
	print '\t[+] Performing request no. {}. Method is {}'.format(TOTAL_REQUESTS, method)
	if method == 'GET':
		TOTAL_REQUESTS = TOTAL_REQUESTS + 1
		r = requests.get(url,
			data = data,
			headers = headers
		)
		status = r.status_code
		responseLength = len(r.text)
		responseText = r.text
	elif method == 'POST':
		TOTAL_REQUESTS = TOTAL_REQUESTS + 1
		r = requests.post(url,
			data = data,
			headers = headers
		)
		status = r.status_code
		responseLength = len(r.text)
		responseText = r.text
	prepend = ''
	if status == 200:
		prepend = colors.OKGREEN
	else:
		prepend = colors.WARNING
	print prepend + '\t[+] Received {}, response length is {}'.format(status, responseLength) + colors.ENDC
	if LOG_RESPONSES == True and responseLength > 0:
		responseText = responseText.replace('\n', '')
		print '\t[+] Response text (removed \'\\n\'):\n'
		print '\t' + responseText 
	grep = ''
	if GREP in responseText and GREP != '':
		grep = GREP 
		print '\t[+] Found GREP pattern \'{}\' in response text'.format(grep)
	logToCsv(str(status) + '|' + str(responseLength) + '|' + grep + '\n')
	sleepTime = (THROTTLE + random.randint(0, JITTER))/1000.
	print '\t[+] Sleeping for {} ms...\n'.format(1000*sleepTime)
	time.sleep(sleepTime)
	return 

"""
Removes all $sqlime$ entries from headers
"""

def cleanHeaders():
	headers = ORIGINAL_HEADERS.copy()
	for header in headers:
			headers[header] = headers[header].replace('$sqlime$', '')
	return headers 

"""
Fuzzing functions 
"""

def fuzzUrl(word):
	url = ORIGINAL_URL.replace('$sqlime$', word)
	data = ORIGINAL_DATA.replace('$sqlime$', '')
	headers = cleanHeaders()

	print '\t' + colors.OKBLUE + '[+] ===== Fuzzing QUERY STRING. Request is =====' + colors.ENDC
	logToConsole(url, data, headers)
	send(METHOD, 'URL', word, url, data, headers)
	return

def fuzzHeaders(word):
	headers = ORIGINAL_HEADERS.copy()
	url = ORIGINAL_URL.replace('$sqlime$', '')
	data = ORIGINAL_DATA.replace('$sqlime$', '')
	for header in headers:
		if '$sqlime$' in ORIGINAL_HEADERS[header]:
			headers = ORIGINAL_HEADERS.copy()
			for headerHeader in headers:
				if headerHeader == header:
					headers[headerHeader] = headers[headerHeader].replace('$sqlime$', word)
				else:
					headers[headerHeader] = headers[headerHeader].replace('$sqlime$', '')
			print '\t' + colors.OKBLUE + '[+] ===== Fuzzing HEADER {}. Request is ====='.format(header) + colors.ENDC
			logToConsole(url, data, headers)
			send(METHOD, 'Header', word, url, data, headers, header)
	return

def fuzzData(word):
	url = ORIGINAL_URL.replace('$sqlime$', '')
	data = ORIGINAL_DATA.replace('$sqlime$', word)
	headers = cleanHeaders()

	print '\t' + colors.OKBLUE + '[+] ===== Fuzzing BODY DATA. Request is =====' + colors.ENDC
	logToConsole(url, data, headers)
	send(METHOD, 'Body', word, url, data, headers)	
	return 

def printHelp():
	print '\nUSAGE:\n'
	print 'python sqlime.py --method <HTTP method> --wordlist <wordlist> --url <target URL, use $sqlime$ to define injection point> --data <request body, use $sqlime$ to define injection point> --json <request headers, use $sqlime$ to define injection point> [-r] [--csvlog <CSV output file>]\n'
	print 'OPTIONS:\n'
	print '-h, --help\t\t\tHelp menu (you\'re here!)'
	print '--method <HTTP method>\t\tGET|POST, default is GET'
	print '--wordlist <wordlist>\t\tFuzzing wordlist'
	print '--csvlog <CSV output>\t\tCSV file for Burp Intruder-like output'
	print '-r\t\t\t\tLog responses'
	print '--url\t\t\t\tTarget URL'
	print '--data, --body\t\t\tRequest body'
	print '--json, --headers\t\tRequest headers'
	print '--throttle <throttle>\t\tRequest throttle, default is 200 ms'
	print '--jitter <throttle>\t\tRequest jitter, default is 1000 ms'
	print '--grep <pattern>\t\tResponse grep pattern'

printBanner()

"""
Main script 
"""

try:
	opts, args = getopt.getopt(sys.argv[1:], ":hr", ["help", "logresponses", "method=", "wordlist=", "csvlog=", "url=", "data=", "body=", "json=", "headers=", "throttle=", "jitter=", "grep="])
except Exception as err:
	print colors.FAIL + '\n[-] Incorrect arguments: ' + str(err) + colors.ENDC
	printHelp()
	exit()
for opt, arg in opts:
	if opt in ['-h', '--help']:
		printHelp()
		exit()
	elif opt in ['--method']:
		METHOD = arg
	elif opt in ['--wordlist']:
		WORDLIST_FILE = arg
	elif opt in ['--csvlog']:
		CSV = arg
	elif opt in ['-r']:
		LOG_RESPONSES = True
	elif opt in ['--url']:
		ORIGINAL_URL = arg
	elif opt in ['--data', '--body']:
		ORIGINAL_DATA = arg 
	elif opt in ['--json', '--headers']:
		ORIGINAL_HEADERS_FILE = arg
		try:
			jsonTest = open(ORIGINAL_HEADERS_FILE, 'r')
		except Exception as err:
			print colors.FAIL + '[-] Failed to open request file! ' + str(err) + colors.ENDC
			exit()
		try:
			with open(arg) as jsonFile:
				ORIGINAL_HEADERS = json.load(jsonFile)
		except Exception as err:
			print colors.FAIL + '[-] Request file {} was found, but failed to decode JSON! '.format(ORIGINAL_HEADERS_FILE) + str(err) + colors.ENDC
			exit()
	elif opt in ['--throttle']:
		THROTTLE = int(arg)
	elif opt in ['--jitter']:
		JITTER = int(arg)
	elif opt in ['--grep']:
		GREP = arg


if (ORIGINAL_URL == ''):
	print colors.FAIL + '[-] Need URL, I ain\'t that clever!' + colors.ENDC
	exit()
if (WORDLIST_FILE == ''):
	print colors.FAIL + '[-] Need wordlist, I ain\'t that clever!' + colors.ENDC
	exit()
try:
	wordlist = open(WORDLIST_FILE, 'r')
except Exception as err:
	print colors.FAIL + '[-] Failed to open wordlist! ' + str(err) + colors.ENDC
	exit()

words = wordlist.readlines()
wordlist.close()

if (CSV != ''):
	os.system('touch ' + CSV)
	csv = open(CSV, 'w')
	csv.write('position|word|url|data|headers|header_if_headers|http_status|response_length|response_grep\n')

print colors.OKBLUE + '\n\n[+] ===== All set. Parameters are as follows =====\n\n' + colors.ENDC
print '[+] Method is {}'.format(METHOD)
print '[+] Using wordlist {}'.format(WORDLIST_FILE)
if CSV != '':
	print '[+] Dumping Burp Intruder-like log to CSV at {}'.format(CSV)
print '[+] LOG_RESPONSES is set to {}'.format(LOG_RESPONSES)
print '[+] Original URL is {}'.format(ORIGINAL_URL)
if ORIGINAL_DATA != '':
	print '[+] Original body data is {}'.format(ORIGINAL_DATA)
print '[+] Original request headers read from {}. Original request headers are:'.format(ORIGINAL_HEADERS_FILE)
for header in ORIGINAL_HEADERS:
	print '[+]\t{}: {}'.format(header, ORIGINAL_HEADERS[header])
print '[+] Request throttle is set to {}'.format(THROTTLE)
print '[+] Request jitter is set to {}'.format(JITTER)
if GREP != '':
	print '[+] Response grep pattern is set to \'{}\''.format(GREP)
print '\n'

answer = ''
while answer != 'Y' and answer != 'n':
	answer = raw_input(colors.UNDERLINE + '[?] Start fuzzing with parameters above? (Y/n)~> ' + colors.ENDC)
if answer == 'n':
	print '[+] Bye.'
	exit()

print colors.OKBLUE + '[+] ===== Okey-dokey. Fuzzer is starting ====='+ colors.ENDC 

for word in words:

	word = word.strip()
	
	print colors.OKBLUE + '\n\n[+] ===== Fuzzing request with word {} =====\n\n'.format(word) + colors.ENDC

	if '$sqlime$' in ORIGINAL_URL:
		fuzzUrl(word)
	fuzzHeaders(word)
	if '$sqlime$' in ORIGINAL_DATA:
		fuzzData(word)

print colors.OKBLUE + '[+] Total requests: {}'.format(TOTAL_REQUESTS)
csv.close()
if CSV != '':
	print '[+] Burp Intruder-like log dumped to CSV at {}'.format(CSV)
print colors.OKBLUE + '[+] All done. Bye.'+ colors.ENDC
