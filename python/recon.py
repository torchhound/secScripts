import requests
import json
from subprocess import call
from github import Github

def googleDork(domain):
	'''Attempts various google dorks'''
	site = "site:{}".format(domain)
	#inurl:
	dorks = ["ext:csv intext:'password'", ] #add dorks
	for x in dorks:
		query = site + " " + x
		rq = requests.get('http://ajax.googleapis.com/ajax/services/search/web?v=1.0&q=' + query)
		jsonContent = rq.content
		jsonObject = json.loads(jsonContent)
		for index,result in enumerate(jsonObject['responseData']['results']):
			print (str(index+1) + ") " + result['titleNoFormatting'])
			print (result['url'])

def subDomainSearch(url):
	'''Searches for subdomains'''
	call("dig {} soa".format(url)) #dig SOA url
	#call("dig @ns.SOA.com %s axfr" %url)
	call("host -t {}".format(url))

def githubBreach(): #user, password
	'''Checks for sensitive information improperly uploaded to Github'''
	#gh = Github(user, password)
	keywords = ['api', 'key', 'username', 'user', 'uname', 'pw', 'password',
                'pass', 'email', 'mail', 'credentials', 'credential', 'login',
				'token', 'secret', 'API', 'instance']
	while True:
		userGuess = input("Input an organization or user or a guess: ")
		try:
			print(github.MainClass.Github.get_organization(userGuess))
			print(github.Organization.userGuess.get_repos())
		except BaseException as e: #need a better exception
			print(e)
			continue
		except Exception as e:
			print(e)
			continue

def validURL(url):
	'''Checks if a URL exists'''
	req = requests.get(url)
	if requests.status_code == 200:
		print("valid URL")
		return True
	else:
		print(requests.status_code)
		return False

def basicDnsInfo(url): #read in a textfile?
	'''Gathers basic DNS information'''
	try:
		call("whois {}".format(url))
		call("dig {} ANY".format(url))
	except TypeError as e:
		print(e)
		call("whois {}".format(url))
		call("dig {} ANY".format(url))
	except Exception as e:
		print(e)

def zoneTransfer(url):
	try:
		call("dig {} axfr".format(url))
		call("host -t axfr {}".format(url))
	except Exception as e:
		print(e)

def scanIPRange(start, end):
	'''Scans an IP range with nmap'''
	call("nmap {start}-{end}".format(start, end))

def bannerGrab(domain, adv): #add user port input for all cmds not just nmap advanced?
	'''Attempts a banner grab'''
	call("nmap -sV {}".format(domain))
	call("telnet {} 80".format(domain))
	call("nc -v {} 80".format(domain))
	if adv == "y":
		userPort = input("Choose port: ")
		userAgression = input("Agressive: y/n ")
		if userAgression == "y":
			call("nmap -A -sV --version-intensity 5 -p {} -v --script banner {}".format(userPort, domain))
		elif userAgression == "n":
			call("nmap -sV -p {} -v --script banner {}".format(userPort, domain))
		else:
			print("Invalid")

def safeScan(domain):
	'''Attempts an nmap safe scan'''
	call("nmap -sV -sC {}".format(domain))

def main(): #add argument parser
	userArg = input("Choose url, dns, github, banner, safescan, ip, zone, or all: ")
	if userArg == "url":
		userURL = input("Input URL to check: ")
		validURL(userURL)
		subDomain(userURL)
	elif userArg == "dns":
		userDNS = input("Input URL or IP: ")
		basicDnsInfo(userDNS)
	elif userArg == "ip":
		userIPS = input("Input the complete starting IP address: ")
		userIPE = input("Input the final quad of the IP address: ")
		scanIPRange(userIPS, userIPE)
	elif userArg == "github":
		#userGithubU = input("Input github username: ")
		#userGithubP = input("Input github password: ")
		githubBreach() #userGithubU, userGithubP
	elif userArg == "banner":
		userDomain = input("Input domain to banner grab: ")
		userAdvA = input("Advanced grab: y/n ")
		bannerGrab(userDomain, userAdv)
	elif userArg == "safescan":
		userDomainSS = input("Input domain to safely scan: ")
		safeScan(userDomainSS)
	elif userArg == "zone":
		userZone = input("Input URL to attempt zone transfer on: ")
		zoneTransfer(userZone)
	elif userArg == "all":
		userDomainA = input("Input domain: ")
		if validURL(userDomainA) == True: #do this check for other args or superfluous
			userAdvA = input("Advanced grab: y/n ")
			bannerGrab(userDomainA, userAdvA)
			userIPSA = input("Input the complete starting IP address: ")
			userIPEA = input("Input the final quad of the IP address: ")
			scanIPRange(userIPSA, userIPEA)
			githubBreach()
			basicDnsInfo(userDomainA)
			subDomain(userDomainA)
		else:
			print("Invalid Input")
	else:
		return False

if __name__ == '__main__':
	main()
