import requests
import json
import argparse
from subprocess import call
from github import Github

#add geoip?

def argsParser():
	parser = argparse.ArgumentParser()

	parser.add_argument("-u", "--url", type = str, help = validURL.__doc__ + "\n" + subDomainSearch.__doc__)

	parser.add_argument("-d", "--dns", type = str, help = basicDnsInfo.__doc__)

	parser.add_argument("-g", "--github", type = str, help = githubBreach.__doc__) #need to change githubBreach function

	parser.add_argument("-b", "--banner", type = str, nargs = "+", help = bannerGrab.__doc__)

	parser.add_argument("-s", "--safescan", type = str, help = safeScan.__doc__)

	parser.add_argument("-i", "--ip", type = int, help = scanIPRange.__doc__)

	parser.add_argument("-z", "--zone", type = str, help = zoneTransfer.__doc__)

	parser.add_argument("-gd", "--googledork", type = str, help = googleDork.__doc__)

	parser.add_argument("-a", "--all", nargs = "?", help = "Runs all reconnaissance gathering operations on the target")

	return parser.parse_args()

def googleDork(domain):
	"""Attempts various google dorks"""
	site = "site:{}".format(domain)
	#inurl:, allintext:, allinurl:
	dorks = ["ext:csv intext:'password'", "inurl:ftp 'password' filetype:xls"] #add dorks
	for x in dorks:
		query = site + " " + x
		rq = requests.get('http://ajax.googleapis.com/ajax/services/search/web?v=1.0&q=' + query)
		jsonContent = rq.content
		jsonObject = json.loads(jsonContent)
		for index,result in enumerate(jsonObject['responseData']['results']):
			print (str(index+1) + ") " + result['titleNoFormatting'])
			print (result['url'])

def subDomainSearch(url):
	"""Searches for subdomains"""
	call("dig {} soa".format(url)) #dig SOA url
	#call("dig @ns.SOA.com %s axfr" %url)
	call("host -t {}".format(url))

def githubBreach(): #user, password
	"""Checks for sensitive information improperly uploaded to Github""" #add bitbucket and local(cloned) repo support
	#gh = Github(user, password)
	keywords = ['api', 'key', 'username', 'user', 'uname', 'pw', 'password',
                'pass', 'email', 'mail', 'credentials', 'credential', 'login',
				'token', 'secret', 'instance', 'oAuth', 'authToken', '_auth',
				'_password', '_authToken'] #, '.ssh', '.npmrc', '.muttrc', 'config.json', '.gitconfig', '.netrc' 
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
	"""Checks if a URL exists"""
	req = requests.get(url)
	if requests.status_code == 200:
		print("valid URL")
		return True
	else:
		print(requests.status_code)
		return False

def basicDnsInfo(url): #read in a textfile?, whois?
	"""Gathers basic DNS information"""
	try:
		call("whois {}".format(url))
		call("dig {} ANY".format(url))
		#call("dig +nocmd txt chaos VERSION.BIND {} +noall +answer".format(dnsServer)) identify bind version
	except TypeError as e:
		print(e)
		call("whois {}".format(url))
		call("dig {} ANY".format(url))
	except Exception as e:
		print(e)

def zoneTransfer(url):
	"""Attempts a zone transfer"""
	try:
		call("dig {} axfr".format(url))
		call("host -t axfr {}".format(url))
	except Exception as e:
		print(e)

def scanIPRange(start, end):
	"""Scans an IP range with nmap, takes two inputs"""
	call("nmap {start}-{end}".format(start, end))

def bannerGrab(domain, adv): #add user port input for all cmds not just nmap advanced?
	"""Attempts a banner grab"""
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
	"""Attempts an nmap safe scan"""
	call("nmap -sV -sC {}".format(domain))

def main():
	args = argsParser()
	if args.a is not None:
		pass #code
	if args.g is not None:
		githubBreach()
	if args.b is not None:
		bannerGrab(args.b)
	if args.s is not None:
		safeScan(args.s)
	if args.i is not None:
		scanIPRange(args.i)
	if args.z is not None:
		zoneTransfer(args.z)
	if args.gd is not None:
		googleDork(args.gd)
	if args.d is not None:
		basicDnsInfo(args.d)
	if args.u is not None:
		validURL(args.u)
		subDomainSearch(args.u)
	else:
		return False #return universal docstring or help

if __name__ == '__main__':
	main()
