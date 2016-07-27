import requests, json
from subprocess import call
from github import Github

def googleDork(domain):
	site = "site:%s" %domain
	dorks = []
	for x in dorks:
		query = site + " " + x
		rq = requests.get('http://ajax.googleapis.com/ajax/services/search/web?v=1.0&q=' + query)
		jsonContent = rq.content
		jsonObject = json.loads(jsonContent)
		for index,result in enumerate(jsonObject['responseData']['results']):
			print (str(index+1) + ") " + result['titleNoFormatting'])
			print (result['url'])
			
def subDomainSearch(url):
	call("dig %s soa" %url) #dig SOA url
	#call("dig @ns.SOA.com %s axfr" %url)
	call("host -t %s" %url)

def githubBreach(): #user, password
	#gh = Github(user, password)
	while True:
		userGuess = input("Input an organization or user or a guess: ")
		try:
			print(github.MainClass.Github.get_organization(userGuess))
			print(github.Organization.userGuess.get_repos())
		except BaseException: #need a better exceptionr
			continue

def validURL(url):
	req = requests.bet(url)
	if requests.status_code == 200:
		print("valid URL")
		return True
	else:
		print(requests.status_code)
		return False

def dnsInfo(url):
	try:
		call("whois %s" %url)
		call("dig %s ANY" %url)
	except TypeError:
		call("whois %d" %url)
		call("dig %d ANY" %url)

def scanIPRange(start, end):
	call("nmap {start}-{end}".format(start, end)) #format function vs percent

def bannerGrab(domain, adv): #add user port input for all cmds not just nmap advanced?
	call("nmap -sV %s" %domain)
	call("telnet %s 80" %domain)
	call("nc -v %s 80" %domain) 
	if adv == "y":
		userPort = input("Choose port: ")
		userAgression = input("Agressive: y/n ")
		if userAgression == "y":
			call("nmap -A -sV --version-intensity 5 -p %d -v --script banner %s" %userPort, domain)
		elif userAgression == "n":
			call("nmap -sV -p %d -v --script banner %s" %userPort, domain)
		else:
			print("Invalid")
	
def safeScan(domain):
	call("nmap -sV -sC %s" %domain)
	
def main():
	userArg = input("Choose url, dns, github, banner, safescan, ip, or all: ")
	if userArg == "url": 
		userURL = input("Input URL to check: ")
		validURL(userURL)
		subDomain(userURL)
	elif userArg == "dns":
		userDNS = input("Input URL or IP: ")
		dnsInfo(userDNS)
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
	elif userArg == "all":
		userDomainA = input("Input domain: ")
		if validURL(userDomainA) == True: #do this check for other args or superfluous
			userAdvA = input("Advanced grab: y/n ")
			bannerGrab(userDomainA, userAdvA)
			userIPSA = input("Input the complete starting IP address: ")
			userIPEA = input("Input the final quad of the IP address: ")
			scanIPRange(userIPSA, userIPEA)
			githubBreach()
			dnsInfo(userDomainA)
			subDomain(userDomainA)
		else:
			print("Invalid Input")
	else:
		return False

if __name__ == '__main__':
	main()
