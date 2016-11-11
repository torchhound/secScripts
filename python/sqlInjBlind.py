import mechanize

browser = mechanize.browserowser()

sqlInj = []

def formAttack(page):
	'''Find all forms on a page and submit a sql injection attack to each of them then record responses to a text file.'''
	try:
		browser.open(page)
		forms = browser.forms()
		for form in forms:
			for atk in sqlInj:
				#fill out and submit an arbitrary form with sqlInj
				browser.select_form(name="form")
				browser.form = atk
				response = browser.submit()
				content = response.get_data() #would be nice to have detection other than manually reading a textfile
				with open("responses.txt", "a") as file:
					file.write(content)
				browser.close()

	except urllib2.HTTPError as e:
		print("{}: {}".format(e.code, e.msg))
	except IOError as e:
		print(e)
	except Exception as e:
		print(e)

def urlAttack(page):
	'''Concatenates sql injections to urls'''
	try:
		for atk in sqlInj:
			browser.open(page + atk)
	except IOError as e:
		print(e)
	except Exception as e:
		print(e)

def main():
	page = input("Input url: ")
	formOrUrl = input("Blind form attack or blind url attack? F/U ")
	if formOrUrl == "F":
		formAttack(page)
	elif formOrUrl == "U":
		urlAttack(page)
	else:
		print("Unknown input")

if __name__ == '__main__':
	main()
