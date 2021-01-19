import re
import os
import string
import requests
import pyinputplus as pyinp
from pysafebrowsing import SafeBrowsing
from collections import Counter

def findingUrls(x):
  inputString = x
  links = re.findall('http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', inputString)
  return links
  #end
def parseURL(url):
	sub_domain1 = re.findall(('http[s]?://+'),url)[0]
	sub_domain = url.replace(sub_domain1,'')
	sub_domain = sub_domain.split('/')[0]
	domain = '.'.join(sub_domain.split('.')[1:])
	return domain

# Did you mean algorithm
def words(text):
	return re.findall(r'\w+', text.lower())

WORDS = Counter(words(open('brand.txt').read()))

def P(word, N=sum(WORDS.values())):
    "Probability of `word`."
    return WORDS[word] / N

def correction(word):
    "Most probable spelling correction for word."
    return max(candidates(word), key=P)

def candidates(word):
    "Generate possible spelling corrections for word."
    return (known([word]) or known(edits1(word)) or known(edits2(word)) or [word])

def known(words):
    "The subset of `words` that appear in the dictionary of WORDS."
    return set(w for w in words if w in WORDS)

def edits1(word):
    "All edits that are one edit away from `word`."
    letters    = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
    splits     = [(word[:i], word[i:])    for i in range(len(word) + 1)]
    deletes    = [L + R[1:]               for L, R in splits if R]
    transposes = [L + R[1] + R[0] + R[2:] for L, R in splits if len(R)>1]
    replaces   = [L + c + R[1:]           for L, R in splits if R for c in letters]
    inserts    = [L + c + R               for L, R in splits for c in letters]
    return set(deletes + transposes + replaces + inserts)

def edits2(word):
    "All edits that are two edits away from `word`."
    return (e2 for e1 in edits1(word) for e2 in edits1(e1))

#end

#checking the digits
def digitcheck(x):
  check = x.isdigit()
  if check == True:
    return 1
  else:
    return 0

#duplicate REMOVAL
def Remove(duplicate):
    final_list = []
    for num in duplicate:
        if num not in final_list:
            final_list.append(num)
    return final_list

def clear():
    os.system('cls' if os.name == 'nt' else 'echo -e \\\\033c')

# Histogram for the known phishing sites of the companies
def number():
  name = input("Enter the company name:")
  file = name + '.txt'

  url = []

  try:
    fopen = open("brand/" + file)
    for i in fopen:
        i = i.rstrip()
        url = i.split()
  except:
    print("The company does not exist in our database.....")

  histogram = dict()

  for c in url:
    histogram[c] = histogram.get(c,0) + 1

  for i in histogram:
    print(i, " --> ",histogram[i])


# Main function


#phishing & blacklisted sites from openphish
openphish_urls_data = "openphish.txt"
openphish_urls = open(openphish_urls_data,'r+')

# Making 62 lakh urls list:
phishfile = 'phishtank.txt'
phishfile_read = open(phishfile)
phishfile = phishfile_read.read()
phishtank_urls = findingUrls(phishfile)

#Authentic Websites sites database
try:
    genuine_websites = open('websites.txt')
except:
    print('websites.txt not present')

#brand name database
Branding = "brand.txt"
brand_names = open(Branding,'r+')

#English words database
english_dic_words = open("word.txt")
#end

#all the lists
english_words_list = []
openphish_urls_list = []
brand_database = []
msg_words_list = []
brand_names_list = []
companies = []
genuine_websites_list = []


#list for brand name
for name in brand_names:
  name = name.lower().rstrip()
  name = name.translate(name.maketrans('','',string.punctuation))
  brand_names_list.append(name)

#list for english WORDS
for i in english_dic_words:
  i = i.lower().rstrip()
  i = i.translate(i.maketrans('','',string.punctuation))
  english_words_list.append(i)

#All english words except popular brand names
for i in english_words_list:
  if i in brand_names_list:
  	english_words_list.remove(i)


words_without_brand = english_words_list
#phishing sites database
for line in openphish_urls:
  line = line.rstrip()
  openphish_urls_list.append(line)

# Authentic Websites sites check
for url in genuine_websites:
    url = url.strip()
    genuine_websites_list.append(url)


#input
msg = """
Learn Machine learning with AWS CLoud at 
Enroll today https://aws.amazon.com/machine-learning/mlu/

"""

# Processing the msg
# --------------------
#finding urls in the message stored in links
links_in_input = findingUrls(msg)

#removing links and making a list of words name MESSAGE
input_words = msg.split()

for i in input_words:
  if i in links_in_input:
    input_words.remove(i)

msg_withouturl = input_words

for word in msg_withouturl:
  word = word.translate(word.maketrans('','',string.punctuation))
  word = word.lower()
  msg_words_list.append(word)

for i in reversed(msg_words_list):
  if i.isdigit() == 1:
    msg_words_list.remove(i)
  if i in words_without_brand:
  	msg_words_list.remove(i)	#Words that are not in dictionary or are Brand Names 

#Removing multiple occurences of same brand name
msg_words_list = Remove(msg_words_list)

# did you mean on the msg_words_list
for i in msg_words_list:
  correct = correction(i)
  companies.append(correct)
companies = Remove(companies)

# If its a persons name its not in word directory or a company name
for i in companies:
  if i not in words_without_brand:
    if i not in brand_names_list:
      companies.remove(i)


#result ..................................................................

EndResult = 1

for i in links_in_input:
  rcheck = 0

  # WHOIS API.......
  response = requests.get("https://jsonwhois.com/api/v1/whois",
              headers={
                "Accept": "application/json",
                "Authorization": "Token token=1d1279b6c95fa95219c040f4f3b6a936"
              },
              params={
                "domain": i
              })
  data = response.json()
  try:
    regis = data["registrar"]
  except:
    pass
  try:
    regiContacts = data["registrant_contacts"]
  except:
    pass

#phishtank & openphish dataset
  if i in phishtank_urls:
    print("This is a phishing site : " , i)
    try:
       	print('The main domain:', data['domain'])
    except Exception as e:
       	pass
    try:
      reg = regiContacts[0]
      print("Organization name: ",reg['organization'])
    except:
      pass
    rcheck = 1

  elif i in openphish_urls_list:
    print("This is a phishing site : " , i)
    try:
        print('The main domain:', data['domain'])
    except Exception as e:
       	pass
    try:
      reg = regiContacts[0]
      print("Organization name: ",reg['organization'])
    except:
      pass
    rcheck = 1

  else:
  	try:
  		s = SafeBrowsing("AIzaSyDZAITEKchXC5BStNgv3guaQY_IYIiKoKg") # Google Safebrowing API
  		print(i)
  		r = s.lookup_urls([i])
  		safebrowsing_check = r[i]['malicious']
  		if(safebrowsing_check == True):
  			print("This is a phishing site : " , i)
  			try:
  				print('The main domain:', data['domain'])
  			except Exception as e:
  				pass
  			try:
  				reg = regiContacts[0]
  				print("Organization name: ",reg['organization'])
  			except:
  				pass
  			rcheck = 1
  	except Exception as e:
  		pass
  if rcheck == 1:
  	brand_database.append(i)

if len(links_in_input) > 0 and rcheck == 0:
    if True:
        print("This appears to be a safe Url")
        try:
        	print('The main domain:', data['domain'])
        except Exception as e:
        	pass
        try:
            reg = regiContacts[0]
            print("Organization name: ", reg['organization'])
        except:
            pass

if len(links_in_input) == 0:
    print('This does not contain any URL....\n')
    EndResult = 0

if rcheck == 1:
  if len(companies)==1:
    print ('The company its trying to masquerade is:',companies[0].capitalize())

  elif len(companies) == 0:
    pass

  else:
    print("The companies its trying to masquerade are:")
    i = 0
    while i<len(companies):
      print(companies[i].capitalize())
      i = i+1


#for database creation .....................................................................

if EndResult==1:
  if len(companies) == 0:
    pass

  else:
    i = 0
    for i in companies:
      name = i+'.txt'
      BrandStore = open("./brand/" + name,'a+')
      for link in brand_database:
          BrandStore.write(link+"            ")
      BrandStore.close()

# End .......................................................................................

try:
  SiteHistogram = pyinp.inputYesNo("\nDo want to see the highest used site for a company, Yes or No: ",limit = 2)
except:
  print("Not valid")

if SiteHistogram == 'yes':
  clear()
  check = number()
  print("\n\nThank you for using PhishFind........\n\n")
else:
  clear()
  print("\nThank you for using PhishFind.........\n")
