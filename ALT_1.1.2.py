from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.alert import Alert
from subprocess import Popen, PIPE
from selenium.common.exceptions import TimeoutException
import unicodedata,time,os,sys,WConio,random,ConfigParser,hashlib,random,shutil,platform,socket

screen=sys.stdout

def update_screen(text):
	
	text = text.strip()
	WConio.clreol()
	if len(text) > 75:
		#pass
		text = str(text[:74])+ "~"
	screen.write("\r"+str(text))

def loading_screen ():
	WConio.clrscr()
	WConio.settitle('ALT ' + version )	
	WConio.textcolor(WConio.LIGHTRED)
	print "\t ___           _    _                 _             _           "
	print "\t(  _`\        (_ ) ( )_              ( )           ( )          "
	print "\t| | ) |   __   | | | ,_)   _ _       | |       _ _ | |_     ___ "
	print "\t| | | ) /'__`\ | | | |   /'_` )      | |  _  /'_` )| '_`\ /',__)"
	print "\t| |_) |(  ___/ | | | |_ ( (_| |      | |_( )( (_| || |_) )\__, \ "
	print "\t(____/'`\____)(___)`\__)`\__,_)      (____/'`\__,_)(_,__/'(____/ "

	WConio.textcolor(WConio.RED)
	print'\n\t\t _    ___   \ /                            _ '
	print'\t\t|_||   |     V  _  __ _  o  _ __    /|    / \ '
	print'\t\t| ||__ |       (/_ | _>  | (_)| |    |  o \_/ \n'
	WConio.textcolor(WConio.WHITE)
	count=0
	letter=""
	string=""
	while count <> 1:
		letters=['a','b','d','e','g','h','i','j','k','l','m','n','o','t','v','u','x','y','z','!','"','.','*','#','?','-','+','_','0','2','3','5','7','9','>','<']
		letter=letters[random.randint(0,len(letters)-1)]
		if letter == "l" and "L" not in string:
			string = 'L'
		elif string == "L":
			if letter == "o":
				string = string+ 'o'
		elif string == "Lo":
			if letter == "a":
				string = string+ 'a'
		elif string == "Loa":
			if letter == "d":
				string = string+ 'd'
		elif string == "Load":
			if letter == "i":
				string = string+ 'i'
		elif string == "Loadi":
			if letter == "n":
				string = string+ 'n'
		elif string == "Loadin":
			if letter == "g":
				string = string+ 'g'
		elif string == "Loading":
			if letter == ".":
				string = string+ '.'
		elif string == "Loading.":
			if letter == ".":
				string = string+ '.'
		elif string == "Loading..":
			if letter == ".":
				string = string+ '.'
		if string == "Loading...":
			count+=1
			update_screen(string)
			time.sleep(0.5)
			string =""

			
		else:
			update_screen(string+letter)
		time.sleep(0.01)

def dismiss_alert():
	for x in range(0,3):	
		try:
			alert = driver.switch_to_alert()
			alert.dismiss()
		except:
			pass
		time.sleep(0.8)

def directory_list(dir,run):
	global cant_access
	cant_access=[]
	try:																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																													
		files = os.listdir(dir)#directory listing
		for current_file in files: 
			path_full = dir + current_file
			if current_file != "System Volume Information":
				try:
					if os.path.isdir(path_full):
						path = dir + current_file + "/"
						directory_list(path,run)
				
					else:
				
						path = dir + current_file # put together the files path to checksum
						if run == "1" :
							files_before.append(path)
						
							update_screen("Looking at : " + str(path))
						else:
							files_after.append(path)
							update_screen("Looking at : " + str(path))
				except IOError:
						print "Denied" # this is most likely to happen on a directory in use
	except:
		cant_access.append(dir)		
	
def log_file(logfile,data):
	log_file= open('logs\\'+logfile,'a')
	log_file.write(unicodedata.normalize('NFKD', unicode(data)).encode('ascii','ignore')+'\n')
	log_file.close()
	
def check_link(link):
		global driver,title,files_before, files_after, fiddler, fiddler_out, pcap, pcap_out, procmon, procmon_out, link_file, wanderer_recursion, wanderer_out, crawler_search_term,pmls
		files_before = []
		files_after = []
		changed_files =[]
		errors=[]
	#try:
		print '\n-Current Link : '+link +'\n'
		print '\nAnalyzing Files Currently On System\n'
		directory_list("C:\\","1")
		print '\n'
		
		for error in cant_access:
			print '\n\n\t[ Error could not process ' + error + ' ]'
		errors=[] #empty the errors aray after printing to screen...
		#start mons here
		#get the md5 of site to create unique log file name...easier than taking out every problematic character
		hash = ""
		hash = hashlib.md5()
		hash.update(link)
		link_md5= hash.hexdigest()
		if "{site_md5}" in fiddler_out: 
			fiddler_log= fiddler_out.replace("{site_md5}",str(link_md5)+'\\'+str(link_md5)) 
			
			if not os.path.exists(fiddler_out.replace("{site_md5}",str(link_md5)).split(".")[0]):
				os.mkdir(fiddler_out.replace("{site_md5}",str(link_md5)).split(".")[0])
				
		if "{site_md5}" in procmon_out:
			procmon_log = procmon_out.replace("{site_md5}",str(link_md5)+'\\'+str(link_md5))
			if not os.path.exists(procmon_out.replace("{site_md5}",str(link_md5)).split(".")[0]):
				os.mkdir(procmon_out.replace("{site_md5}",str(link_md5)).split(".")[0])
		if "{site_md5}" in pcap_out:
			pcap_log = pcap_out.replace("{site_md5}",str(link_md5)+'\\'+str(link_md5))
			if not os.path.exists(pcap_out.replace("{site_md5}",str(link_md5)).split(".")[0]):
				os.mkdir(pcap_out.replace("{site_md5}",str(link_md5)).split(".")[0])
		###
		if fiddler == True :
			WConio.textcolor(WConio.GREEN)
			print 'Starting Fiddler'
			WConio.textcolor(WConio.WHITE)
			os.system("mon_launch.exe open fiddler")
		if procmon == True :
			WConio.textcolor(WConio.GREEN)
			print 'Starting Procmon'
			WConio.textcolor(WConio.WHITE)
			os.system('mon_launch.exe open procmon "'+procmon_start_command+'" "'+ procmon_log+'"')
		if pcap == True :
			WConio.textcolor(WConio.GREEN)
			print 'Starting WinDump\n'
			os.system('mon_launch.exe open windump "'+pcap_start_command+'" "'+ pcap_log+'"')
			WConio.textcolor(WConio.WHITE)
		
		dismiss_alert()
		timeout_error=0
		try:
			driver.set_page_load_timeout(int(timeout))
			driver.get(link)
			time.sleep(int(landing_page_wait))
		except TimeoutException:
			print str(link) + 'Timed Out!'
			timeout_error=1
		
			
		dismiss_alert()
			
		
		
		if fiddler == True :
			WConio.textcolor(WConio.GREEN)
			print 'Closing Fiddler'
			WConio.textcolor(WConio.WHITE)
			os.system('mon_launch.exe close fiddler')
			try:
				shutil.copyfile(fiddler_dump,fiddler_log)
			except:
				print "couldn't copy fiddler dump..."
		if procmon == True :
			WConio.textcolor(WConio.GREEN)
			print 'Closing Procmon'
			os.system('mon_launch.exe close procmon')
			print 'Converting Procmon Log To CSV Format'
			os.system('mon_launch.exe convert "procmon /saveas '+procmon_log.replace(".pml",".csv")+ " /openlog "+procmon_log+'"')
			WConio.textcolor(WConio.WHITE)
		if pcap == True :
			WConio.textcolor(WConio.GREEN)
			print 'Closing WinDump'
			WConio.textcolor(WConio.WHITE)
			os.system('mon_launch.exe close windump')
		print '\nAnalyzing Files After Link\n'
		#testexe=open("testing.exe","w")
		#testexe.write("wtfisthis")
		#testexe.close()
		directory_list("C:\\","2")
		print '\n'
		
		
		for error in cant_access:
			print '\n\n\t[ Error could not process ' + error + ' ]'
			
		WConio.textcolor(WConio.WHITE)#set terminal colour to white!
		#print len(files_before)
		#print len(files_after)
		for after_path in files_after: #see whats changed
			
			if after_path in files_before:
				files_before.remove(after_path) # if files in our 2nd scan are in the first get rid of them
			else:
				changed_files.append(after_path) # if 2nd scan file isnt in our before scan results its a new file!

		
		#define arrays for executable files! (that i can think of)
		exes=[]
		coms=[]
		bats=[]
		msis=[]
		#now dlls i guess
		dlls=[]
		#and 1 single array for images
		images=[]
		#one array for web crap like html,htm,css
		web_crap=[]
		#last one anything thats not an extension listed above
		unknown=[] 
		
		for changed in changed_files:
			extension = changed.rpartition(".")[2] 

			if extension == "exe" or extension == "EXE":
				exes.append(changed)
			elif extension == "com" or extension == "COM":
				coms.append(changed)
			elif extension == "bat" or extension == "BAT":
				bats.append(changed)
			elif extension == "msi" or extension == "MSI":
				msis.append(changed)
			elif extension == "dll" or extension == "DLL":
				dlls.append(changed)
			elif extension == "bmp" or extension == "BMP":
				images.append(changed)
			elif extension == "jpg" or extension == "JPG":
				images.append(changed)
			elif extension == "png" or extension == "PNG":
				images.append(changed)
			elif extension == "gif" or extension == "GIF":
				images.append(changed)
			elif extension == "htm" or extension == "HTM":
				web_crap.append(changed)
			elif extension == "html" or extension == "HTML":
				web_crap.append(changed)
			elif extension == "css" or extension == "CSS":
				web_crap.append(changed)
			elif extension == "js" or extension == "JS":
				web_crap.append(changed)
			elif extension == "txt" or extension == "TXT":
				web_crap.append(changed)
			else:
				unknown.append(changed)
		
		WConio.textcolor(WConio.WHITE)

		print '\nDropped Files :\n'
		if len(exes) > 0 or len(coms) > 0 or len(bats)>0 or len(msis) > 0 :
			pmls+=1
			log_file(str(link_md5)+'\\'+"PMLs.log",str(link)+','+str(link_md5)+','+str(len(exes)) + ',' + str(len(coms)) + ',' + str(len(bats)) + ',' + str(len(msis)))
			WConio.settitle("ALT " + version + " - PML's : " + str(pmls) ) 
		dismiss_alert()
		try:	
			title = driver.title
			#check page titles here
			match=0
			try:
				ip = socket.gethostbyname(socket.gethostname()).strip()
			except:
				ip = Error
			for check in phrases:
				if check in title:
					log_file(str(link_md5)+'\\'+"PMLs.log",str(link)+','+str(link_md5)+',[TITLE-MATCH]'+title)
					log_file(str(link_md5)+'\\'+link_md5+'.log+','[TITLE-MATCH]'+title+','+link+','+str(ip))
					pmls+=1
					WConio.settitle("ALT " + version + " - PML's : " + str(pmls) ) 
					match=1
			if match ==0:
				log_file(str(link_md5)+'\\'+link_md5+'.log','[Link]'+title+','+link+','+str(ip))
		except:
			print "couldn't check title for " + str(link)
			
		for exe in exes:
			WConio.textcolor(WConio.LIGHTRED)
			log_file(str(link_md5)+'\\'+link_md5+'.log','[EXE]' + exe)
			print '[EXE] ' + exe
		
		for com in coms:
			WConio.textcolor(WConio.LIGHTRED)
			log_file(str(link_md5)+'\\'+link_md5+'.log','[COM]' + com)
			print '[COM] ' + com
			
		for bat in bats:
			WConio.textcolor(WConio.LIGHTRED)
			log_file(str(link_md5)+'\\'+link_md5+'.log','[BAT]' + bat)
			print '[BAT] ' + bat
		
		for msi in msis:
			WConio.textcolor(WConio.LIGHTRED)
			log_file(str(link_md5)+'\\'+link_md5+'.log','[MSI]' +msi)
			print '[MSI] ' + msi
		
		for dll in dlls:
			WConio.textcolor(WConio.LIGHTMAGENTA)
			log_file(str(link_md5)+'\\'+link_md5+'.log','[DLL]' +dll)
			print '[DLL] ' + dll
		
		for image in images:
			WConio.textcolor(WConio.LIGHTCYAN)
			log_file(str(link_md5)+'\\'+link_md5+'.log','[IMAGE]' +image)
			#print '[IMAGE] ' + image
		
		for web in web_crap:
			WConio.textcolor(WConio.LIGHTBLUE)
			log_file(str(link_md5)+'\\'+link_md5+'.log','[WEB]' +web)
			#print '[WEB] ' + web
		
		WConio.textcolor(WConio.WHITE)
		print '\n\nUnknown File Types:\n\n'
		
		for file in unknown:
			WConio.textcolor(WConio.BROWN)
			log_file(str(link_md5)+'\\'+link_md5+'.log','[UNKNOWN]' +file)
			print file

		WConio.textcolor(WConio.WHITE)
		if timeout_error == 0:
			return True
		else:
			return False
	#except (KeyboardInterrupt, SystemExit): # handles exiting script early
	#		print'\nScript manually closed...\n'
	#		sys.exit()
			
def search_page_for_links(mode):
	global page_links,driver
	try:
		print 'Searching Page For Links\n'
		#mode : 1 = google search mode , 2 = wanderer mode
		dismiss_alert()
		link_search = driver.find_elements_by_tag_name("a")
		dismiss_alert()
		page_links=[]
		for i in link_search:
			link = str(i.get_attribute('href'))
			if mode == 1:
				if "windows-7" in plat.lower():
					if "webcache" not in link and "google" in link and "url=" in link and link <> "None" and "javascript:" not in link and link <> "https://www.youtube.com/?gl=GB" and link <> "https://www.blogger.com/?tab=wj":
						if link not in page_links:
							page_links.append(link)
							update_screen(link)
				else:
					
					if "url?q=" in link and "webcache" not in link and "/settings/ads/preferences" not in link:
						split =link.split("?q=")[1].split("&sa=")[0]
						if split not in page_links:
							page_links.append(split)
						
				#get pages
				if "search?q="+crawler_search_term in link and "start=10" in link:
					page2= link
				if "search?q="+crawler_search_term in link and "start=20" in link:
					page3= link
				if "search?q="+crawler_search_term in link and "start=30" in link:
					page4= link
				if "search?q="+crawler_search_term in link and "start=40" in link:
					page5= link
				if "search?q="+crawler_search_term in link and "start=50" in link:
					page6= link
				if "search?q="+crawler_search_term in link and "start=60" in link:
					page7= link
				if "search?q="+crawler_search_term in link and "start=70" in link:
					page8= link
				if "search?q="+crawler_search_term in link and "start=80" in link:
					page9= link
				if "search?q="+crawler_search_term in link and "start=90" in link:
					page10= link
					
			elif mode == 2:
				page_links.append(link)
	except:
			print 'error looking for links'
			return "nolinks"

def crawler(search_term):
	global driver
	try:
			alert = driver.switch_to_alert()
			alert.dismiss()
	except:
			pass
	driver.set_page_load_timeout(int(timeout))
	try:
		driver.get("http://google.com")
		#below looks for search input box on google 
		element = driver.find_element_by_name("q")
		element.send_keys(search_term, Keys.ENTER)
		time.sleep(1)
		search_page_for_links(1)
	except TimeoutException:
		print 'Failed to load google...exiting.'
		sys.exit()

def options(config):
	global timeout,phrases,landing_page_wait,fiddler, fiddler_out,fiddler_dump, pcap, pcap_out, procmon, procmon_out,fiddler_start_command, fiddler_finish_command,pcap_start_command,procmon_start_command,procmon_finish_command, link_file, wanderer_recursion, wanderer_out, crawler_search_term
	phrases=[]
	if config.getboolean('Logging','Fiddler'):
		fiddler = True
		fiddler_dump= config.get('Logging','Fiddler-Dump-Location')
		fiddler_out = str(config.get('Logging','Fiddler-Out'))
		print '\t- Fiddler Logging Enabled, output will be saved to ' + fiddler_out
	if config.getboolean('Logging','Packet-Capture'):
		pcap = True
		pcap_start_command= config.get('Logging','Packet-Capture-Start-Command')
		pcap_out = str(config.get('Logging','Packet-Capture-Out'))
		print '\t- Packet Capturing Enabled, output will be saved to ' + pcap_out
	if config.getboolean('Logging','Procmon'):
		procmon = True
		procmon_start_command=config.get('Logging','Procmon-Start-Command')
		procmon_out = str(config.get('Logging','Procmon-Out'))
		print '\t- Procmon Logging Enabled, output will be saved to ' + procmon_out
	print '\n'
	link_file = config.get('Data','Link-File-Location')
	wanderer_recursion = config.get('Wanderer','Recursion-Level')
	crawler_search_term = config.get('Crawler','Search-Term')
	landing_page_wait = config.get('Main','Landing-Page-Wait')
	timeout = config.get('Main','Timeout')
	phrases_file = config.get('Main','Title-Match-File')
	phrases_data= open(phrases_file,"r")
	for phrase in phrases_data.readlines():
		phrases.append(phrase.strip())
	WConio.textcolor(WConio.WHITE)
# @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
# ~   -    Script Starts Here    -    ~ #
# @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@

global driver,timeout,plat,version,landing_page_wait,title,files_before, files_after, fiddler, fiddler_out, pcap, pcap_out, procmon, procmon_out, link_file, wanderer_recursion, wanderer_out, crawler_search_term, pmls
version = "1.1.2"
timeout = 60
files_before = []
files_after = []
changed_files =[]
errors=[]
fiddler = False
fiddler_out = ''
pcap = False
pcap_out = ''
procmon = False
procmon_out = ''
link_file=""
wanderer_recursion= ""
wanderer_out= ""
crawler_search_term = ""
pmls=0
title=""
landing_page_wait=""
plat= platform.platform()

WConio.settitle("ALT " + version + " - PML's : " + str(pmls) ) 
if not os.path.exists("logs"):
		os.mkdir("logs")
		
loading_screen()
config = ConfigParser.ConfigParser()
config.read('settings.ini')

WConio.textcolor(WConio.LIGHTRED)
print '\n'
input= config.get('Data','Link-File-Location')


if config.getboolean('Main','Crawler-Mode'):

	print '\n+ Entering Crawler Mode!\n'
	WConio.textcolor(WConio.RED)
	options(config)
	print '\t- Search Term : ' + crawler_search_term+'\n\n'	
	driver = webdriver.Ie('IEDriverServer.exe')
	driver.set_page_load_timeout(int(timeout))
	crawler(crawler_search_term)
	print page_links
	for link in page_links:
		check_link(link)

elif config.getboolean('Main','Wanderer-Mode'):
	print '\n+ Entering Wanderer Mode!\n'
	options(config)
	recursions = int(config.get("Wanderer","Recursion-Level"))
	data = open(input,'r')
	driver = webdriver.Ie('IEDriverServer.exe')
	driver.set_page_load_timeout(int(timeout))
	line=data.readline().strip()
		#driver.get(line)
	if check_link(line):
		start = 0
		retry = 0
		while start <> recursions:
			page_links=[]
			search_page_for_links(2)
			if page_links:
				random_link= random.randint(1,len(page_links)-1)
				if check_link(page_links[random_link]):
					start+=1
					#print str(start),str(recursions)
			else:
				try:
					alert = driver.switch_to_alert()
					alert.dismiss()
				except:
					pass
				driver.set_page_load_timeout(int(timeout))
				driver.get(line)#if no links on current page go back to the start
				#POTENTIAL FOR ENDLESS LOOP HERE IF FRST PAGE HAS NO LINKS!!
				retry+=1
				if retry >20: #if we hit 20 then fuck it
					break
elif config.getboolean('Main','Multi-Test'):

	print '\n+ Entering Multiple Link Mode!\n'
	options(config)
	data = open(input,'r')
	linkstodo=[]
	for line in data:
		linkstodo.append(line.strip())
	data.close()
	for linktodo in linkstodo:
		driver = webdriver.Ie('IEDriverServer.exe')
		driver.set_page_load_timeout(int(timeout))
		if check_link(linktodo):
			linksbackup=open("links.bk","w")
			for todo in linkstodo:
				if todo <> linktodo:
					linksbackup.write(todo+'\n')
			linksbackup.close()
			shutil.copyfile('links.bk',input)
			dismiss_alert()
		dismiss_alert()
		driver.close()
		os.system("taskkill /F /im IEDriverServer.exe >nul")
else:

	print '\nEntering Single Link Mode!\n'
	options(config)
	data = open(input,'r')
	driver = webdriver.Ie('IEDriverServer.exe')
	driver.set_page_load_timeout(int(timeout))
	check_link(data.readline().strip())	
	os.system("taskkill /F /im IEDriverServer.exe >nul")
WConio.textcolor(WConio.WHITE)
try:
	alert = driver.switch_to_alert()
	alert.dismiss()
except:
	pass
try:
	driver.close()
except:
	pass
os.system("taskkill /F /im IEDriverServer.exe >nul")
os.system('shutdown.exe -r -t 5 -f -c "ALT Shutting Down"')
