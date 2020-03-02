#! usr/bin/python2

import sys ,  hashlib ,  time ,  os , random , binascii

from urllib import urlopen, urlencode
from re import search

# Color
if sys.platform == "linux" or sys.platform == "linux2":

	BB = "\033[34;1m" # Blue Light
	YY = "\033[33;1m" # Yellow Light
	GG = "\033[32;1m" # Green Light
	WW = "\033[0;1m"  # White Light
	RR = "\033[31;1m" # Red Light
	CC = "\033[36;1m" # Cyan Light
	MM = "\033[35;1m" # Magenta Light
	B = "\033[34;1m"  # Blue
	Y = "\033[33;1m"  # Yellow
	G = "\033[32;1m"  # Green
	W = "\033[0;1m"   # White
	R = "\033[31;1m"  # Red
	C = "\033[36;1m"  # Cyan
	M = "\033[35;1m"  # Magenta

	# Random Color
	rand = (BB,YY,GG,WW,RR,CC)
	P = random.choice(rand)

elif sys.platform == "win32":

	BB = '' # Blue Light
	YY = '' # Yellow Light
	GG = '' # Green Light
	WW = '' # White Light
	RR = '' # Red Light
	CC = '' # Cyan Light
	B = ''  # Blue
	Y = ''  # Yellow
	G = ''  # Green
	W = ''  # White
	R = ''  # Red
	C = ''  # Cyan
	P = ''  # Random Color

def banner():
	print ('\n')
   	print (CC+'              Hash Cracker'+GG+' v1.0.0')
	print (P+'  #      #'+WW+' ##################################')
	print (P+'  #      #   ##    ####  #    # ###### #####  ')
	print (P+'  #      #  #  #  #      #    # #      #    # ')
	print (P+'  ######## #    #  ####  ###### #####  #    # ')
	print (P+'  #      # ######      # #    # #      #####  ')
	print (P+'  #      # #    # #    # #    # #      #   #  ')
	print (P+'  #      # #    #  ####  #    # ###### #    # ')
	print (WW+'  ##############['+CC+' TheDarkRoot'+WW+' ]############## ')
	print (P+"            python2 "+sys.argv[0]+" --info\n"+W)

def info():

	print (GG+"\n 0{======================"+WW+" INFO "+GG+"=======================}0")
	print (GG+" |"+BB+" ["+RR+"="+BB+"] "+WW+"Name     "+CC+":"+WW+" Hasher"+GG+"                               |")
	print (GG+" |"+BB+" ["+RR+"="+BB+"] "+WW+"Code     "+CC+":"+WW+" Python2"+GG+"                              |")
	print (GG+" |"+BB+" ["+RR+"="+BB+"] "+WW+"Version  "+CC+":"+WW+" v1.0.0 (Alpha)"+GG+"                       |")
	print (GG+" |"+BB+" ["+RR+"="+BB+"] "+WW+"Author   "+CC+":"+WW+" TheDarkRoot"+GG+"                          |")
	print (GG+" |"+BB+" ["+RR+"="+BB+"] "+WW+"Email    "+CC+":"+WW+" 7H3D4RKR007@gmail.com"+GG+"                |")
	print (GG+" |"+BB+" ["+RR+"="+BB+"] "+WW+"Github   "+CC+":"+WW+" https://github.com/TheDarkRoot"+GG+"       |")
	print (GG+" |"+BB+" ["+RR+"="+BB+"] "+WW+"Telegram "+CC+":"+WW+" @TDarkRoot (https://t.me/TDarkRoot)"+GG+"  |")
	print (GG+" |"+BB+" ["+RR+"="+BB+"] "+WW+"Team     "+CC+":"+WW+" TurkHackTeam (www.turkhackteam.org)"+GG+"  |")
	print (GG+" 0{===================================================}0\n")
	print (BB+" ["+RR+"="+BB+"] "+WW+"python2 "+sys.argv[0]+" -u")
	print (BB+"\n ["+RR+"="+BB+"] "+WW+"To Update Wordlist")
	print (BB+"\n ["+RR+"="+BB+"] "+WW+"List of supported hashes:")
	print (YY+"\n                          ["+WW+"01"+YY+"] "+CC+"md4")
	print (YY+"                          ["+WW+"02"+YY+"] "+CC+"md5")
	print (YY+"                          ["+WW+"03"+YY+"] "+CC+"sha1")
	print (YY+"                          ["+WW+"04"+YY+"] "+CC+"sha224")
	print (YY+"                          ["+WW+"05"+YY+"] "+CC+"sha256")
	print (YY+"                          ["+WW+"06"+YY+"] "+CC+"sha384")
	print (YY+"                          ["+WW+"07"+YY+"] "+CC+"sha512")
	print (YY+"                          ["+WW+"08"+YY+"] "+CC+"ripemd160")
	print (YY+"                          ["+WW+"09"+YY+"] "+CC+"whirlpool")
	print (YY+"                          ["+WW+"10"+YY+"] "+CC+"MySQL 3.2.3")
	print (YY+"                          ["+WW+"11"+YY+"] "+CC+"MySQL 4.1")
	print (YY+"                          ["+WW+"12"+YY+"] "+CC+"MSSQL 2000")
	print (YY+"                          ["+WW+"13"+YY+"] "+CC+"MSSQL 2005")
	print (YY+"                          ["+WW+"14"+YY+"] "+CC+"Nthash")
	print (YY+"                          ["+WW+"15"+YY+"] "+CC+"lmhash")
	print (YY+"                          ["+WW+"16"+YY+"] "+CC+"NTLM hash\n"+W)

def Update():
	if sys.platform == "linux" or sys.platform == "linux2":
		print (BB+" 0={"+WW+" Update wordlist. "+BB+"}=0\n")
		time.sleep(1)

		print (BB+"["+WW+"="+BB+"] "+GG+"Remove old wordlist.")
		os.system("rm -rf Wordlist.txt")
		time.sleep(1)

		print (BB+"["+WW+"="+BB+"] "+GG+"Downloading new wordlist.")
		time.sleep(1)

		print (RR+"["+WW+"*"+RR+"] "+RR+"Curl Started...\n"+W)

		os.system("curl https://raw.githubusercontent.com/TheDarkRoot/Hasher/master/Wordlist.txt -o Wordlist.txt")

		print (RR+"\n["+WW+"*"+RR+"] "+GG+"Download finish.\n"+W)
		sys.exit()
	else:
		print ("Sorry, word list update feature is only available on linux platform.\n")
		sys.exit()


try:

	# Module Tambahan

	import progressbar
	from passlib.hash import mysql323 as m20
	from passlib.hash import mysql41 as m25
	from passlib.hash import mssql2000 as ms20
	from passlib.hash import mssql2005 as ms25
	from passlib.hash import nthash as nthash
	from passlib.hash import lmhash as lmhash

except ImportError:
        banner()
	time.sleep(0.5)
        print (BB+"["+WW+"="+BB+"] "+GG+"installing module "+RR+"progressbar, passlib.\n"+W)

	os.system("pip2 install --upgrade pip")
	os.system("pip2 install passlib")
	os.system("pip2 install progressbar")

	print (BB+"\n["+WW+"="+BB+"] "+GG+"install success, run program again.\n"+W)
        sys.exit()

def hash():
	banner()

	hash_str = raw_input(BB+"["+WW+"?"+BB+"]"+GG+" Hash: "+W)
#	time.sleep(0.5)
	print (BB+"["+RR+"="+BB+"] "+GG+"Cek Hash Type...")
#	time.sleep(1)


	# Contoh Hash nya , nb : jangan di ubah ntar error

	SHA512= ('dd0ada8693250b31d9f44f3ec2d4a106003a6ce67eaa92e384b356d1b4ef6d66a818d47c1f3a2c6e8a9a9b9bdbd28d485e06161ccd0f528c8bbb5541c3fef36f')
	md = ('ae11fd697ec92c7c98de3fac23aba525')
	sha1 = ('4a1d4dbc1e193ec3ab2e9213876ceb8f4db72333')
	sha224 = ('e301f414993d5ec2bd1d780688d37fe41512f8b57f6923d054ef8e59')
	sha384 = ('3b21c44f8d830fa55ee9328a7713c6aad548fe6d7a4a438723a0da67c48c485220081a2fbc3e8c17fd9bd65f8d4b4e6b')
	sha256 = ('2c740d20dab7f14ec30510a11f8fd78b82bc3a711abe8a993acdb323e78e6d5e')
	mysql1323 = ("5d2e19393cc5ef67")
	mysql41 = ("*88166B019A3144C579AC4A7131BCC3AD6FF61DA6")
	mssql2000 = ("0x0100DE9B3306258B37432CAC3A6FB7C638946FA393E09C9CBC0FA8C6E03B803390B1C3E7FB112A21B2304595D490")
	mssql2005 = ('0x01008110620C7BD03A38A28A3D1D032059AE9F2F94F3B74397F8')

	if len(hash_str)==len(mysql1323) and hash_str.isdigit()==False and hash_str.isalpha()==False and hash_str.isalnum()==True:
		print (BB+"["+RR+"="+BB+"] "+GG+"Hash type: "+WW+"mysql 3.2.3")
		hash = "mysql1323"

	elif len(hash_str)==len(mysql41) and "*" in hash_str:
		print (BB+"["+RR+"="+BB+"] "+GG+"Hash type: "+WW+"mysql 4.1")
		hash = "mysql41"

	elif len(hash_str)==len(mssql2000) and "0x0" in hash_str:
		print (BB+"["+RR+"="+BB+"] "+GG+"Hash type: "+WW+"Mssql2000")
		hash = "mssql2000"

	elif len(hash_str)==len(mssql2005) and "0x0" in hash_str:
		print (BB+"["+RR+"="+BB+"] "+GG+"Hash type: "+WW+"Mssql2005")
                hash = "mssql2005"


	elif len(hash_str)==len(SHA512) and hash_str.isdigit()==False and hash_str.isalpha()==False and hash_str.isalnum()==True:
	        print (YY+"   ["+WW+"01"+YY+"] "+CC+"sha512")
		print (YY+"   ["+WW+"02"+YY+"] "+CC+"whirlpool")
#		time.sleep(0.3)
		cek = raw_input(BB+"["+WW+"?"+BB+"] "+GG+"Choose hash "+YY+">>> "+W)

		if cek == "1" or cek == "01" or cek == "sha512":
			hash = "sha512"
		elif cek == "2" or cek == "02" or cek == "whirlpool":
			hash = "whirlpool"
		else:
			print (RR+"["+WW+"!"+RR+"] "+GG+"Exiting ... \n")
#                       time.sleep(0.5)
                        sys.exit()

	elif len(hash_str)==len(md) and hash_str.isdigit()==False and hash_str.isalpha()==False and hash_str.isalnum()==True:

		print (YY+"   ["+WW+"01"+YY+"] "+CC+"md4")
		print (YY+"   ["+WW+"02"+YY+"] "+CC+"md5")
		print (YY+"   ["+WW+"03"+YY+"] "+CC+"Nthash")
		print (YY+"   ["+WW+"04"+YY+"] "+CC+"Lmhash")
		print (YY+"   ["+WW+"05"+YY+"] "+CC+"Ntlm hash")

#		time.sleep(0.3)
		cek = raw_input(BB+"["+WW+"?"+BB+"] "+GG+"Choose Hash "+YY+">>> "+W)

		if cek == "1" or cek == "01" or cek == "md4" or cek == "MD4" or cek == "Md4":
			hash = "md4"
		elif cek == "2" or cek == "02" or cek == "md5" or cek == "MD5" or cek == "Md5":
			try:
				print (BB+"["+RR+"="+BB+"] "+GG+"Open Google")
#				time.sleep(0.3)
				print (BB+"["+WW+"*"+BB+"] "+GG+"Start...")
#				time.sleep(0.3)
				start = ("00:00:00")
				start1 = time.time()
				print (BB+"\n["+WW+"{}"+BB+"] "+GG+"Searching..."+Y).format(start)

				data = urlencode({"md5":hash_str,"x":"21","y":"8"})
        	    		html = urlopen("http://md5.my-addr.com/md5_decrypt-md5_cracker_online/md5_decoder_tool.php", data)
		                find = html.read()
        	     		match = search (r"<span class='middle_title'>Hashed string</span>: [^<]*</div>", find)    
	               		if match:

					end = time.strftime("%H:%M:%S", time.gmtime(time.time() - start1))
					print (BB+"["+WW+"{}"+BB+"] "+YY+"Stopped...").format(end)
#	                                time.sleep(0.3)
					print (BB+"\n["+WW+"="+BB+"]"+GG+" Password found:")
					print (BB+"["+GG+"*"+BB+"] "+WW+(hash_str)+GG+" }==> "+WW+(match.group().split('span')[2][3:-6])+"\n")
					sys.exit()
		                else:
					data = urlencode({"md5":hash_str,"x":"21","y":"8"})
            				html = urlopen("http://md5.my-addr.com/md5_decrypt-md5_cracker_online/md5_decoder_tool.php", data)
			                find = html.read()
				        match = search (r"<span class='middle_title'>Hashed string</span>: [^<]*</div>", find)
			                if match:

					        end = time.strftime("%H:%M:%S", time.gmtime(time.time() - start1))
        				    	print (BB+"["+WW+"{}"+BB+"] "+YY+"Stopped...").format(end)
#						time.sleep(0.3)
						print (BB+"\n["+WW+"="+BB+"]"+GG+" Password found:")
                				print (BB+" ["+GG+"*"+BB+"] "+WW+hash_str+GG+" }==> "+WW+match.group().split('span')[2][3:-6]+WW+" \n")
						sys.exit()
			                else:
	                  			url = "http://www.nitrxgen.net/md5db/" + hash_str
        	        			cek = urlopen(url).read()
                				if len(cek) > 0:

						        end = time.strftime("%H:%M:%S", time.gmtime(time.time() - start1))
							print (BB+"["+WW+"{}"+BB+"] "+YY+"Stopped...").format(end)
#							time.sleep(0.3)
				                	print (BB+"\n["+WW+"="+BB+"]"+GG+" Password found:")
						        print (BB+"["+GG+"*"+BB+"] "+WW+hash_str+GG+" }==> "+WW+cek+"\n")
							sys.exit()
						else:

						        end = time.strftime("%H:%M:%S", time.gmtime(time.time() - start1))
							print (BB+"["+WW+"{}"+BB+"]"+RR+" Password not found.\n").format(end)
							hash = "md5"

			except IOError:

				end = time.strftime("%H:%M:%S", time.gmtime(time.time() - start1))
				print (BB+"["+WW+"{}"+BB+"]"+GG+" Timeout\n").format(end)
				hash = "md5"

		elif cek == "03" or cek == "3" or cek.upper() == "NTHASH":
			hash = "nthash"

		elif cek == "04" or cek == "4" or cek.upper() == "LMHASH":
			hash = "lmhash"

		elif cek == "05" or cek == "5" or cek.upper() == "NTLM":
			hash = "ntlm"

		else:
			print (RR+"["+WW+"!"+RR+"] "+GG+"Exiting... \n"+W)
#			time.sleep(0.5)
			sys.exit()


	elif len(hash_str)==len(sha1) and hash_str.isdigit()==False and hash_str.isalpha()==False and hash_str.isalnum()==True:

		print (YY+"   ["+WW+"01"+YY+"] "+CC+"sha1")
		print (YY+"   ["+WW+"02"+YY+"] "+CC+"ripemd160")
#		time.sleep(0.3)
		cek = raw_input(BB+"["+WW+"?"+BB+"] "+GG+"Choose Hash "+YY+">>> "+W)

		if cek == "1" or cek == "01" or cek == "sha1" or cek == "SHA1" or cek == "Sha1":
#			time.sleep(0.5)
			print (BB+"["+RR+"="+BB+"] "+GG+"Open Google")
#			time.sleep(0.3)
			print (BB+"["+WW+"*"+BB+"] "+GG+"Start ...")
#			time.sleep(0.3)
			start = ("00:00:00")
			start1 = time.time()
			print (BB+"\n["+WW+"{}"+BB+"] "+GG+"Searching..."+Y).format(start)
			try:

				data = urlencode({"auth":"8272hgt", "hash":hash_str, "string":"","Submit":"Submit"})
				html = urlopen("http://hashcrack.com/index.php" , data)
				find = html.read()
    				match = search (r'<span class=hervorheb2>[^<]*</span></div></TD>', find)
 				if match:

					end = time.strftime("%H:%M:%S", time.gmtime(time.time() - start1))
					print (BB+"["+WW+"{}"+BB+"] "+YY+"Stopped...").format(end)
#					time.sleep(0.3)
		           		print (BB+"\n["+WW+"="+BB+"]"+GG+" Password found:")
				        print (BB+"["+GG+"*"+BB+"] "+WW+hash_str+GG+" }==> "+WW+match.group().split('hervorheb2>')[1][:-18]+"\n")
					sys.exit()

				else:

					end = time.strftime("%H:%M:%S", time.gmtime(time.time() - start1))
					print (BB+"["+WW+"{}"+BB+"]"+RR+" Password not found.\n").format(date)
					hash = "sha1"
			except IOError:

				end = time.strftime("%H:%M:%S", time.gmtime(time.time() - start1))
				print (BB+"["+WW+"{}"+BB+"]"+GG+" Timeout\n").format(end)
				hash = "sha1"

		elif cek == "2" or cek == "02" or cek == "ripemd160":
			hash = 'ripemd160'
		else:
			print (RR+"["+WW+"!"+RR+"] "+GG+"Exiting...\n"+W)
#			time.sleep(0.5)
			sys.exit()

	elif len(hash_str)==len(sha224) and hash_str.isdigit()==False and hash_str.isalpha()==False and hash_str.isalnum()==True:
		print (BB+"["+RR+"="+BB+"] "+GG+"Hash type: "+WW+"SHA224")
		hash = "SHA224"

	elif len(hash_str)==len(sha384) and hash_str.isdigit()==False and hash_str.isalpha()==False and hash_str.isalnum()==True:
		print (BB+"["+RR+"="+BB+"] "+GG+"Hash type: "+WW+"SHA384")
		hash = "SHA384"

	elif len(hash_str)==len(sha256) and hash_str.isdigit()==False and hash_str.isalpha()==False and hash_str.isalnum()==True:
		print (BB+"["+RR+"="+BB+"] "+GG+"Hash type: "+WW+"sha256")
#		time.sleep(0.5)
		print (BB+"["+RR+"="+BB+"] "+GG+"Open Google")
#		time.sleep(0.3)
		print (BB+"["+WW+"*"+BB+"] "+GG+"Start ...")
#		time.sleep(0.3)
		start = ("00:00:00")
		start1 = time.time()
		print (BB+"\n["+WW+"{}"+BB+"] "+GG+"Searching..."+YY).format(start)

		try:
			data = urlencode({"hash":hash_str, "decrypt":"Decrypt"})
	     	        html = urlopen("http://md5decrypt.net/en/Sha256/", data)
	        	find = html.read()
    		        match = search (r'<b>[^<]*</b><br/><br/>', find)
		        if match:

        			end = time.strftime("%H:%M:%S", time.gmtime(time.time() - start1))
			        print (BB+"["+WW+"{}"+BB+"] "+YY+"Stopped...").format(end)
#				time.sleep(0.3)
	           		print (BB+"\n["+WW+"="+BB+"]"+GG+" Password found:")
			        print (BB+"["+GG+"*"+BB+"] "+WW+hash_str+GG+" }==> "+WW+match.group().split('<b>')[1][:-14]+"\n")
				sys.exit()

			else:

			        end = time.strftime("%H:%M:%S", time.gmtime(time.time() - start1))
				print (BB+"["+WW+"{}"+BB+"]"+RR+" Password not found.\n").format(end)
				hash = "sha256"
		except IOError:

				end = time.strftime("%H:%M:%S", time.gmtime(time.time() - start1))
				print (BB+"["+WW+"{}"+BB+"]"+GG+" Timeout\n").format(end)
				hash = "sha256"

	else:
		print (RR+"["+WW+"!"+RR+"] "+GG+"Hash Error.\n"+W)
		sys.exit()

	time.sleep(0.1)
	print (BB+"["+WW+"="+BB+"] "+GG+"Cek Wordlist...")

	try:
		w = open("Wordlist.txt","r").readlines()
		x = len(w)
	except IOError:
#		time.sleep(0.5)
		print (BB+"["+RR+"="+BB+"]"+GG+"Can't load "+WW+"Wordlist.txt, "+GG+"file not exist.\n"+W)
		sys.exit()

#	time.sleep(0.3)
	print (BB+"["+RR+"="+BB+"] "+GG+"Load "+WW+"{}"+GG+" words in "+WW+"Wordlist.txt").format(x)
	print (BB+"["+WW+"*"+BB+"] "+GG+"Start...\n")
#	time.sleep(1)

	start = ("00:00:00")
	start1 = time.time()
	print (BB+"["+WW+"{}"+BB+"] "+GG+"Cracking..."+YY).format(start)

	pbar = progressbar.ProgressBar()

	if hash == "mysql1323":

		hash_str = hash_str.lower()
		for line in pbar(w):
			line = line.strip()
			h = m20.encrypt(line)


			if h == hash_str:

				end = time.strftime("%H:%M:%S", time.gmtime(time.time() - start1))
#                                time.sleep(0.3)
                                print (BB+"\n["+WW+"{}"+BB+"] "+YY+"Stopped...\n").format(end)
#                                time.sleep(0.3)
                                print (BB+"["+WW+"="+BB+"]"+GG+" Password found:")
				print (BB+"["+GG+"*"+BB+"] "+WW+hash_str+GG+" }==> "+WW+line+WW+"\n")
                                sys.exit()

		end = time.strftime("%H:%M:%S", time.gmtime(time.time() - start1))
		print (BB+"["+WW+"{}"+BB+"]"+RR+" Password not found.\n"+W).format(end)
		sys.exit()

	elif hash == "lmhash":

		hasb_str = hash_str.upper()
		for line in pbar(w):
			line = line.strip()
			h = lmhash.encrypt(line)
			if h == hash_str:

			        end = time.strftime("%H:%M:%S", time.gmtime(time.time() - start1))
#                                time.sleep(0.3)
                                print (BB+"\n["+WW+"{}"+BB+"] "+YY+"Stopped...\n").format(end)
#                                time.sleep(0.3)
                                print (BB+"["+WW+"="+BB+"]"+GG+" Password found:")
                                print (BB+"["+GG+"*"+BB+"] "+WW+hash_str+GG+" }==> "+WW+line+WW+"\n")
                                sys.exit()

		end = time.strftime("%H:%M:%S", time.gmtime(time.time() - start1))
		print (BB+"["+WW+"{}"+BB+"]"+RR+" Password not found.\n"+W).format(end)
                sys.exit()

	elif hash == "nthash":

		hasb_str = hash_str.upper()
                for line in pbar(w):
                        line = line.strip()
                        h = nthash.encrypt(line)

                        if h == hash_str:

			        end = time.strftime("%H:%M:%S", time.gmtime(time.time() - start1))
#                                time.sleep(0.3)
                                print (BB+"\n["+WW+"{}"+BB+"] "+YY+"Stopped...\n").format(end)
#                                time.sleep(0.3)
                                print (BB+"["+WW+"="+BB+"]"+GG+" Password found:")
                                print (BB+"["+GG+"*"+BB+"] "+WW+hash_str+GG+" }==> "+WW+line+WW+"\n")
                                sys.exit()

		end = time.strftime("%H:%M:%S", time.gmtime(time.time() - start1))
                print (BB+"["+WW+"{}"+BB+"]"+RR+" Password not found.\n"+W).format(end)
                sys.exit()

	elif hash == "mysql41":

		hash_str = hash_str.upper()
		for line in pbar(w):
			line = line.strip()
			h = m25.encrypt(line)

			if h == hash_str:

			        end = time.strftime("%H:%M:%S", time.gmtime(time.time() - start1))
#                                time.sleep(0.3)
                                print (BB+"\n["+WW+"{}"+BB+"] "+YY+"Stopped...\n").format(end)
#                                time.sleep(0.3)
                                print (BB+"["+WW+"="+BB+"]"+GG+" Password found:")
                                print (BB+"["+GG+"*"+BB+"] "+WW+hash_str+GG+" }==> "+WW+line+WW+"\n")
                                sys.exit()

		end = time.strftime("%H:%M:%S", time.gmtime(time.time() - start1))
		print (BB+"["+WW+"{}"+BB+"]"+RR+" Password not found.\n"+W).format(end)
                sys.exit()

	elif hash == "mssql2000":

		hash_str = hash_str.upper()
		for line in pbar(w):
			line = line.strip()
			h = ms20.encrypt(line)

			if h == hash_str:

				end = time.strftime("%H:%M:%S", time.gmtime(time.time() - start1))
#                                time.sleep(0.3)
                                print (BB+"\n["+WW+"{}"+BB+"] "+YY+"Stopped...\n").format(end)
#                                time.sleep(0.3)
                                print (BB+"["+WW+"="+BB+"]"+GG+" Password found:")
                                print (BB+"["+GG+"*"+BB+"] "+WW+hash_str+GG+" }==> "+WW+line+WW+"\n")
                                sys.exit()

		end = time.strftime("%H:%M:%S", time.gmtime(time.time() - start1))
		print (BB+"["+WW+"{}"+BB+"]"+RR+" Password not found.\n"+W).format(end)
                sys.exit()

	elif hash == "ntlm":

		hash_str = hash_str.lower()
		for line in pbar(w):
			line = line.strip()
			h = ntlm_hash = binascii.hexlify(hashlib.new('md4', line.encode('utf-16le')).digest())
			if h == hash_str:

				end = time.strftime("%H:%M:%S", time.gmtime(time.time() - start1))
#				time.sleep(0.3)
                                print (BB+"\n["+WW+"{}"+BB+"] "+YY+"Stopped...\n").format(end)
#                                time.sleep(0.3)
                                print (BB+"["+WW+"="+BB+"]"+GG+" Password found:")
                                print (BB+"["+GG+"*"+BB+"] "+WW+hash_str+GG+" }==> "+WW+line+WW+"\n")
                                sys.exit()

		end = time.strftime("%H:%M:%S", time.gmtime(time.time() - start1))
		print (BB+"["+WW+"{}"+BB+"]"+RR+" Password not found.\n"+W).format(end)
                sys.exit()

	elif hash == "mssql2005":

		hasb_str = hash_str.upper()
                for line in pbar(w):
                        line = line.strip()
                        h = ms25.encrypt(line)

                        if h == hash_str:

                                end = time.strftime("%H:%M:%S", time.gmtime(time.time() - start1))
#                                time.sleep(0.3)
                                print (BB+"\n["+WW+"{}"+BB+"] "+YY+"Stopped...\n").format(end)
#                                time.sleep(0.3)
                                print (BB+"["+WW+"="+BB+"]"+GG+" Password found:")
                                print (BB+"["+GG+"*"+BB+"] "+WW+hash_str+GG+" }==> "+WW+line+WW+"\n")
                                sys.exit()


		end = time.strftime("%H:%M:%S", time.gmtime(time.time() - start1))
                print (BB+"["+WW+"{}"+BB+"]"+RR+" Password not found.\n"+W).format(end)
		sys.exit()

	else:

		hash_str = hash_str.lower()
		for line in pbar(w):

			line = line.strip()
		        h = hashlib.new(hash)
			h.update(line)

			if h.hexdigest() == hash_str:

				end = time.strftime("%H:%M:%S", time.gmtime(time.time() - start1))
#				time.sleep(0.3)
				print (BB+"\n["+WW+"{}"+BB+"] "+YY+"Stopped...\n").format(end)
#				time.sleep(0.3)
				print (BB+"["+WW+"="+BB+"]"+GG+" Password found:")
        	       		print (BB+"["+GG+"*"+BB+"] "+WW+hash_str+GG+" }==> "+WW+line+WW+"\n")
				sys.exit()

		end = time.strftime("%H:%M:%S", time.gmtime(time.time() - start1))
		print (BB+"["+WW+"{}"+BB+"]"+RR+" Password not found.\n"+W).format(end)
		sys.exit()

try:
	if sys.argv[1] == "-u":
		Update()
	elif sys.argv[1] == "-i" or sys.argv[1] == "--info":
		info()
	else:
		print (RR+"["+WW+"!"+RR+"] "+GG+"Command Error!!!"+W)
		sys.exit()

except IndexError:
	hash()

