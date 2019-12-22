# mv
mv

## lazymux.py - Lazymux v3.0
# -*- coding: utf-8 -*-
##
import os
import sys
from time import sleep as timeout
from core.lzmcore import *

def main():
	banner()
	print "   [01] Information Gathering"
	print "   [02] Vulnerability Scanner"
	print "   [03] Stress Testing"
	print "   [04] Password Attacks"
	print "   [05] Web Hacking"
	print "   [06] Exploitation Tools"
	print "   [07] Sniffing & Spoofing"
	print "   [08] Other\n"
	print "   [10] Exit the Lazymux\n"
	lazymux = raw_input("lzmx > ")
	
	if lazymux == "1" or lazymux == "01":
		print "\n    [01] Nmap"
		print "    [02] Red Hawk"
		print "    [03] D-Tect"
		print "    [04] sqlmap"
		print "    [05] Infoga"
		print "    [06] ReconDog"
		print "    [07] AndroZenmap"
		print "    [08] sqlmate"
		print "    [09] AstraNmap"
		print "    [10] WTF"
		print "    [11] Easymap"
		print "    [12] BlackBox"
		print "    [13] XD3v"
		print "    [14] Crips"
		print "    [15] SIR"
		print "    [16] EvilURL"
		print "    [17] Striker"
		print "    [18] Xshell"
		print "    [19] OWScan"
		print "    [20] OSIF"
		print "    [21] Devploit"
		print "    [22] Namechk"
		print "    [23] AUXILE"
		print "    [24] inther"
		print "    [25] GINF"
		print "    [26] GPS Tracking"
		print "    [27] ASU"
		print "    [28] fim"
		print "    [29] MaxSubdoFinder"
		print "    [30] pwnedOrNot"
		print "    [31] Mac-Lookup"
		print "    [32] BillCypher\n"
		print "    [00] Back to main menu\n"
		infogathering = raw_input("lzmx > ")
		
		if infogathering == "01" or infogathering == "1":
			nmap()
		elif infogathering == "02" or infogathering == "2":
			red_hawk()
		elif infogathering == "03" or infogathering == "3":
			dtect()
		elif infogathering == "04" or infogathering == "4":
			sqlmap()
		elif infogathering == "05" or infogathering == "5":
			infoga()
		elif infogathering == "06" or infogathering == "6":
			reconDog()
		elif infogathering == "07" or infogathering == "7":
			androZenmap()
		elif infogathering == "08" or infogathering == "8":
			sqlmate()
		elif infogathering == "09" or infogathering == "9":
			astraNmap()
		elif infogathering == "10":
			wtf()
		elif infogathering == "11":
			easyMap()
		elif infogathering == "12":
			blackbox()
		elif infogathering == "13":
			xd3v()
		elif infogathering == "14":
			crips()
		elif infogathering == "15":
			sir()
		elif infogathering == "16":
			evilURL()
		elif infogathering == "17":
			striker()
		elif infogathering == "18":
			xshell()
		elif infogathering == "19":
			owscan()
		elif infogathering == "20":
			osif()
		elif infogathering == "21":
			devploit()
		elif infogathering == "22":
			namechk()
		elif infogathering == "23":
			auxile()
		elif infogathering == "24":
			inther()
		elif infogathering == "25":
			ginf()
		elif infogathering == "26":
			gpstr()
		elif infogathering == "27":
			asu()
		elif infogathering == "28":
			fim()
		elif infogathering == "29":
			maxsubdofinder()
		elif infogathering == "30":
			pwnedOrNot()
		elif infogathering == "31":
			maclook()
		elif infogathering == "32":
			billcypher()
		elif infogathering == "00" or infogathering == "0":
			restart_program()
		else:
			print "\nERROR: Wrong Input"
			timeout(2)
			restart_program()
	
	elif lazymux == "2" or lazymux == "02":
  print "\n    [01] Nmap"
		print "    [02] AndroZenmap"
		print "    [03] AstraNmap"
		print "    [04] Easymap"
		print "    [05] Red Hawk"
		print "    [06] D-Tect"
		print "    [07] Damn Small SQLi Scanner"
		print "    [08] SQLiv"
		print "    [09] sqlmap"
		print "    [10] sqlscan"
		print "    [11] Wordpresscan"
		print "    [12] WPScan"
		print "    [13] sqlmate"
		print "    [14] wordpresscan"
		print "    [15] WTF"
		print "    [16] Rang3r"
		print "    [17] Striker"
		print "    [18] Routersploit"
		print "    [19] Xshell"
		print "    [20] SH33LL"
		print "    [21] BlackBox"
		print "    [22] XAttacker"
		print "    [23] OWScan\n"
		print "    [00] Back to main menu\n"
		vulnscan = raw_input("lzmx > ")
		
		if vulnscan == "01" or vulnscan == "1":
			nmap()
		elif vulnscan == "02" or vulnscan == "2":
			androZenmap()
		elif vulnscan == "03" or vulnscan == "3":
			astraNmap()
		elif vulnscan == "04" or vulnscan == "4":
			easyMap()
		elif vulnscan == "05" or vulnscan == "5":
			red_hawk()
		elif vulnscan == "06" or vulnscan == "6":
			dtect()
		elif vulnscan == "07" or vulnscan == "7":
			dsss()
		elif vulnscan == "08" or vulnscan == "8":
			sqliv()
		elif vulnscan == "09" or vulnscan == "9":
			sqlmap()
		elif vulnscan == "10":
			sqlscan()
		elif vulnscan == "11":
			wordpreSScan()
		elif vulnscan == "12":
			wpscan()
		elif vulnscan == "13":
			sqlmate()
		elif vulnscan == "14":
			wordpresscan()
		elif vulnscan == "15":
			wtf()
		elif vulnscan == "16":
			rang3r()
		elif vulnscan == "17":
			striker()
		elif vulnscan == "18":
			routersploit()
		elif vulnscan == "19":
			xshell()
		elif vulnscan == "20":
			sh33ll()
		elif vulnscan == "21":
			blackbox()
		elif vulnscan == "22":
			xattacker()
		elif vulnscan == "23":
			owscan()
		elif vulnscan == "00" or vulnscan == "0":
			restart_program()
		else:
			print "\nERROR: Wrong Input"
			timeout(2)
			restart_program()
	
	elif lazymux == "3" or lazymux == "03":
		print "\n    [01] Torshammer"
		print "    [02] Slowloris"
		print "    [03] Fl00d & Fl00d2"
		print "    [04] GoldenEye"
		print "    [05] Xerxes"
		print "    [06] Planetwork-DDOS"
		print "    [07] Hydra"
		print "    [08] Black Hydra"
		print "    [09] Xshell"
		print "    [10] santet-online\n"
		print "    [00] Back to main menu\n"
		stresstest = raw_input("lzmx > ")
		
		if stresstest == "01" or stresstest == "1":
			torshammer()
		elif stresstest == "02" or stresstest == "2":
			slowloris()
		elif stresstest == "03" or stresstest == "3":
			fl00d12()
		elif stresstest == "04" or stresstest == "4":
			goldeneye()
		elif stresstest == "05" or stresstest == "5":
			xerxes()
		elif stresstest == "06" or stresstest == "6":
			planetwork_ddos()
		elif stresstest == "07" or stresstest == "7":
			hydra()
		elif stresstest == "08" or stresstest == "8":
			black_hydra()
		elif stresstest == "09" or stresstest == "9":
			xshell()
		elif stresstest == "10":
			sanlen()
		elif stresstest == "00" or stresstest == "0":
			restart_program()
		else:
			print "\nERROR: Wrong Input"
			timeout(2)
			restart_program()
	
	elif lazymux == "4" or lazymux == "04":
		print "\n    [01] Hydra"
		print "    [02] FMBrute"
		print "    [03] HashID"
		print "    [04] Facebook Brute Force 3"
		print "    [05] Black Hydra"
		print "    [06] Hash Buster"
		print "    [07] FBBrute"
		print "    [08] Cupp"
		print "    [09] InstaHack"
		print "    [10] Indonesian Wordlist"
		print "    [11] Xshell"
		print "    [12] Social-Engineering"
		print "    [13] BlackBox"
		print "    [14] Hashzer"
		print "    [15] Hasher"
		print "    [16] Hash-Generator"
		print "    [17] nk26"
		print "    [18] Hasherdotid"
		print "    [19] Crunch"
		print "    [20] Hashcat"
		print "    [21] ASU"
		print "    [22] Katak\n"
		print "    [00] Back to main menu\n"
		passtak = raw_input("lzmx > ")
		
		if passtak == "01" or passtak == "1":
			hydra()
		elif passtak == "02" or passtak == "2":
			fmbrute()
		elif passtak == "03" or passtak == "3":
			hashid()
		elif passtak == "04" or passtak == "4":
			fbBrute()
		elif passtak == "05" or passtak == "5":
			black_hydra()
		elif passtak == "06" or passtak == "6":
			hash_buster()
		elif passtak == "07" or passtak == "7":
			fbbrutex()
		elif passtak == "08" or passtak == "8":
			cupp()
		elif passtak == "09" or passtak == "9":
			instaHack()
		elif passtak == "10":
			indonesian_wordlist()
		elif passtak == "11":
			xshell()
		elif passtak == "12":
			social()
		elif passtak == "13":
			blackbox()
		elif passtak == "14":
			hashzer()
		elif passtak == "15":
			hasher()
		elif passtak == "16":
			hashgenerator()
		elif passtak == "17":
			nk26()
		elif passtak == "18":
			hasherdotid()
		elif passtak == "19":
			crunch()
		elif passtak == "20":
			hashcat()
		elif passtak == "21":
			asu()
		elif passtak == "22":
			katak()
		elif passtak == "00" or passtak == "0":
			restart_program()
		else:
			print "\nERROR: Wrong Input"
			timeout(2)
			restart_program()
	
	elif lazymux == "5" or lazymux == "05":
		print "\n    [01] sqlmap"
		print "    [02] Webdav"
		print "    [03] xGans"
		print "    [04] Webdav Mass Exploit"
		print "    [05] WPSploit"
		print "    [06] sqldump"
		print "    [07] Websploit"
		print "    [08] sqlmate"
		print "    [09] sqlokmed"
		print "    [10] zones"
		print "    [11] Xshell"
		print "    [12] SH33LL"
		print "    [13] XAttacker"
		print "    [14] XSStrike"
		print "    [15] Breacher"
		print "    [16] OWScan"
		print "    [17] ko-dork"
		print "    [18] ApSca"
		print "    [19] amox"
		print "    [20] FaDe"
		print "    [21] AUXILE"
		print "    [22] HPB"
		print "    [23] inther"
		print "    [24] Atlas"
		print "    [25] MaxSubdoFinder\n"
		print "    [00] Back to main menu\n"
		webhack = raw_input("lzmx > ")
    
  
