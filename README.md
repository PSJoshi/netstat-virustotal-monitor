netstat-virustotal-monitor
==========================

netstat is a de-facto command for monitoring incoming and outgoing network connections on Linux/Windows platforms. A python-based script enhances netstat command output to include city, country and ASN information using Maxmind Geolite databases(http://dev.maxmind.com/geoip/legacy/geolite/). In addition, it also checks whether the remote IP is in malicious or not using Virustotal database(https://www.virustotal.com/en/documentation/public-api/) and DNS-based Blackhole List (DNSBL) databases(http://www.dnsbl.info/dnsbl-database-check.php).

A big thanks to Giampaolo Rodola for writing psutils(http://pythonhosted.org/psutil/) and its nice API. Also thanks to Maxmind(https://www.maxmind.com/en/home), Virustotal(https://www.virustotal.com/) and DNSBL community for providing services.

Installation
==============
Netstat-virustotal-monitor has been tested on CentOS distribution but should work on any platform without any issues.

Running
=========
1. Do not forget to add virustotal key in configuration file - netstat-monitor.conf
2. Also, set file paths for City,Country and ASN Maxmind databases in the configuration file - netstat-monitor.conf
	- Country - http://geolite.maxmind.com/download/geoip/database/GeoLiteCountry/GeoIP.dat.gz
	- City - http://geolite.maxmind.com/download/geoip/database/GeoLiteCity.dat.gz
	- ASN - http://download.maxmind.com/download/geoip/database/asnum/GeoIPASNum.dat.gz

To run the script:

netstat-main.py --config ./netstat-monitor.conf

