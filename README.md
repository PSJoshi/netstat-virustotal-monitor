netstat-virustotal-monitor
==========================

netstat is a de-facto command for monitoring incoming and outgoing network connections on Linux/Windows platforms. A python-based script enhances netstat command output to include city, country and ASN information using Maxmind Geolite databases(http://dev.maxmind.com/geoip/legacy/geolite/). In addition, it also checks whether the remote IP is in malicious or not using Virustotal database(https://www.virustotal.com/en/documentation/public-api/) and DNS-based Blackhole List (DNSBL) databases(http://www.dnsbl.info/dnsbl-database-check.php).

A big thanks Giampaolo Rodola for writing psutils(http://pythonhosted.org/psutil/) and its nice API. 

