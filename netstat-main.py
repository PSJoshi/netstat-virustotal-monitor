#!/usr/bin/env python
"""
This module displays information about network connections on a system using psutil.The output of psutils is enhanced to
 include city,country and ASN information using Maxmind Geo databases.
 In addition, remote addresses are checked for their presence in Virustotal database and domain name system (DNS)
 blacklist databases (DNSBL). An e-mail is generated when any suspicious IP connections are noticed.
"""
import os
import sys
import psutil
import pygeoip
import logging.handlers
import logging
import argparse
import ConfigParser
from IPy import IP
#DNSBL checks
from dnsbl import DNSBL_check
# virustotal checks
from virustotal import Virustotal

def setup_logging():
    """ set up logging"""
    logging.basicConfig(level=logging.INFO)  # (level=logging.DEBUG)
    logger = logging.getLogger(__name__)

    # set up file handler
    #handler = logging.FileHandler('netstat-monitor.log')
    handler = logging.handlers.RotatingFileHandler('netstat-monitor.log', maxBytes=20000, backupCount=5)
    handler.setLevel(logging.INFO)  # logging format
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)

    # add the handlers to the logger
    logger.addHandler(handler)
    return logger


def commandline_options(log_instance):
    """  command line arguments """
    args = None
    try:
        # good tutorial on argparse - http://pymotw.com/2/argparse/
        parser = argparse.ArgumentParser(description='This program displays enchanced network connections information \
		 and monitors if any network connections are malicious using Virustotal and DNSBL databases.')

        parser.add_argument('--config', action='store', required=True, help='Configuration file', dest='config_file')

        args, unknown = parser.parse_known_args()

        if not args.config_file:
            args.error("Error - Please enter full path of configuration file.")

    except Exception, e:
        log_instance.error('Error while parsing command line arguments - %s' % str(e).strip(), exc_info=True)
    return args


def _confGetSection(conf, section):
    """returns the value of all the configuration options in one section or None if not set"""
    try:
        options = {}
        for i in conf.items(section):
            options[i[0]] = i[1]
        return options
    except ConfigParser.Error:
        return None  # ignore missing values


def _confGet(conf, section, option):
    """returns the value of the configuration option or None if not set"""
    try:
        return conf.get(section, option)
    except ConfigParser.Error:
        return None  # ignore missing values


def config_options(config_file, log_instance):
    """Read configuration file"""

    try:
        conf = ConfigParser.ConfigParser()
        conf.read(config_file)
        connections_type = _confGet(conf, "settings", "connections_type") or None
        virustotal_key = _confGet(conf, "settings", "virustotal_key") or None
        refresh_interval = _confGet(conf, "settings", "refresh_interval") or 5
        # proxy
        proxy_user = _confGet(conf, "proxy", "user") or None
        proxy_password = _confGet(conf, "proxy", "password") or None
        proxy_server = _confGet(conf, "proxy", "server") or None
        proxy_port = _confGet(conf, "proxy", "port") or 8080
        asn_db = _confGet(conf, "GeoIP_databases", "asn_database") or None
        country_db = _confGet(conf, "GeoIP_databases", "country_database") or None
        city_db = _confGet(conf, "GeoIP_databases", "city_database") or None

        return connections_type, virustotal_key, refresh_interval, city_db, country_db, asn_db, \
               proxy_user, proxy_password, proxy_server, proxy_port

    except Exception, e:
        log_instance.error('Error while reading configuration file - %s' % str(e).strip(), exc_info=True)

def find_asn(log_instance,asn_db,ip):
    """
    returns ASN information for ip
    """
    try:
        if asn_db and ip:
            gi_asn=pygeoip.GeoIP(asn_db)
            asn_name = gi_asn.org_by_addr(ip)
            return asn_name
        else:
            return ''
    except Exception, e:
        log_instance.error("Error while getting ASN information for ip-%s :%s"%(ip,str(e).strip()),exc_info=True)

def find_country(log_instance,country_db,ip):
    """
    returns country name and code for ip
    """
    try:
        if country_db and ip:
            gi_country=pygeoip.GeoIP(country_db)
            country_name = gi_country.country_name_by_addr(ip)
            return country_name
        else:
            return ''
    except Exception, e:
        log_instance.error("Error while getting country information for ip-%s :%s"%(ip,str(e).strip()),exc_info=True)

def find_city(log_instance,city_db,ip):
    """
    returns city for ip
    """
    city_name=''
    city_latitude=None
    city_longitude=None
    try:
        if city_db and ip:
            gi_city=pygeoip.GeoIP(city_db)
            city_info = gi_city.record_by_addr(ip)
            city_name = city_info.get('city','')
            city_latitude = city_info.get('latitude',None)
            city_longitude = city_info.get('longitude',None)
            return city_name,city_latitude,city_longitude
        else:
            return '',None,None
    except Exception, e:
        log_instance.error("Error while getting city information for ip-%s :%s"%(ip,str(e).strip()),exc_info=True)

def _is_ip_private(ip):
    """Determine if IP address belongs to a private address."""
    is_private = False
    test_ip = IP(ip)
    if test_ip.iptype().lower()=='private' or test_ip.iptype().lower()=='loopback':
        is_private=True
    return is_private

def check_ip_using_dnsbl(log_instance,ip):
    try:
        dnsbl_instance = DNSBL_check(ip=ip)
        dnsbl_results = dnsbl_instance.check()
        ip_result =[item for item in dnsbl_results if item[1]!=False]
        # list is empty. No malicious IP found
        if ip_result:
            return True
        else:
            return  False
    except Exception,e:
        log_instance.error("Error while checking IP against DNSBL servers-%s"%str(e).strip())


def check_ip_using_virustotal(log_instance,api_key, user, password, server, port, ip):
    try:
        # class instance
        client_instance = Virustotal(api_key, debug=0, error=0)
        proxy_handle = None
        # check if all proxy parameters are entered or not.
        if server and port and user and password:
            # setup proxy
            proxy_handle = client_instance.setup_proxy(server, port, user, password)
        else:
            log_instance.warning("No proxy parameters are not entered and hence,a direct network connection to internet \
        is assumed for checking ip against virustotal database.")
        # IP report
        if proxy_handle:
            #check url
            response = client_instance.ip_reporter(ip, proxy_handle)
        else:
            #no proxy
            response = client_instance.ip_reporter(ip)
        # check if malware presence is seen by virustotal scan
        if 'detected_urls' in response:
            return True
        else:
            return False
    except Exception,e:
        log_instance.error("Error while checking IP against Virustotal database-%s"%str(e).strip())

if __name__ == '__main__':
    try:
        # setup logging
        log_instance = setup_logging()
        # read command line arguments
        cmd_args = commandline_options(log_instance)
        # check if config file exists. if yes, read configuaration parameters
        if os.path.isfile(cmd_args.config_file):
            connections_type, virustotal_key, refresh_interval, city_db, country_db, asn_db, proxy_user, proxy_password, \
            proxy_server,proxy_port  = config_options(cmd_args.config_file, log_instance)

        if not (asn_db and country_db and city_db):
            log_instance.warning("Some of the Geo-databases do not exists. All the network connection information \
            may not be displayed correctly.")

        # network connections
        network_connections = psutil.net_connections(kind=connections_type)

        ip_asn=ip_country=ip_city=None

        for item in network_connections:
            # check if remote address is valid and is not private
            if item.raddr:
                if not _is_ip_private(item.raddr[0]):
                    if item.pid:
                        p=psutil.Process(item.pid)
                        #print p.cmdline(),p.exe(),p.get_cpu_percent()
                        #print item.laddr[0], item.laddr[1],item.raddr[0],item.raddr[1],item.status,item.pid

                        # asn
                        if item.raddr[0]:
                            ip_asn = find_asn(log_instance,asn_db,item.raddr[0])
                        else:
                            ip_asn=None

                        # country
                        if item.raddr[0]:
                            ip_country = find_country(log_instance,country_db,item.raddr[0])
                        else:
                            ip_country=None

                        # city
                        if item.raddr[0]:
                            ip_city = find_city(log_instance,city_db,item.raddr[0])
                        else:
                            ip_city=None

                        #print "Virustotal result for ip -%s : %s"%(item.raddr[0],check_ip_using_virustotal(log_instance,virustotal_key,proxy_user,proxy_password,proxy_server,proxy_port,item.raddr[0]))
                        #print "DNSBL result for ip -%s : %s"%(item.raddr[0],check_ip_using_dnsbl(log_instance,item.raddr[0]))

                        virustotal_result = check_ip_using_virustotal(log_instance,virustotal_key,proxy_user,proxy_password,proxy_server,proxy_port,item.raddr[0])
                        dnsbl_result = check_ip_using_dnsbl(log_instance,item.raddr[0])

                        print item.laddr[0], item.laddr[1],item.raddr[0],item.raddr[1],item.status,item.pid,p.exe(), \
                            p.cpu_percent(),ip_asn,ip_country,ip_city,virustotal_result,dnsbl_result

    except Exception, e:
        log_instance.error('The network connections can not be displayed because of error- %s' %str(e).strip(),exc_info=True)
