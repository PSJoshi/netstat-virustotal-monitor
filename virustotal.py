# VirusTotal's Public API lets you upload and scan files, submit and scan URLs, access finished scan reports and make automatic comments on URLs and samples without the need of using the HTML website interface.
# A python-based script will be used to check if the file/process is a virus/spyware/malware. 
# The format for the API is HTTP POST requests with JSON object responses 
#
#Limits - The number of requests are limited to at most 4 requests of any nature in any given 1 minute time frame.

import urllib
import urllib2
import hashlib

class Virustotal():

	def __init__(self,key='',debug=0,error=0):
		""" Pass on your API key - http://code.google.com/apis/safebrowsing/key_signup.html
			Arguments :
			key - API key
			debug - 
				1 - print debug output to stdout 
				0 - Disabled
			error - 
				1 - print error output to stdout
				0 - Disabled
		"""
		self.apikey = key
		self.debug = debug
		self.error = error
		self.url_scan = "https://www.virustotal.com/vtapi/v2/url/scan"
		self.url_report = "https://www.virustotal.com/vtapi/v2/url/report"
		self.file_scan = "https://www.virustotal.com/vtapi/v2/file/scan"
		self.file_report = "https://www.virustotal.com/vtapi/v2/file/report"
		self.ip_report = "http://www.virustotal.com/vtapi/v2/ip-address/report"
		self.domain_report = "http://www.virustotal.com/vtapi/v2/domain/report"


		if self.apikey == '':
			#raise ValueError('Missing Virustotal API key')
			self.__debug('Missing Virustotal API key')
			self.__error('Missing Virustotal API key')

	def __debug(self,message = ''):
		
		"""
			Debug print
		"""

		if self.debug == 1:
			print message + '\n'
	
	def __error(self,message = ''):
		
		"""
			Error handling
		"""

		if self.debug == 1 and self.error == 1:
			print message + '\n'
	
	
	def setup_proxy(self,name,port,user,passwd):
		
		"""
			set-up proxy with basic authentication
		"""

		proxy = urllib2.ProxyHandler({'http':'http://' + user + ':' + passwd + '@' + name + ':' + port,'https':'http://' + user + ':' + passwd + '@' + name + ':' + port})
		
		auth = urllib2.HTTPBasicAuthHandler()

		opener = urllib2.build_opener(proxy, auth, urllib2.HTTPHandler)

		return opener
	
	def compute_md5(self,md5_file, block_size=8192):
		"""
			Find md5 hash
		"""
		md5 = hashlib.md5()
		
		f = open(md5_file,'rb')
		
		while True:
			data = f.read(block_size)
			if not data:
				break
			md5.update(data)
	
		return md5.digest()

	def url_scanner(self,check_url,proxy_handler=None):
		"""
			Submit a url to VirusTotal for analysis
		"""

		response = None
		
		self.__debug("Submitting URL - %s to VirusTotal for analysis "%(check_url))
		
		# request using proxy or not
		if proxy_handler:
	
			urllib2.install_opener(proxy_handler)

		# POST request parameters
		post_parameters = {"url": check_url,"apikey": self.apikey}
		
		encoded_data = urllib.urlencode(post_parameters)
		
		req = urllib2.Request(self.url_scan, encoded_data)
		
		try:
		
			response = urllib2.urlopen(req)
		
		except Exception,e:
			
			self.__debug("Error while submitting URL - %s to VirusTotal for analysis -%s." %(check_url,e.strip()))

		scan_result = response.read()
		
		# http response headers
		self.__debug("Http response headers:\n%s" %(response.info()))
		
		# http status codes
		self.__debug("Http response code:\n%s" %(response.getcode()))
		
		# http response
		self.__debug("Http response:\n%s" %(scan_result))
		
		return scan_result

	
	def url_reporter(self,report_url,proxy_handler=None):
		"""
			Check VirusTotal report for the given url
		"""

		response = None
		
		self.__debug("Getting VirusTotal report for - %s"%(report_url))
		
		# request using proxy or not
		if proxy_handler:
	
			urllib2.install_opener(proxy_handler)

		# POST request parameters
		post_parameters = {"url": report_url,"apikey": self.apikey}
		
		encoded_data = urllib.urlencode(post_parameters)
		
		req = urllib2.Request(self.url_report, encoded_data)
		
		try:
		
			response = urllib2.urlopen(req)
		
		except Exception,e:
			
			self.__debug("Error while getting VirusTotal report for URL - %s - %s." %(report_url,e.strip()))

		report_result = response.read()
		
		# http response headers
		self.__debug("Http response headers:\n%s" %(response.info()))
		
		# http status codes
		self.__debug("Http response code:\n%s" %(response.getcode()))
		
		# http response
		self.__debug("Http response:\n%s" %(report_result))
		
		return report_result


	
	def file_scanner(self,file_name,proxy_handler=None):

		"""Check VirusTotal report for the given file's - MD5 hash"""
		
		# this module is required as urllib2 can not handle multipart/form-data encoding
		
		try:
		
			from urllib2_post import MultiPartForm
		
		except Exception,e:
			self.__debug("Error while importing module - MultiPartForm")
			self.__error("Error while importing module - MultiPartForm")

		response = None
		
		self.__post_form = MultiPartForm()
		
		self.__post_form.add_field("apikey",self.apikey)
		
		file_handle = open(file_name,"rb")

		self.__post_form.add_file("file",file_name,file_handle)

		self.__debug("Submitting file - %s to VirusTotal for analysis"%(file_name))
		
		# request using proxy or not
		if proxy_handler:
	
			urllib2.install_opener(proxy_handler)

		req = urllib2.Request(self.url_report)

		self.__form_body = str(self.__post_form)

		req.add_header('Content-type', self.__post_form.get_content_type())

		req.add_header('Content-length', len(self.__form_body))

		req.add_data(self.__form_body)
		try:
			response = urllib2.urlopen(req)
		except Exception,e:
			self.__debug("Error while submitting file - %s to VirusTotal - %s." %(file_name,e.strip()))

		report_result = response.read()
		
		# http response headers
		self.__debug("Http response headers:\n%s" %(response.info()))
		
		# http status codes
		self.__debug("Http response code:\n%s" %(response.getcode()))
		
		# http response
		self.__debug("Http response:\n%s" %(report_result))
		
		return report_result


	def file_reporter(self,filename,md5_hash,proxy_handler=None):
		"""
			Check VirusTotal report for the given file's - MD5 hash
		"""

		response = None
		
		self.__debug("Getting VirusTotal report for - %s"%(filename))
		
		# request using proxy or not
		if proxy_handler:
	
			urllib2.install_opener(proxy_handler)

		# POST request parameters
		post_parameters = {"resource": md5_hash,"apikey": self.apikey}
		
		encoded_data = urllib.urlencode(post_parameters)
		
		req = urllib2.Request(self.url_report, encoded_data)
		
		try:
		
			response = urllib2.urlopen(req)
		
		except Exception,e:
			
			self.__debug("Error while getting VirusTotal report for file - %s - %s." %(filename,e.strip()))

		report_result = response.read()
		
		# http response headers
		self.__debug("Http response headers:\n%s" %(response.info()))
		
		# http status codes
		self.__debug("Http response code:\n%s" %(response.getcode()))
		
		# http response
		self.__debug("Http response:\n%s" %(report_result))
		
		return report_result


	def domain_reporter(self,check_domain,proxy_handler=None):
		"""
			Check VirusTotal report for the given domain
		"""

		response = None
		
		self.__debug("Getting VirusTotal report for domain - %s"%(check_domain))
		
		# request using proxy or not
		if proxy_handler:
	
			urllib2.install_opener(proxy_handler)

		# GET request parameters
		get_parameters = {"domain": check_domain,"apikey": self.apikey}
		
		encoded_data = urllib.urlencode(get_parameters)
		
		try:
		
			response = urllib2.urlopen('%s?%s'%(self.domain_report,encoded_data))
		
		except Exception,e:
			
			self.__debug("Error while getting VirusTotal domain report for URL - %s - %s." %(domain_url,e.strip()))

		report_result = response.read()
		
		# http response headers
		self.__debug("Http response headers:\n%s" %(response.info()))
		
		# http status codes
		self.__debug("Http response code:\n%s" %(response.getcode()))
		
		# http response
		self.__debug("Http response:\n%s" %(report_result))
		
		return report_result


	def ip_reporter(self,check_ip,proxy_handler=None):
		"""
			Check VirusTotal report for the given ip
		"""

		response = None
		
		self.__debug("Getting VirusTotal report for IP - %s"%(check_ip))
		
		# request using proxy or not
		if proxy_handler:
	
			urllib2.install_opener(proxy_handler)

		# GET request parameters
		get_parameters = {"ip": check_ip,"apikey": self.apikey}
		
		encoded_data = urllib.urlencode(get_parameters)
		
		try:
		
			response = urllib2.urlopen('%s?%s'%(self.ip_report,encoded_data))
		
		except Exception,e:
			
			self.__debug("Error while getting VirusTotal IP report for URL - %s - %s." %(check_ip,e.strip()))

		report_result = response.read()
		
		# http response headers
		self.__debug("Http response headers:\n%s" %(response.info()))
		
		# http status codes
		self.__debug("Http response code:\n%s" %(response.getcode()))
		
		# http response
		self.__debug("Http response:\n%s" %(report_result))
		
		return report_result
	
	