#!/usr/bin/python
#    Copyright (C) 2013 Christoph Mueller, Hasso-Plattner-Institut fuer Softwaresystemtechnik Potsdam GmbH
#    christoph.mueller@student.hpi.uni-potsdam.de

#    This file is part of dns_recon.py.

#    dns_recon.py is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.

#    dns_recon.py is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.

#    You should have received a copy of the GNU General Public License
#    along with dns_recon.py.  If not, see <http://www.gnu.org/licenses/>.

from sets import Set
from collections import OrderedDict
import sys, hashlib, base64, string
import csv
import sqlite3
import dns.query
import dns.zone
from dns.exception import DNSException
import dns.dnssec
from dns.resolver import Resolver, NoAnswer
from itertools import product
import cProfile
import pstats
import pprint
from multiprocessing import Process
import os
import traceback
from zone_walk import *
import signal
import subprocess
import random
import bisect

import dns.message
import dns.query
import dns.rdatatype
import dns.resolver
import dns.reversename
import dns.zone
import dns.rdata
import dns.rdatatype
import dns.flags
from netaddr import *
from lib.dnshelper import DnsHelper

PROFILE = False # set to true to get profiling of code execution
MIN_LENGTH = 1  # minimum length of entries for brute forcing
MAX_LENGTH = 4  # maximum length of entries for brute forcing
# defaults that we configured for our test server, not really used anymore
SALT = "FFFFFF"
ITERATIONS = 5
ALGO=1
DICTIONARY_PATH = "results/dictionary.csv" # the dictionary file


##############################################
# Zone Walking
##############################################
class TimeoutException(Exception): 
    pass 

def get_nsec_param(zone, ns):
  # The NSEC3 fields are: 'algorithm flags iterations salt'. The salt is hexadecimal. 
  res = DnsHelper(zone, ns, 2)
  default = (ALGO, 0, ITERATIONS, SALT)
  result = default

  query = "dig +dnssec any @{0} {1} | grep NSEC3".format(ns, zone)
  try:
    response = subprocess.check_output(query, shell=True)
  except subprocess.CalledProcessError:
    print "Could not retrieve zone records. Is the server correct? NS: {0}".format(ns)
    exit(-1)

  for line in response.split("\n"):
    record = line.split()
    if (len(record) >= 8 and record[3] == "NSEC3PARAM"):
      result = (record[4], record[5], record[6], record[7])
      break
  return result

def has_nsec(zone, ns):
  res = DnsHelper(zone, ns, 2)
  return get_nsec_type(zone, res)

def get_ns(zone):
  res = DnsHelper(zone)
  return res.get_ns()[0][2] # ip address of first NS record

def transfer_zone(ns, zone):
  result = []
  def timeout_handler(signum, frame):
      raise TimeoutException()
  signal.signal(signal.SIGALRM, timeout_handler) 
  signal.alarm(2)
  try:
    z = dns.zone.from_xfr(dns.query.xfr(ns, zone))
    names = z.nodes.keys()
    names.sort()
    for n in names:
      if str(n) != "@":
        result.append(str(n))
        #print z[n].to_text(n)
  except TimeoutException:
    print "Zone transfer timed out."
    signal.alarm(0)
    return []
  except Exception as e:
    print "Zone transfer failed."
    #traceback.print_exc()
    signal.alarm(0)
    return []
  signal.alarm(0)
  return result

def walk_zone(ns, zone):
  """ Will create an array of dictionaries (one for each record)."""
  res = DnsHelper(zone, ns, 2)
  result = walk_nsec_zone(res, zone, ns)
  return result


def random_guess(size=8, symbols=string.ascii_lowercase + string.digits):
  return ''.join(random.choice(symbols) for x in range(size))

def gather_hashes(ns, zone, nsecparam):
  iterations = nsecparam[2]
  salt = nsecparam[3]
  query = "dig +dnssec any @{0} {1} | grep NSEC3"
  zone_hash = hash_record(zone.lower(), salt, iterations)

  guesses = []  # random character strings of length 8
  hashes = []   # hashes of our guesses
  gaps = dict()
  
  try:
    while(True):
      # TODO: might not want to make the guess (and thus request) if we know that the resulting gap has already been discovered
      guess = random_guess()
      hashed_guess = hash_record(guess + ".{0}".format(zone.lower()) , salt, iterations)
      
      bisect.insort(guesses, guess)
      bisect.insort(hashes, hashed_guess)
      #guesses.append(guess)
      #hashes.append(hashed_guess)
      current_query = query.format(ns, guess + "." + zone)

      try:
        response = subprocess.check_output(current_query, stderr=subprocess.STDOUT, shell=True)
      except subprocess.CalledProcessError, e:
        print "Could not dig for NSEC3 hashes. Returned: \n", e.output
	return set(gaps.keys())
      first = None
      second = None
      third = None
      for line in response.split("\n"):
        record = line.split()
        if (len(record) >= 4 and record[3] == "NSEC3"):
          if (not first):
            strip_len = len(zone) + 2
            first = record[0][:-strip_len]     # strip .zone from end, e.g. .hpi.de. (with dot at the end!) is appended to the hash, so we have to remove it
          elif (not second):
            second = record[0][:-strip_len]
            third = record[8].lower()
            
      if (first in gaps and gaps[first] == second):
        print "already have first"
        if (second in gaps):
          print "already have second"
          if (third in gaps):
            print "already have third"
            continue
          else:
            print "no link"
        else:                
          gaps[second] = third
      else:                
        gaps[first] = second

        if (second in gaps):
          print "already have second"
          if (third in gaps):
            print "already have third"
          else:
            print "no link"
        else:                
          gaps[second] = third
          # we built a connection to the next sequence
          print "we built a connection to the next sequence starting with " + third

      if (first in gaps and second != gaps[first]):
        print "something went wrong! With " + first + " and " + second
        exit(-1)

      # verify if we are done 
      # TODO: might not want to go through entire list each time and instead keep missing hashes somewhere else
      if (ring_complete(gaps, zone_hash)):
        print "Gathering complete!"
        break      
      
  except KeyboardInterrupt:
    print "Gathering interrupted!"
    print "Guesses made: \t{0}".format(len(guesses))
    print "Hashes gathered: \t{0}".format(len(gaps))
    return set(gaps.keys())

  print "Guesses made: \t{0}".format(len(guesses))
  print "Hashes gathered: \t{0}".format(len(gaps))
  return set(gaps.keys())

def ring_complete(gaps, zone_hash):
  next = zone_hash
  while next:
    if next in gaps:
      if (gaps[next] == zone_hash):
        return True
      next = gaps[next]
    else:
      return False

# return hashes that match entries in our table (list of tuples)
def compare(hashes, rainbow_table):
  l = []
  for h in hashes:
    if (rainbow_table.get(h)):
      l.append((h, rainbow_table.get(h)))
  return l

def find_in(hashes, x):
  for h in hashes:
    if h and x and h.lower() == x.lower():
      return h

# TODO: WIP multiprocessing, not finished or used anywhere so far
def spawn_processes(data, num_procs):
  procs = []

  chunksize = len(data)/num_procs
  remainder = len(data)%num_procs
  print "Processing " + str(len(data)) + " entries with " + str(num_procs) + " processes (chunksize: " + str(chunksize) + ")."
  for i in range(num_procs):
      p = Process(
              target=collect_zone_info,
              args=([data[chunksize * i:chunksize * (i + 1)]]))
      procs.append(p)
      p.start()

  # do the rest ourselves
  if remainder > 0:
    collect_zone_info(data[chunksize * num_procs + 1:])
  # Wait for all worker processes to finish
  i = 1
  for p in procs:
    p.join()
    print "Process " + str(i) + "/" + str(num_procs) + " finished."
    exit()
    i += 1

def break_hashes(zone, hashes, nsec_param):
  try:
    remaining_hashes = hashes
    #resolved_hashes = []
    resolved_hashes = Set()
    salt = nsec_param[3]#nsec_param.salt
    iterations = nsec_param[2]#nsec_param.iterations
    algorithm = nsec_param[0]#nsec_param.algorithm # will be ignored as we only have the rsa-sha1 algorithm implemented anyway...
    print "Hashing Info:\n"+"\n\tAlgorithm:\t" + dns.dnssec.algorithm_to_text(algorithm) + "\n\tSalt:\t\t" + salt + "\n\tIterations:\t" + str(iterations)

    print "\n"
    print "=============NSEC3 Recon============="
    print "\n"
    print "Total unresolved hashes:\t" + str(len(remaining_hashes))
    # try the dictionary first
    #resolved_hashes.extend(compare(remaining_hashes, hash_dictionary(zone, salt, iterations)))
    resolved_hashes.update(compare(remaining_hashes, hash_dictionary(zone, salt, iterations)))
    print "After Dictionary Found:\t\t" + str(len(resolved_hashes))
    # if there is still something left, try the brute force approach
    l = MIN_LENGTH
    while (len(resolved_hashes) < len(hashes) and l < MAX_LENGTH + 1):
      hash_tuples = yield_combinations(zone, salt, iterations, l)
      for t in hash_tuples:
        if (find_in(remaining_hashes, t[0])):
          resolved_hashes.add(t)
          #resolved_hashes.extend([t])
      l += 1
    print "After Bruteforce Found:\t\t" + str(len(resolved_hashes))

    print "\n"
    print "================DONE================="
    print "\n"
    print "Hashes solved:\t\t" + str(len(set(resolved_hashes)))
    print "Hashes unresolved:\t" + str(len(hashes) - len(set(resolved_hashes)))
    return resolved_hashes
  except KeyboardInterrupt:
    print "Prematurely interrupted by user."
    return resolved_hashes


def analyze_zone(zone, ns):
  print "\n"
  print "=============Commencing=============="
  print "\n"
  if (not ns):
    ns = get_ns(zone)
  axfr = transfer_zone(ns, zone)
  nsec_type = has_nsec(zone, ns)
  
  if (axfr):
    print "Zone Transfer enabled."
    return axfr # that was easy...
  if (nsec_type == "NSEC"):
    print "DNSSEC with NSEC."
    return walk_zone(ns, zone)  # NSEC v1, we can walk the zone in clear text
  if (nsec_type == "NSEC3"):
    print "DNSSEC with NSEC3."
    nsec_param = get_nsec_param(zone, ns)
    return break_hashes(zone, gather_hashes(ns, zone, nsec_param), nsec_param)
  return [] # no axfr, no dnssec. We are done for the scope of this project. Could still try google or other services...

##############################################
# Hashing
##############################################
DICTIONARY = Set() 
#read from csv
def read_from_csv():
  if os.path.isfile(DICTIONARY_PATH):
    with open(DICTIONARY_PATH, 'rb') as csvfile:
      spamreader = csv.reader(csvfile, delimiter=',', quotechar='"')
      for row in spamreader:
        DICTIONARY.add(row[0])
  else:
    print "No dictionary found! Tried: %s" % DICTIONARY_PATH

# code from http://pypi.python.org/pypi/django-powerdns-manager
def hash_record(qname, salt, iterations):    
  qname = wirename(qname.encode('ascii'))    
  # Prepare salt
  salt = salt.decode('hex')    
  hashed_name = sha1(qname+salt)
  i = 0
  while i < int(iterations):
    hashed_name = sha1(hashed_name+salt)
    i += 1
  
  # Do standard base32 encoding
  final_data = base64.b32encode(hashed_name)
  # Apply the translation table to convert to base32hex encoding.
  final_data = final_data.translate(
    string.maketrans('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567',
    '0123456789ABCDEFGHIJKLMNOPQRSTUV'))
  return final_data.lower()

def wirename(s):
  return ''.join(chr(len(label))+label for label in s.split('.'))+chr(0)

def sha1(s):
  d = hashlib.sha1()
  d.update(s)
  return d.digest()

def build_hash_tuple(name, salt, iterations):
  return (hash_record(name, salt, iterations), name)

def yield_dictionary(zone, iterations):
  read_from_csv()
  for qname in DICTIONARY:
    yield build_hash_tuple(qname + ".{0}".format(zone.lower()), salt, iterations)

def yield_combinations(zone, salt, iterations, length):
  symbols = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ" + "-" + "_"
  symbols = ''.join(sorted(symbols))
  for qname in product(symbols, repeat=length):
    yield build_hash_tuple("".join(qname).lower() + ".{0}".format(zone.lower()), salt, iterations)

def hash_dictionary(zone, salt, iterations):
  dictionary = OrderedDict()
  read_from_csv()

  # add the zone itself to the dictionary:
  zonename = zone.lower()
  hashed_name = hash_record(zonename, salt, iterations)
  dictionary[hashed_name] = zonename
  
  for qname in DICTIONARY:
    name = qname + ".{0}".format(zone.lower())
    hashed_name = hash_record(name, salt, iterations)
    dictionary[hashed_name] = name
  return dictionary
    
def hash_combinations(zone, salt, iterations, length):
  dictionary = OrderedDict()
  symbols = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ" + "-" + "_" # underscore not allowed for hostnames but for other DNS names
  symbols = ''.join(sorted(symbols))
  for qname in product(symbols, repeat=length):
    name = "".join(qname).lower() + ".{0}".format(zone.lower())
    hashed_name = hash_record(name, salt, iterations)
    dictionary[hashed_name] = name
  return dictionary

##############################################
# Main
##############################################
def print_results(res):
    print "Results:\n"
    pp = pprint.PrettyPrinter(indent=4)
    pp.pprint(res)
    #pp.pprint(set(res))

def main():
    zone = sys.argv[1]
    ns = ""
    if (len(sys.argv) == 3):
      ns = sys.argv[2]
    # Step 1: get NSEC3PARAM if available and determine salt, no. of iterations, algorithm
    # Step 2: take domain and zone-walk all (hashed) records
    # Step 3: build dictionary and check against hashes
    # Step 4: bruteforce attack check against hashes
    # Step 5: output all records in the zone
    
    if (PROFILE):
      profile_log = 'profiling/statisticsL'+ str(MIN_LENGTH) + '-' + str(MAX_LENGTH) + '.stats'
      cProfile.run('print_results(analyze_zone("{0}", "{1}"))'.format(zone, ns), profile_log)
      
      print "\n"
      print "===============STATS================="
      print "\n"
      p = pstats.Stats(profile_log)
      p.sort_stats('cumulative').print_stats(10)
    else:
      print_results(analyze_zone(zone, ns))

if __name__ == "__main__":
    main()
