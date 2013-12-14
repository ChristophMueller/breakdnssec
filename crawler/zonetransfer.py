#!/usr/bin/python
#    Copyright (C) 2013 Christoph Mueller, Jannik Streek, Hasso-Plattner-Institut fuer Softwaresystemtechnik Potsdam GmbH
#    christoph.mueller@student.hpi.uni-potsdam.de
#    jannik.streek@student.hpi.uni-potsdam.de

#    This file is part of zonetransfer.py.

#    zonetransfer.py is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.

#    zonetransfer.py is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.

#    You should have received a copy of the GNU General Public License
#    along with zonetransfer.py.  If not, see <http://www.gnu.org/licenses/>.

#!/usr/bin/python
from xgoogle.search import GoogleSearch, SearchError
from sets import Set
import dns.query
import dns.zone
from dns.exception import DNSException
import dns.resolver
import errno
from socket import error as socket_error
import ping
import sys
import signal
from collections import Counter
import operator
import csv
import sqlite3
from multiprocessing import Process
import os
import MySQLdb
import traceback

# db connection info
HOSTNAME = "localhost"
USERNAME = "root"
PASSWORD = ""
DATABASE = "ipv6"

#parameters
csv_lower_limit = 0#180000
csv_upper_limit = 1000000#200000
mode = 1 #0 for google, 1 for csv

#global data set
global_set = Set() 

#helper functions
class TimeoutException(Exception): 
    pass 

def find_nth(haystack, needle, n):
  start = haystack.find(needle)
  while start >= 0 and n > 1:
    start = haystack.find(needle, start+len(needle))
    n -= 1
  return start

#do google lookup
def google_search(query):
  try:
    list = Set()
    for i in range(0,15):
      print "Step: " + str(i) + " for "+query
      gs = GoogleSearch(query)
      gs.results_per_page = 100
      gs.page=i
      results = gs.get_results()
      for res in results:
        url = res.url.encode('utf8')
        url = url[url.find(".")+1:find_nth(url, "/", 3)]
        if url.count('.', 0, len(url)) > 1:
          url = url[url.find(".")+1:len(url)]
        list.add(url)
        
    return list 
  except SearchError, e:
    print "Search failed: %s" % e

#look for ns servers
def alive(url):
  for key in ["ns.","ns1.","ns2.","ns3.","dns.","dns1.","dns2."]:
    try:
      lat = ping.Ping(key+url, timeout=2000).do()
      return key
    except Exception as e:
        print e
        continue
    return ""

def dig(entry):
  resolver = dns.resolver.Resolver()
  resolver.timeout = 2
  for rdata in resolver.query(entry, 'NS') :
    return str(rdata.target)

#try a axfr request
def zone_transfer(ns, url):
  def timeout_handler(signum, frame):
      raise TimeoutException()
  signal.signal(signal.SIGALRM, timeout_handler) 
  signal.alarm(2)
 # try:
  result = dns.zone.from_xfr(dns.query.xfr(ns, url))
#  except TimeoutException:
    # shit
  signal.alarm(0)
  return result

#read from csv
def read_from_csv():
  with open('top-1m.csv', 'rb') as csvfile:
    spamreader = csv.reader(csvfile, delimiter=',', quotechar='|')
    for row in spamreader:
      if int(row[0]) > csv_upper_limit:
        break
      if int(row[0]) > csv_lower_limit:
        global_set.add(row[1])

#read from google
def read_from_google(): 
  global global_set
  global_set = global_set.union(google_search("site:ns.*"))
  global_set = global_set.union(google_search("site:ns1.*"))
  global_set = global_set.union(google_search("site:ns2.*"))
  global_set = global_set.union(google_search("site:ns3.*"))
  global_set = global_set.union(google_search("site:dns.*"))
  global_set = global_set.union(google_search("site:dns1.*"))
  global_set.discard("web.tr")

  #global_set.add('ghostscript.com')
  #global_set.add('bassflava.com')
  #global_set.add('vcdq.com')
  #global_set.add('serialsws.org')
  #global_set.add('bushtarion.com')
  #global_set.add('creativecommons.org')
  #empire-host.ru
  #['ns.c4dsky.com', 'ns.grfoz.com', 'ns1.uavto.kiev.ua', 'ns.pornoitaliano.biz']
  #['ns.fpss.ru', 'ns2.917play.com.tw', 'ns.th3mirror.com']
  #['ns1.tours-malaysia.com', 'ns.starfakes.ru']
  #['ns.techshristi.com']
  #['ns.2berega.spb.ru']
  #['ns1.40konline.com']
  #['ns.suplugins.com', 'ns1.hostalfa.ru']
  #['ns.noguchi.co.jp']
  #['ns.ekitapdownload.com', 'ns1.area.lv', 'ns1.aer-bucuresti.ro']
  #['ns.neoza.ru', 'ns.pensoft.net', 'ns.smashingweb.de', 'ns1.jam-warez.ru', 'ns3.refugeforums.com']
  #['ns1.citidecor.com', 'ns1.sexvideotube.in', 'ns.adsrich.com', 'ns1.talantbox.com', 'ns.gtauto.ru']
  #['ns1.solutionsinnovative.com', 'ns1.videocharge.com', 'ns.infometeo.pl', 'ns.siatkarskaligatv.pl']
  #['ns.twilightlexicon.com', 'dns2.henannu.edu.cn']
  #['ns.bebio.pl', 'ns.prolink.ws']
  #['ns.025info.rs']
  #['ns.give-rub.ru', 'ns1.visotki.com', 'ns1.submitlinks.com']
  #['ns1.whitehousetown.jp', 'ns1.chiensderace.com', 'dns.organic.org.tw', 'ns1.audiovideoconference.com', 'ns1.murom.ru', 'ns1.usamv.ro']
  #['ns.lustset.com', 'ns.thehotmovie.com', 'ns1.speedrabbitpizza.com']
  #['ns1.cff.org.br', 'ns.comparical.com', 'ns1.reef.hk']
  #['ns.bywyld.com', 'ns1.webkoncept.pl', 'ns.fastline24.de', 'ns1.crush.com.br']
  #['ns1.all-unlock.com', 'ns3.cookgroup.com', 'ns1.camion1.com', 'ns1.bushtarion.com', 'ns1.skyclipart.ru', 'ns.rdrop.com', 'ns3.squaresound.com', 'ns.porar.com', 'ns1.mcwnetwork.com', 'ns1.dnohost.com', 'ns1.netdesignthailand.com']
  #['ns.kinoline.su']
  #['ns.apple-shop.ir']
  #['ns2.tennis.com.co', 'ns.7hp.jp']
  #['ns1.effnet.pl']

def main():
  if mode == 1:
    read_from_csv()
  elif mode == 0:
    read_from_google()
  elif mode == 2:
    global_set.add('ghostscript.com')

  spawn_processes(list(global_set), 50)

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


def collect_zone_info(data):
  conn = MySQLdb.connect(host=HOSTNAME,
                       user=USERNAME,
                        passwd=PASSWORD,
                        db=DATABASE)
  #conn = sqlite3.connect('dns.db')
  c = conn.cursor()
  keys = []
  url_counter = 0
  domains = []
  for entry in data:
    #print "-----------"+entry+"-----------"
    try:
      #ns = alive(entry)
      ns = dig(entry)
      if ns == "":
        continue
      print "transfer of " + entry + " starting ..."
      z = zone_transfer(ns,entry)#+entry
      print "...done"
      url_counter = url_counter +1
      domains.append(entry)
      dnsname = entry
      c.execute("INSERT INTO servers (name) VALUES ('"+dnsname+"')")
      #c.execute("INSERT INTO servers VALUES (NULL, '"+dnsname+"')")
      id = c.lastrowid
      names = z.nodes.keys()
      names.sort()
      for n in names:
        if str(n) != "@":
          print n
          keys.append(str(n))
          c.execute("INSERT INTO rrs (name, server_id) VALUES ('"+str(n)+"', '"+str(id)+"')")
          #c.execute("INSERT INTO rrs VALUES (NULL,'"+str(n)+"', '"+str(id)+"')")
          print z[n].to_text(n)
      conn.commit()

    except TimeoutException:
      print "Timeout. Continue..."
      continue
    except Exception as e:
      print "Some exception occured in process " + str(os.getpid())
      traceback.print_exc()
      continue
  conn.close()

#  print "Result: "
#  print "------------"
#  print '[%s]' % ', '.join(map(str, keys))
#  print "------------"
#  print domains
#  print "------------"
#  print "Counter data"
#  c = Counter(keys)
#  print "Count: " + str(url_counter)
#  print "------------"
#  print "Ranked data"
#  sorted_x = sorted(c.iteritems(), key=operator.itemgetter(1))
#  print sorted_x


if __name__ == '__main__':
  main()
