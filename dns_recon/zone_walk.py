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

from lib.dnshelper import DnsHelper
from dns.dnssec import algorithm_to_text
import dns.message
import re
import string
import netaddr
import socket
from netaddr import *

def get_nsec_type(domain, res):
  target = "0." + domain

  answer = get_a_answer(target, res._res.nameservers[0], res._res.timeout)
  for a in answer.authority:
    if a.rdtype == 50:
      return "NSEC3"
    elif a.rdtype == 47:
      return "NSEC"

def socket_resolv(target):
  """
  Resolve IPv4 and IPv6
  """
  found_recs = []
  families = get_constants('AF_')
  types = get_constants('SOCK_')
  try:
    for response in socket.getaddrinfo(target, 0):
      # Unpack the response tuple
      family, socktype, proto, canonname, sockaddr = response
      if families[family] == "AF_INET" and types[socktype] == "SOCK_DGRAM":
        found_recs.append(["A", target, sockaddr[0]])
      elif families[family] == "AF_INET6" and types[socktype] == "SOCK_DGRAM":
        found_recs.append(["AAAA", target, sockaddr[0]])
  except:
    return found_recs
  return found_recs

def get_constants(prefix):
  """
  Map socket constants to their names.
  """
  return dict((getattr(socket, n), n)
              for n in dir(socket)
              if n.startswith(prefix))

def get_a_answer(target, ns, timeout):
  query = dns.message.make_query(target, dns.rdatatype.A, dns.rdataclass.IN)
  query.flags += dns.flags.CD
  query.use_edns(edns=True, payload=4096)
  query.want_dnssec(True)
  answer = dns.query.udp(query, ns, timeout)
  return answer

def lookup_next(target, res):
  """
  Try to get the most accurate information for the record found.
  """
  res_sys = DnsHelper(target)
  returned_records = []

  if re.search("^_[A-Za-z0-9_-]*._[A-Za-z0-9_-]*.", target, re.I):
    srv_answer = res.get_srv(target)
    if len(srv_answer) > 0:
      for r in srv_answer:
        print("\t {0}".format(" ".join(r)))
        returned_records.append({'type': r[0],
                                'name': r[1],
                                'target': r[2],
                                'address': r[3],
                                'port': r[4]})

  elif re.search("(_autodiscover\\.|_spf\\.|_domainkey\\.)", target, re.I):
    txt_answer = res.get_txt(target)
    if len(txt_answer) > 0:
      for r in txt_answer:
        print("\t {0}".format(" ".join(r)))
        returned_records.append({'type': r[0],
                                'name': r[1], 'strings': r[2]})
    else:
      txt_answer = res_sys.get_tx(target)
      if len(txt_answer) > 0:
        for r in txt_answer:
          print("\t {0}".format(" ".join(r)))
          returned_records.append({'type': r[0],
                                      'name': r[1], 'strings': r[2]})
      else:
        print('\t A {0} no_ip'.format(target))
        returned_records.append({'type': 'A', 'name': target, 'address': "no_ip"})

  else:
    a_answer = res.get_ip(target)
    if len(a_answer) > 0:
      for r in a_answer:
        print('\t {0} {1} {2}'.format(r[0], r[1], r[2]))
        if r[0] == 'CNAME':
          returned_records.append({'type': r[0], 'name': r[1], 'target': r[2]})
        else:
          returned_records.append({'type': r[0], 'name': r[1], 'address': r[2]})
    else:
      a_answer = socket_resolv(target)
      if len(a_answer) > 0:
        for r in a_answer:
          print('\t {0} {1} {2}'.format(r[0], r[1], r[2]))
          returned_records.append({'type': r[0], 'name': r[1], 'address': r[2]})
      else:
        print('\t A {0} no_ip'.format(target))
        returned_records.append({'type': 'A', 'name': target, 'address': "no_ip"})

  return returned_records


def walk_nsec_zone(res, domain, ns=""):
  print("Performing NSEC Zone Walk for {0}".format(domain))

  nameserver = ns
  if (not nameserver):
    print("Getting SOA record for {0}".format(domain))
    soa_rcd = res.get_soa()[0][2]
    nameserver = soa_rcd
  print("Name Server {0} will be used".format(nameserver))
  
  res = DnsHelper(domain, nameserver, 3)

  timeout = res._res.timeout

  records = []

  transformations = [
    # Send the hostname as-is
    lambda h, hc, dc: h,

    # Prepend a zero as a subdomain
    lambda h, hc, dc: "0.{0}".format(h),

    # Append a hyphen to the host portion
    lambda h, hc, dc: "{0}-.{1}".format(hc, dc),

    # Double the last character of the host portion
    lambda h, hc, dc: "{0}{1}.{2}".format(hc, hc[-1], dc)
  ]

  pending = set([domain])
  finished = set()

  try:
    while pending:
      # Get the next pending hostname
      hostname = pending.pop()
      finished.add(hostname)

      # Get all the records we can for the hostname
      records.extend(lookup_next(hostname, res))

      # Arrange the arguments for the transformations
      fields = re.search("(^[^.]*).(\S*)",  hostname)
      params = [hostname, fields.group(1), fields.group(2)]

      for transformation in transformations:
        # Apply the transformation
        target = transformation(*params)

        # Perform a DNS query for the target and process the response
        response = get_a_answer(target, nameserver, timeout)
        for a in response.authority:
          if a.rdtype != 47:
            continue

          # NSEC records give two results:
          #   1) The previous existing hostname that is signed
          #   2) The subsequent existing hostname that is signed
          # Add the latter to our list of pending hostnames
          for r in a:
            pending.add(r.next.to_text()[:-1])

      # Ensure nothing pending has already been queried
      pending -= finished

  except (KeyboardInterrupt):
    print("You have pressed Ctrl + C. Saving found records.")

  except (dns.exception.Timeout):
    print("Timout while walking.")

  if len(records) > 0:
    print("{0} records found".format(len(records)))
  else:
    print("Zone could not be walked")

  return records
