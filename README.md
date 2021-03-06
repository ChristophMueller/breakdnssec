breakdnssec
===========

DNS recon / enumeration tool capable of attacking DNSSEC

breakdnssec is a proof-of-concept proving security issues introduced or not sufficiently solved by the DNSSEC standard. It is not intended to serve as a full-fledged penetration testing tool, but I encourage you to fork and extend or rewrite the tool.

Based on the work of Daniel J. Bernstein.

The crawler/ requires the Alexa top 1 million websites list (available at http://s3.amazonaws.com/alexa-static/top-1m.csv.zip) or a similarly formated CSV of host and domain names. Through simple AXFR requests the crawler will collect a dictionary of commonly used host names.

This dictionary is later used by dns_recon/ to execute a dictionary attack on the specified domain. dns_recon/ will look for following weaknesses:
- enabled AXFR requests (zone transfer)
- DNSSEC with NSEC (zone walking)
- DNSSEC with NSEC3 (hash collecting a la zone walk, dictionary and brute force attack on the hashed host names) 


breakdnssec depends on netaddr:
`pip install netaddr`

When using the crawler, do not forget to download the Alexa records as top-1m.csv into the crawler/ directory.

## Research ##
breakdnssec has been featured in http://dl.acm.org/citation.cfm?id=2527001
The paper has won the best paper award at SIN'13 (Participants' Selection).

## Maintenance ##
The project is currently not being actively maintained, however maintenance will resume to extend the tool for more practical use cases.
