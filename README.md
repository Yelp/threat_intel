# threat_intel
Threat Intelligence APIs

## Supported threat intelligence feeds

### OpenDNS Investigate API

[OpenDNS Investigate](https://investigate.opendns.com/) provides an API that
allows querying for:
* Domain categorization
* Security information about a domain
* Cooccurrences (related domains)
* Domains related to an IP

### VirusTotal

[VirusTotal](https://www.virustotal.com/) provides an
[API](https://www.virustotal.com/en/documentation/public-api/) that makes it
possible to query for the reports about:
* Domains
* URLs
* Hashes

## Installation

### Install with `pip`
TBD

### Testing
To test, ensure basic dependencies are ready and then go to town with `make`
```shell
$ sudo pip install tox
$ make test
```
