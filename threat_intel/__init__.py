# -*- coding: utf-8 -*-
"""

Supported threat intelligence feeds.

The package contains API wrappers for:

* OpenDNS Investigate API
* VirusTotal API v2.0
* ShadowServer API


OpenDNS Investigate API
=======================

OpenDNS Investigate  provides an API that allows querying for:

    * Domain categorization
    * Security information about a domain
    * Co-occurrences for a domain
    * Related domains for a domain
    * Domains related to an IP
    * Domain tagging dates for a domain
    * DNS RR history for a domain

To use the Investigate API wrapper import InvestigateApi class from threat_intel.opendns module:

    >>> from threat_intel.opendns import InvestigateApi

To initialize the API wrapper you need the API key:

    >>> investigate = InvestigateApi("<INVESTIGATE-API-KEY-HERE>")

You can also specify a file name where the API responses will be cached in a JSON file, to save you the bandwidth for the multiple calls about the same domains or IPs:

    >>> investigate = InvestigateApi("<INVESTIGATE-API-KEY-HERE>", cache_file_name="/tmp/cache.opendns.json")


Domain categorization
---------------------
Calls domains/categorization/?showLabels Investigate API endpoint. It takes a list (or any other Python enumerable) of domains and returns the categories associated with this domains by OpenDNS.

    >>> domains = ["google.com", "baidu.com", "bibikun.ru"]
    >>> investigate.categorization(domains)

will result in:
{
    "baidu.com": {"status": 1, "content_categories": ["Search Engines"], "security_categories": []},
    "google.com": {"status": 1, "content_categories": ["Search Engines"], "security_categories": []},
    "bibikun.ru": {"status": -1, "content_categories": [], "security_categories": ["Malware"]}
}


Security information about a domain
-----------------------------------
Calls security/name/ Investigate API endpoint. It takes any Python enumerable with domains, e.g. list, and returns security parameters associated with each domain.

    >>> domains = ["google.com", "baidu.com", "bibikun.ru"]
    >>> investigate.security(domains)

will result in:

{
  "baidu.com": {
    "found": true,
    "handlings": {
      "domaintagging": 0.00032008666962131285,
      "blocked": 0.00018876906157154347,
      "whitelisted": 0.00019697641207465407,
      "expired": 2.462205150933176e-05,
      "normal": 0.9992695458052232
    },
    "dga_score": 0,
    "rip_score": 0,
    ..
  }
}


Co-ooccurrences of domain
--------------------------
Calls recommendations/name/ Investigate API endpoint. Use this method to find out related domains to the one given in a list, or any other Python enumerable.

    >>> domains = ["google.com", "baidu.com", "bibikun.ru"]
    >>> investigate.cooccurrences(domains)

will result in:

{
  "baidu.com": {
    "found": true,
    "pfs2": [
      ["www.howtoforge.de", 0.14108563836506008],
      ..
}


Related domains for a domain
----------------------------

Calls links/name/ Investigate API endpoint. Use this method to find out a list of related domains (domains that have been frequently seen requested around a time window of 60 seconds, but that are not associated with the given domain) to the one given in a list, or any other Python enumerable.

    >>> domains = ["google.com", "baidu.com", "bibikun.ru"]
    >>> investigate.related_domains(domains)

will result in:

    {
        "tb1": [
                ["t.co", 11.0],
                        ]

                            ..

    }


Domain tagging dates for a domain
---------------------------------

Calls domains/name/ Investigate API endpoint.

Use this method to get the date range when the domain being queried was a part of the OpenDNS block list and how long a domain has been in this list

    >>> domains = ["google.com", "baidu.com", "bibikun.ru"]
    >>> investigate.domain_tag(domains)

will result in:

    {
        'category': u'Malware',
            'url': None,
                'period': {
                        'begin': u'2013-09-16',
                                'end': u'Current'
                        }

        ..

    }




DNS RR history for an IP
------------------------
Calls dnsdb/ip/a/ Investigate API endpoint. Use this method to find out related domains to the IP addresses given in a list, or any other Python enumerable.

    >>> ips = ['8.8.8.8']
    >>> investigate.rr_history(ips)

will result in:

{
  "8.8.8.8": {
    "rrs": [
      {
        "name": "8.8.8.8",
        "type": "A",
        "class": "IN",
        "rr": "000189.com.",
        "ttl": 3600
      },
      {
        "name": "8.8.8.8",
        "type": "A",
        "class": "IN",
        "rr": "008.no-ip.net.",
        "ttl": 60
      },
      ..
}



VirusTotal API
==============

VirusTotal provides an API that makes it possible to query for the reports about:

    * File hashes
    * Domains
    * URLs

To use the VirusTotal API wrapper import VirusTotalApi class from threat_intel.virustotal module:

    >>> from threat_intel.virustotal import VirusTotalApi

To initialize the API wrapper you need the API key:

    >>> vt = VirusTotalApi("<VIRUSTOTAL-API-KEY-HERE>")

VirusTotal API calls allow to squeeze a list of file hashes or URLs into a single HTTP call. Depending on the API version you are using (public or private) you may need to tune the maximum number
of the resources (file hashes or URLs) that could be passed in a single API call. You can do it with the resources_per_req parameter:

    >>> vt = VirusTotalApi("<VIRUSTOTAL-API-KEY-HERE>", resources_per_req=4)

When using the public API your standard request rate allows you too put maximum 4 resources per request. With private API you are able to put up to 25 resources per call. That is also the default value if you don't pass the resources_per_req parameter.

Of course when calling the API wrapper methods in the VirusTotalApi class you can pass as many resources as you want and the wrapper will take care of producing as many API calls as necessary to satisfy the request rate.

Similarly to OpenDNS API wrapper, you can also specify the file name where the responses will be cached:

    >>> vt = VirusTotalApi("<VIRUSTOTAL-API-KEY-HERE>", cache_file_name="/tmp/cache.virustotal.json")


File hash reports
-----------------
Calls file/report VirusTotal API endpoint.
You can request the file reports passing a list of hashes (md5, sha1 or sha2):

    >>> file_hashes = [
        "99017f6eebbac24f351415dd410d522d",
        "88817f6eebbac24f351415dd410d522d"
    ]

    >>> vt.get_file_reports(file_hashes)

will result in:

{
  "88817f6eebbac24f351415dd410d522d": {
    "response_code": 0,
    "resource": "88817f6eebbac24f351415dd410d522d",
    "verbose_msg": "The requested resource is not among the finished, queued or pending scans"
  },
  "99017f6eebbac24f351415dd410d522d": {
    "scan_id": "52d3df0ed60c46f336c131bf2ca454f73bafdc4b04dfa2aea80746f5ba9e6d1c-1423261860",
    "sha1": "4d1740485713a2ab3a4f5822a01f645fe8387f92",
}


Domain reports
--------------
Calls domain/report VirusTotal API endpoint.
Pass a list or any other Python enumerable containing the domains:

    >>> domains = ["google.com", "baidu.com", "bibikun.ru"]
    >>> vt.get_domain_reports(domains)

will result in:

{
  "baidu.com": {
    "undetected_referrer_samples": [
      {
        "positives": 0,
        "total": 56,
        "sha256": "e3c1aea1352362e4b5c008e16b03810192d12a4f1cc71245f5a75e796c719c69"
      }
    ],
    ..
}


URL reports
-----------
Calls url/report VirusTotal API endpoint.
Pass a list or any other Python enumerable containing the URL addresses:

    >>> urls = ["http://www.google.com", "http://www.yelp.com"]
    >>> vt.get_url_reports(urls)

will result in:

{
  "http://www.google.com": {
    "permalink": "https://www.virustotal.com/url/dd014af5ed6b38d9130e3f466f850e46d21b951199d53a18ef29ee9341614eaf/analysis/1423344006/",
    "resource": "http://www.google.com",
    "url": "http://www.google.com/",
    "response_code": 1,
    "scan_date": "2015-02-07 21:20:06",
    "scan_id": "dd014af5ed6b38d9130e3f466f850e46d21b951199d53a18ef29ee9341614eaf-1423344006",
    "verbose_msg": "Scan finished, scan information embedded in this object",
    "filescan_id": null,
    "positives": 0,
    "total": 62,
    "scans": {
      "CLEAN MX": {
        "detected": false,
        "result": "clean site"
      },
  ..
}


ShadowServer API
----------------
ShadowServer provides and API that allows to test the hashes against a list of known software applications.

To use the ShadowServer API wrapper import ShadowServerApi class from threat_intel.shadowserver module:

    >>> from threat_intel.shadowserver import ShadowServerApi

To use the API wrapper simply call the ShadowServerApi initializer:

    >>> ss = ShadowServerApi()

You can also specify the file name where the API responses will be cached:

    >>> ss = ShadowServerApi(cache_file_name="/tmp/cache.shadowserver.json")

To check whether the hashes are on the ShadowServer list of known hashes, call get_bin_test method and pass enumerable with the hashes you want to test:

    >>> file_hashes = [
        "99017f6eebbac24f351415dd410d522d",
        "88817f6eebbac24f351415dd410d522d"
    ]

    >>> ss.get_bin_test(file_hashes)

"""

__all__ = ['exceptions', 'opendns', 'shadowserver', 'virustotal']
