#!/usr/bin/python

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import xml.etree.ElementTree as et

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


def submitStats():
    """Test function to submit stats dump for SLR generation"""
    file1 = open('20180222_1307_statsdump.tar.gz', 'r')
    url = "http://riskreporttest.paloaltonetworks.com/API/v1/Create"
    key = "6a85f78e5cd9a7eccae9333361f3cbd798ee1e8c70bad9dfeb027f345e562d2d"
    mailIDs = ['cstancill@paloaltonetworks.com']
    requestor = "angupta@paloaltonetworks.com"
    headers = {"apiKey" : key}
    file = {"file1":('20180222_1307_statsdump.tar.gz', file1, 'application/gzip')}
    payload = {"EmailIdList" : mailIDs[0],
               "RequestedBy" : requestor}
    slr_req = requests.post(url, headers=headers, data=payload, files=file)
    print slr_req.status_code
    print slr_req.content

def main():
    submitStats()


if __name__ == '__main__':
    main()

