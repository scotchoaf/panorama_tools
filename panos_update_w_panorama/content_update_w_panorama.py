# Copyright (c) 2018, Palo Alto Networks
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

# Author: Scott Shoaf <sshoaf@paloaltonetworks.com>

'''
Palo Alto Networks content_update.py

uses the firewall api to check, download, and install content updates
does both content/threat and antivirus updates

This software is provided without support, warranty, or guarantee.
Use at your own risk.
'''

import argparse
import sys
import time
import pan.xapi


def get_job_id(s):
    '''
    extract job-id from pan-python string xml response
    regex parse due to pan-python output join breaking xml rules
    :param s is the input string
    :return: simple string with job id
    '''

    return s.split('<job>')[1].split('</job>')[0]

def get_job_status(s):
    '''
    extract status and progress % from pan-python string xml response
    regex parse due to pan-python output join breaking xml rules
    :param s is the input string
    :return: status text and progress %
    '''

    status = s.split('<status>')[1].split('</status>')[0]
    progress = s.split('<progress>')[1].split('</progress>')[0]
    return status, progress

def check_job_status(fw, results, target):
    '''
    periodically check job status in the firewall
    :param fw is fw object being queried
    :param results is the xml-string results returned for job status
    :param target is an api string using the fw serial number
    '''

    # initialize to null status
    status = ''

    job_id = get_job_id(results)

    # check job id status and progress
    # extra_qs target names the fw serial number
    while status != 'FIN':

        fw.op(cmd='<show><jobs><id>{0}</id></jobs></show>'.format(job_id), extra_qs=target)
        status, progress = get_job_status(fw.xml_result())
        if status != 'FIN':
            print('job {0} in progress [ {1}% complete ]'.format(job_id, progress), end='\r', flush=True)
            time.sleep(5)

    print('\njob {0} is complete'.format(job_id))

def update_content(fw, type, sn):
    '''
    check, download, and install latest content updates
    :param fw is the fw object being updated
    :param type is update type - content or anti-virus
    '''

    # text used in extra_qs to use panorama api as proxy to fw based on serial number
    # target used in all api calls referencing the same serial number aka fw
    target = 'target={0}'.format(sn)

    print('checking for latest {0} updates...'.format(type))
    fw.op(cmd='<request><{0}><upgrade><check/></upgrade></{0}></request>'.format(type), extra_qs=target)

    # download latest content
    print('downloading latest {0} updates...'.format(type))
    fw.op(cmd='<request><{0}><upgrade><download><latest/></download></upgrade></{0}></request>'.format(type), extra_qs=target)
    results = fw.xml_result()

    if '<job>' in results:
        check_job_status(fw, results, target)

    # install latest content
    print('installing latest {0} updates...'.format(type))
    fw.op(cmd='<request><{0}><upgrade><install><version>latest</version></install></upgrade></{0}></request>'.format(type), extra_qs=target)
    results = fw.xml_result()

    if '<job>' in results:
        check_job_status(fw, results, target)


def main():
    '''
    simple set of api calls to update fw to latest content versions
    uses panorama as a proxy by adding target=serial_number to the api requests
    '''

    # python skillets currently use CLI arguments to get input from the operator / user. Each argparse argument long
    # name must match a variable in the .meta-cnc file directly
    parser = argparse.ArgumentParser()
    # TODO: need to update the -f to another value to make sense
    parser.add_argument("-f", "--panorama", help="IP address of Panorama", type=str)
    parser.add_argument("-u", "--username", help="Panorama Username", type=str)
    parser.add_argument("-p", "--password", help="Panorama Password", type=str)
    parser.add_argument("-s", "--serial_number", help="Firewall Serial Number", type=str)
    args = parser.parse_args()

    if len(sys.argv) < 2:
        parser.print_help()
        parser.exit()
        exit(1)

    # this is actually the panorama ip and will fix
    fw_ip = args.panorama
    username = args.username
    password = args.password
    serial_number = args.serial_number

    # create fw object using pan-python class
    # fw object is actually a panorama object so an api device object
    fw = pan.xapi.PanXapi(api_username=username, api_password=password, hostname=fw_ip)

    # get panorama api key
    api_key = fw.keygen()

    print('updating content for NGFW serial number {0}'.format(serial_number))

    # !!! updates require panorama mgmt interface with internet access
    # update ngfw to latest content and av versions
    # passing in the serial number to use in panorama as api target
    for item in ['content', 'anti-virus']:
        update_content(fw, item, serial_number)

    print('\ncontent update complete')


if __name__ == '__main__':
    main()