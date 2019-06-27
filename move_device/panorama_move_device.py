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
Palo Alto Networks move_device.py

uses the panorama api to move a device to a new device-group and stack

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
    result = s.split('<result>')[1].split('</result>')[0]
    details = ''
    if '<details>' in s:
        details = s.split('<details>')[1].split('</details>')[0]
    return status, progress, result, details

def check_job_status(fw, results):
    '''
    periodically check job status in the firewall
    :param fw is fw object being queried
    :param results is the xml-string results returned for job status
    '''

    # initialize to null status
    status = ''

    job_id = get_job_id(results)
    #print('checking status of job id {0}...'.format(job_id))

    # check job id status and progress
    while status != 'FIN':

        fw.op(cmd='<show><jobs><id>{0}</id></jobs></show>'.format(job_id))
        status, progress, result, details = get_job_status(fw.xml_result())
        if status != 'FIN':
            print('job {0} in progress [ {1}% complete ]'.format(job_id, progress), end='\r', flush=True)
            time.sleep(5)

    print('\njob {0} is complete as {1}'.format(job_id, result))

    if result == 'FAIL':
        print(details)

def move_dg(pano, sn, from_dg, to_dg):
    '''
    move a device serial number to a new device-group
    :param pano is the panorama object being updated
    :param sn is the firewall serial number
    :param from_dg is the current device-group moving from
    :param to_dg is the device-group moving to
    '''

    xpath = "/config/devices/entry[@name='localhost.localdomain']/device-group/" \
            "entry[@name='{0}']/devices/entry[@name='{1}']".format(from_dg, sn)

    print('removing firewall {0} from dg {1}...'.format(sn, from_dg))
    pano.delete(xpath)

    xpath = "/config/devices/entry[@name='localhost.localdomain']/device-group/" \
            "entry[@name='{0}']/devices".format(to_dg)
    element = "<entry name='{0}'/>".format(sn)

    print('adding firewall {0} to dg {1}...'.format(sn, to_dg))
    pano.set(xpath, element)

def move_ts(pano, sn, from_ts, to_ts):
    '''
    move a device serial number to a new template-stack
    :param pano: is the panorama object being updated
    :param sn is the firewall serial number
    :param from_ts is the current template-stack moving from
    :param to_ts is the template-stack moving to
    '''

    xpath = "/config/devices/entry[@name='localhost.localdomain']/template-stack/" \
            "entry[@name='{0}']/devices/entry[@name='{1}']".format(from_ts, sn)

    print('removing firewall {0} from stack {1}...'.format(sn, from_ts))
    pano.delete(xpath)

    xpath = "/config/devices/entry[@name='localhost.localdomain']/template-stack/" \
            "entry[@name='{0}']/devices".format(to_ts)
    element = "<entry name='{0}'/>".format(sn)

    print('adding firewall {0} to stack {1}...'.format(sn, to_ts))
    pano.set(xpath, element)

def commit(pano, sn, to_ts, to_dg):
    '''
    commit to panorama after move is complete
    :param pano: 
    :return: 
    '''

    # commit changes to panorama
    cmd = '<commit></commit>'
    print('commit to panorama')
    pano.commit(cmd=cmd)
    results = pano.xml_result()

    if '<job>' in results:
        check_job_status(pano, results)


    # template stack push to device
    # pushing first to ensure no commit errors for object references
    cmd_ts = '<commit-all><template-stack><force-template-values>yes</force-template-values>' \
          '<device><member>{0}</member></device>' \
          '<name>{1}</name></template-stack></commit-all>'.format(sn, to_ts)

    print('commit for template stack')
    pano.commit(action='all', cmd=cmd_ts)
    results = pano.xml_result()

    if '<job>' in results:
        check_job_status(pano, results)

    # device group push to device
    cmd_dg = "<commit-all><shared-policy><force-template-values>yes</force-template-values>" \
             "<device-group><entry name='{0}'><devices><entry name='{1}'/></devices></entry>" \
             "</device-group></shared-policy></commit-all>".format(to_dg, sn)

    print('commit for device-group')
    pano.commit(action='all', cmd=cmd_dg)
    results = pano.xml_result()

    if '<job>' in results:
        check_job_status(pano, results)


def main():
    '''
    simple set of api calls to to move a device to a new device group and stack
    '''

    # python skillets currently use CLI arguments to get input from the operator / user. Each argparse argument long
    # name must match a variable in the .meta-cnc file directly
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--panorama_ip", help="IP address of Panorama", type=str)
    parser.add_argument("-u", "--username", help="Panorama Username", type=str)
    parser.add_argument("-p", "--password", help="Panorama Password", type=str)
    parser.add_argument("-s", "--serial_number", help="Firewall Serial Number", type=str)
    parser.add_argument("-fs", "--from_ts", help="Stack moving from", type=str)
    parser.add_argument("-fd", "--from_dg", help="Device Group moving from", type=str)
    parser.add_argument("-ts", "--to_ts", help="Stack moving to", type=str)
    parser.add_argument("-td", "--to_dg", help="Device Group moving to", type=str)
    args = parser.parse_args()

    if len(sys.argv) < 2:
        parser.print_help()
        parser.exit()
        exit(1)

    panorama_ip = args.panorama_ip
    username = args.username
    password = args.password
    serial_number = args.serial_number
    from_ts=args.from_ts
    from_dg=args.from_dg
    to_ts=args.to_ts
    to_dg=args.to_dg

    # create panorama object using pan-python class
    panorama = pan.xapi.PanXapi(api_username=username, api_password=password, hostname=panorama_ip)

    # get panorama api key
    api_key = panorama.keygen()

    print('moving device-group for NGFW serial number {0}'.format(serial_number))
    move_dg(panorama, serial_number, from_dg, to_dg)

    print('moving template-stack for NGFW serial number {0}'.format(serial_number))
    move_ts(panorama, serial_number, from_ts, to_ts)

    print('commit to Panorama and push to device {0}'.format(serial_number))
    commit(panorama, serial_number, to_ts, to_dg)


if __name__ == '__main__':
    main()