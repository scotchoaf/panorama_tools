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
Palo Alto Networks content_update_panorama_upload.py

uses panorama install content updates to a managed firewall
does both content/threat and antivirus updates

This software is provided without support, warranty, or guarantee.
Use at your own risk.
'''

import argparse
import sys
import pan.xapi
from xml.etree import ElementTree as etree

def get_hostname(fw, sn, dg_name):
    '''
    query sn to get hostname
    :param fw is the fw object being updated
    :param serial_number is the device serial number
    '''

    # query panorama devicegroup to get associated devices list
    print('checking dg {0} to find sn {1}'.format(dg_name, sn))
    fw.op(cmd='<show><devicegroups><name>{0}</name></devicegroups></show>'.format(dg_name))
    results = fw.xml_result()
    tree = etree.fromstring(results)

    # iter list of devices to match serial number
    # if no match return hostname=unknown
    for device in tree[0][1].getchildren():
        if device.attrib['name'] == sn:
            hostname = device.find("./hostname").text
        else:
            print('serial number not found')
            hostname = 'unknown'

    return hostname


def main():
    '''
    simple set of api calls to update fw to latest content versions
    '''

    # python skillets currently use CLI arguments to get input from the operator / user. Each argparse argument long
    # name must match a variable in the .meta-cnc file directly
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--TARGET_IP", help="IP address of Panorama", type=str)
    parser.add_argument("-u", "--TARGET_USERNAME", help="Panorama Username", type=str)
    parser.add_argument("-p", "--TARGET_PASSWORD", help="Panorama Password", type=str)
    parser.add_argument("-s", "--serial_number", help="Firewall Serial Number", type=str)
    parser.add_argument("-d", "--device_group", help="Device Group to query", type=str)
    args = parser.parse_args()

    if len(sys.argv) < 2:
        parser.print_help()
        parser.exit()
        exit(1)

    # this is actually the panorama ip and will fix
    fw_ip = args.TARGET_IP
    username = args.TARGET_USERNAME
    password = args.TARGET_PASSWORD
    serial_number = args.serial_number
    dg_name = args.device_group

    # create fw object using pan-python class
    # fw object is actually a panorama object so an api device object
    fw = pan.xapi.PanXapi(api_username=username, api_password=password, hostname=fw_ip)

    # get panorama api key
    api_key = fw.keygen()

    print('getting hostname for {0}'.format(serial_number))

    hostname = get_hostname(fw, serial_number, dg_name)

    print('hostname is {0}'.format(hostname))


if __name__ == '__main__':
    main()