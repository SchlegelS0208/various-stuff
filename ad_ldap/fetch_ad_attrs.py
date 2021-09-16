#!/usr/bin/env python3

### Author: Steven Schlegel | steven@schlegel.tech
### Date: 13.07.2021
### Description: Retrieve various from Active Directory (LDAP),
###              while converting necessary timestamps into date-strings.
###
### Changelog:
### 0.1.1 - 13.07.2021 - Steven Schlegel
###     * provided 1st working version of a python script
###     * fixed various bugs when handling dictionaries

import argparse
import sys
import time
import traceback
import datetime
import getpass
import ldap, ldapurl

STATUS_OK = 0
STATUS_WARNING = 1
STATUS_CRITICAL = 2
STATUS_UNKNOWN = 3

### LDAP static connection settings
LDAP_PROTO = 'ldaps'
LDAP_PORT = 636
LDAP_SCOPE = ldap.SCOPE_SUBTREE

global ldap_attrs

def get_login():
    user_prompt = input('Username: ')  
    pass_prompt = lambda: (getpass.getpass('Password: '))

    user_name = user_prompt
    user_pass = pass_prompt()
    
    return user_name, user_pass

def timestamp_to_date(my_timestamp):
    timestamp = my_timestamp
    #print(timestamp)
    decoded_value = datetime.datetime (1601, 1, 1) + datetime.timedelta(seconds=timestamp/10000000) ### combine str 3 and 4
    return decoded_value

def convert_epoch(attribute):
    for attr_val in attribute:
        #print("Value: " + attr_val)
        ret_value = (timestamp_to_date(int(attr_val)).strftime('%Y-%m-%d %H:%M:%S'))
    return ret_value

# helper function to try to decode results if possible
def try_decode(value):
    if isinstance(value, bytes):
        try:
            value = value.decode()
        except:
            # sometimes, we can't decode bytes to str
            # so we just ignore and return it as is
            pass
    
    return value

def query_x509(args):
    if args.search_attr:
        ldap_creds = (get_login())

        #print("Credentials: {} " . format(ldap_creds))
        #print("LDAP-Username: {} " . format(ldap_user))
        #print("LDAP-Password: {} " . format(ldap_pass))

        LDAP_SERVER = args.ldap_server
        ldap_name, ldap_suffix = args.ldap_server.split('.')[-2:]
        LDAP_DOMAIN = (ldap_name + '.' + ldap_suffix)

        LDAP_BASE_DN = ('dc=' + ldap_name + ',' + 'dc=' + ldap_suffix)

        #print(LDAP_DOMAIN)
        #print(LDAP_BASE_DN)

        ATTRIBUTES_TO_SEARCH = (args.search_attr.split(','))
        #print("Searching for: {} " . format(ATTRIBUTES_TO_SEARCH))

        ldap_user = (ldap_creds[0] + '@' + LDAP_DOMAIN)
        ldap_pass = (ldap_creds[1])

        if (args.objecttype == 'computer'):
            LDAP_QUERY = "(&(objectClass=computer)(cn=" + args.objectname + "))"
        else:
            LDAP_QUERY = "(&(objectClass=person)(samAccountName=" + args.objectname + "))"
        #print("Query for: {}" . format(LDAP_QUERY))

    if None not in (ldap_user, ldap_pass):
        print('\n\n' + "Running LDAP-search for object: {}".format(args.objectname) + " (type: {}".format(args.objecttype) + ")" + '\n\n')
        try:
            ldap_url = ldapurl.LDAPUrl(urlscheme=LDAP_PROTO, hostport="%s:%s" % (LDAP_SERVER, str(LDAP_PORT))).initializeUrl()
            ldap_conn = ldap.initialize(ldap_url)
            ldap_conn.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
            ldap_conn.set_option(ldap.OPT_REFERRALS, 0)
            ldap_conn.set_option(ldap.OPT_PROTOCOL_VERSION, 3)
            ldap_conn.set_option(ldap.OPT_X_TLS,ldap.OPT_X_TLS_DEMAND)
            ldap_conn.set_option( ldap.OPT_X_TLS_DEMAND, True )
            # to search the object and all its descendants
            ldap_conn.simple_bind_s(ldap_user, ldap_pass)
            result = ldap_conn.search_s(LDAP_BASE_DN, LDAP_SCOPE, LDAP_QUERY, ATTRIBUTES_TO_SEARCH)
            #print("Response (LDAP): {}" . format(result))
        except Exception as exc:
            print('Missing AD object / AD name for retrieving attributes: {}'.format(exc))
            sys.exit(STATUS_CRITICAL)

    if None not in (result):
        return result

def run(args):
    ldap_attrs = ""
    return_status = STATUS_OK
    ldap_data = query_x509(args)
    #print(ldap_data)

    if None not in (ldap_data):
        for dn, attrs in ldap_data:
            if dn:
            #if decodeBytes:
                attrs = {
                    k: [try_decode(i) for i in attrs[k]]
                    for k in attrs
                }
                ldap_attrs = attrs

        if 'lastLogon' in ldap_attrs:
            ldap_attrs['lastLogon'] = convert_epoch(ldap_attrs['lastLogon'])
        
        if 'pwdLastSet' in ldap_attrs:
            ldap_attrs['pwdLastSet'] = convert_epoch(ldap_attrs['pwdLastSet'])
        
        if 'lastLogonTimestamp' in ldap_attrs:
            ldap_attrs['lastLogonTimestamp'] = convert_epoch(ldap_attrs['lastLogonTimestamp'])
     
        #print(ldap_attrs)
        
        print('>>> BEGIN - LDAP_DATA: \n' + '------------------------------------\n')

        for key in ldap_attrs:
            print(key + ':', str(ldap_attrs[key]).strip("[]").replace("'","") + '\n')

        print('------------------------------------\n' + '<<< END - LDAP_DATA' + '\n')
    else:
        print("LDAP search returned EMPTY list / response!")

def parse_args():
    parser = argparse.ArgumentParser(
        'This plugin checks the timestamps provided as inputs from Active Directory (LDAP)'
        ' and coverts those timestamps into human-readable format.')
    parser.add_argument('--server', type=str,
                        required=True,
                        dest='ldap_server',
                        default=None,
                        help='(--server ldaps.my.domain)')
    parser.add_argument('--type', type=str,
                        required=True,
                        dest='objecttype',
                        default='computer',
                        help='(--type computer | --type user)')
    parser.add_argument('--object', type=str,
                        required=True,
                        dest='objectname',
                        default=None,
                        help='(--object MY-LINUX-VM-01 | --object schlegels)')
    parser.add_argument('--search', type=str,
                        required=False,
                        dest='search_attr',
                        default=None,
                        help='(--search "pwdLastSet,lastLogon,lastLogonTimestamp,samAccountName,userPrincipalName")')
    args = parser.parse_args()
#    if args.warning > args.critical:
#        print('Warning must be less than critical')
#        sys.exit(STATUS_CRITICAL)
    return args


if __name__ == '__main__':
    try:
        run(parse_args())
    # pylint: disable=broad-except
    except Exception as ex:
        print('%s: Unhandled exception %s' % (sys.argv[0], type(ex)))
        print(ex)
        print('bla')
        traceback.print_exc()
        sys.exit(STATUS_CRITICAL)
