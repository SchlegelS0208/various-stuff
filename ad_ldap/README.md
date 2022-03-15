# Fetching ldap/ad attributes from Active Directory

## Requirements

* yum package: python3-ldap

### Step 1: dump TLS certs with chain into cacert.pem (from your LDAPS/AD server)

```
$ openssl s_client -showcerts -verify 5 -connect ldaps.ssc.tech:636 < /dev/null | awk '/BEGIN/,/END/{ if(/BEGIN/){a++}; out="cert"a".pem"; print >out}'; \
  for cert in *.pem; do cat ${cert} >> cacert.pem; done
```

### Step 2: concatenate all given cert files into one cacert.pem

```
$ sudo mv cacert.pem /etc/ldap/cacert.pem
```

### Step 3: create a valid ldap.conf for TLS connections

```
$ sudo cat << EOF > /etc/ldap/ldap.conf
TLS_CACERT      /etc/ldap/cacert.pem
TLS_REQCERT     allow
EOF
```

## Usage

### Example 1: fetch attributes for a computer object

```
$ ./fetch_ad_attrs.py --server ldaps.ssc.tech --type computer --object Linux-SSC-01 --search "pwdLastSet,lastLogon,lastLogonTimestamp,samAccountName,userPrincipalName"
Username: <username>
Password: <password>


Running LDAP-search for object: Linux-SSC-01 (type: computer)


>>> BEGIN - LDAP_DATA: 
------------------------------------

lastLogon: 2021-07-23 04:03:48

pwdLastSet: 2021-06-24 12:36:05

sAMAccountName: Linux-SSC-01$

lastLogonTimestamp: 2021-07-17 09:20:56

------------------------------------
<<< END - LDAP_DATA

```

### Example 2: fetch attributes for a user object

```
$ ./fetch_ad_attrs.py --server ssc.tech --type user --object schlegels --search "pwdLastSet,lastLogon,lastLogonTimestamp,samAccountName,userPrincipalName"
Username: <username>
Password: <password>


Running LDAP-search for object: schlegels (type: user)


>>> BEGIN - LDAP_DATA: 
------------------------------------

lastLogon: 2021-07-22 19:37:22

pwdLastSet: 2021-06-04 08:12:31

sAMAccountName: schlegels

userPrincipalName: steven@schlegel.tech

lastLogonTimestamp: 2021-07-22 07:16:06

------------------------------------
<<< END - LDAP_DATA

```
