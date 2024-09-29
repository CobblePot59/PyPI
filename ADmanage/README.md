[![Maintenance mode](https://img.shields.io/badge/maintenance_mode-%F0%9F%9A%A7-grey.svg?labelColor=orange)](#maintenance-mode)

# ADmanage

The provided script is a Python program that interacts with an Active Directory (AD) server using the LDAP protocol. It allows you to perform various operations on DNS entries and AD objects (users, groups and computers).

#### get_DNSentries
```sh
from ADmanage import ADclient

ad_client = ADclient(domain='cobblepot59.int', username='Administrator', password='Password1', dc_ip='ldap.cobblepot59.int', base_dn='DC=cobblepot59,DC=int', secure=True)
result = ad_client.get_DNSentries()
ad_client.disconnect()
print(result)
```
#### get_DNSentry
```sh
from ADmanage import ADclient

ad_client = ADclient(domain='cobblepot59.int', username='Administrator', password='Password1', dc_ip='ldap.cobblepot59.int', base_dn='DC=cobblepot59,DC=int', secure=True)
result = ad_client.get_DNSentry('quad9')
ad_client.disconnect()
print(result)
```
#### add_DNSentry
```sh
from ADmanage import ADclient

ad_client = ADclient(domain='cobblepot59.int', username='Administrator', password='Password1', dc_ip='ldap.cobblepot59.int', base_dn='DC=cobblepot59,DC=int', secure=True)
result = ad_client.add_DNSentry('quad9', '149.112.112.112')
ad_client.disconnect()
print(result)
```
#### modify_DNSentry
```sh
from ADmanage import ADclient

ad_client = ADclient(domain='cobblepot59.int', username='Administrator', password='Password1', dc_ip='ldap.cobblepot59.int', base_dn='DC=cobblepot59,DC=int', secure=True)
result = ad_client.modify_DNSentry('quad9', '9.9.9.9')
ad_client.disconnect()
print(result)
```
#### del_DNSentry
```sh
from ADmanage import ADclient

ad_client = ADclient(domain='cobblepot59.int', username='Administrator', password='Password1', dc_ip='ldap.cobblepot59.int', base_dn='DC=cobblepot59,DC=int', secure=True)
result = ad_client.del_DNSentry('quad9')
ad_client.disconnect()
print(result)
```
#### get_ADobjects
Searches for and returns all user, group, and computer objects.
```sh
from ADmanage import ADclient

ad_client = ADclient(domain='cobblepot59.int', username='Administrator', password='Password1', dc_ip='ldap.cobblepot59.int', base_dn='DC=cobblepot59,DC=int', secure=True)
result = ad_client.get_ADobjects()
ad_client.disconnect()
print(result)
```
#### get_ADobject
Searches for and returns a specific AD object based on its sAMAccountName value.
```sh
from ADmanage import ADclient

ad_client = ADclient(domain='cobblepot59.int', username='Administrator', password='Password1', dc_ip='ldap.cobblepot59.int', base_dn='DC=cobblepot59,DC=int', secure=True)
result = ad_client.get_ADobject('Administrator')
ad_client.disconnect()
print(result)
```
#### add_ADobject
Adds users, computers, or groups to the AD server.
```sh
from ADmanage import ADclient

ad_client = ADclient(domain='cobblepot59.int', username='Administrator', password='Password1', dc_ip='ldap.cobblepot59.int', base_dn='DC=cobblepot59,DC=int', secure=True)
result = ad_client.add_ADobject('OU=test,DC=cobblepot59,DC=int', {'objectClass': 'user', 'givenName': 'Jack', 'sn': 'Bower', 'password': 'Password1'})
ad_client.disconnect()
print(result)
```
```sh
from ADmanage import ADclient

ad_client = ADclient(domain='cobblepot59.int', username='Administrator', password='Password1', dc_ip='ldap.cobblepot59.int', base_dn='DC=cobblepot59,DC=int', secure=True)
result = ad_client.add_ADobject('OU=test,DC=cobblepot59,DC=int', {'objectClass': 'computer', 'cn': 'jbower-pc'})
ad_client.disconnect()
print(result)
```
```sh
from ADmanage import ADclient

ad_client = ADclient(domain='cobblepot59.int', username='Administrator', password='Password1', dc_ip='ldap.cobblepot59.int', base_dn='DC=cobblepot59,DC=int', secure=True)
result = ad_client.add_ADobject('OU=test,DC=cobblepot59,DC=int', {'objectClass': 'group', 'cn': '24hChrono'})
ad_client.disconnect()
print(result)
```
#### del_ADobject
Deletes a specified AD object.
```sh
from ADmanage import ADclient

ad_client = ADclient(domain='cobblepot59.int', username='Administrator', password='Password1', dc_ip='ldap.cobblepot59.int', base_dn='DC=cobblepot59,DC=int', secure=True)
result = ad_client.del_ADobject('jbower')
ad_client.disconnect()
print(result)
```
```sh
from ADmanage import ADclient

ad_client = ADclient(domain='cobblepot59.int', username='Administrator', password='Password1', dc_ip='ldap.cobblepot59.int', base_dn='DC=cobblepot59,DC=int', secure=True)
result = ad_client.del_ADobject('jbower-pc$')
ad_client.disconnect()
print(result)
```
#### get_member
Retrieves the members of a specified group.
```sh
from ADmanage import ADclient

ad_client = ADclient(domain='cobblepot59.int', username='Administrator', password='Password1', dc_ip='ldap.cobblepot59.int', base_dn='DC=cobblepot59,DC=int', secure=True)
result = ad_client.get_member('Administrators')
ad_client.disconnect()
print(result)
```
#### get_memberOf
Retrieves the groups to which a user belongs.
```sh
from ADmanage import ADclient

ad_client = ADclient(domain='cobblepot59.int', username='Administrator', password='Password1', dc_ip='ldap.cobblepot59.int', base_dn='DC=cobblepot59,DC=int', secure=True)
result = ad_client.get_memberOf('Administrator')
ad_client.disconnect()
print(result)
```
#### add_ADobject_to_group
Adds an AD object to a group.
```sh
from ADmanage import ADclient

ad_client = ADclient(domain='cobblepot59.int', username='Administrator', password='Password1', dc_ip='ldap.cobblepot59.int', base_dn='DC=cobblepot59,DC=int', secure=True)
result = ad_client.add_ADobject_to_group('jbower', 'test')
ad_client.disconnect()
print(result)
```
#### del_ADobject_from_group
Removes an AD object from a group.
```sh
from ADmanage import ADclient

ad_client = ADclient(domain='cobblepot59.int', username='Administrator', password='Password1', dc_ip='ldap.cobblepot59.int', base_dn='DC=cobblepot59,DC=int', secure=True)
result = ad_client.del_ADobject_from_group('jbower', 'test')
ad_client.disconnect()
print(result)
```
#### modify_ADobject_attributes
Modifies attributes of a specified AD object.
```sh
from ADmanage import ADclient

ad_client = ADclient(domain='cobblepot59.int', username='Administrator', password='Password1', dc_ip='ldap.cobblepot59.int', base_dn='DC=cobblepot59,DC=int', secure=True)
result = ad_client.modify_ADobject_attributes('jbower', {'mail': 'jack.bower@cobblepot59.int'})
ad_client.disconnect()
print(result)
```
#### reset_password
Resets the password of a user (works with SSL bind).
```sh
from ADmanage import ADclient

ad_client = ADclient(domain='cobblepot59.int', username='Administrator', password='Password1', dc_ip='ldap.cobblepot59.int', base_dn='DC=cobblepot59,DC=int', secure=True)
result = ad_client.reset_password('jbower', 'Password2')
ad_client.disconnect()
print(result)
```
#### enable_ADobject
Enables a user or computer account.
```sh
from ADmanage import ADclient

ad_client = ADclient(domain='cobblepot59.int', username='Administrator', password='Password1', dc_ip='ldap.cobblepot59.int', base_dn='DC=cobblepot59,DC=int', secure=True)
result = ad_client.enable_ADobject('jbower')
ad_client.disconnect()
print(result)
```
#### disable_ADobject
Disables a user or computer account.
```sh
from ADmanage import ADclient

ad_client = ADclient(domain='cobblepot59.int', username='Administrator', password='Password1', dc_ip='ldap.cobblepot59.int', base_dn='DC=cobblepot59,DC=int', secure=True)
result = ad_client.disable_ADobject('jbower-pc$')
ad_client.disconnect()
print(result)
```

## Maintenance Mode
There is no active development & new major features are not planned.   
You can use other alternatives like [ms_active_directory](https://github.com/zorn96/ms_active_directory) or [msldap](https://github.com/skelsec/msldap).
