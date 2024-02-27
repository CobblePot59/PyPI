import ldap3
from ldap3 import Server, Connection, ALL, SUBTREE, MODIFY_ADD, MODIFY_DELETE, MODIFY_REPLACE
from impacket.structure import Structure
import socket
import dns.resolver
import datetime

class ADclient:
    def __init__(self, domain, username, password, dc_ip, base_dn=None, secure=False):
        self.domain = domain
        self.username = username
        self.sam = f"{username}@{domain}"
        self.password = password
        self.dc_ip = dc_ip
        self.base_dn = base_dn
        self.secure = secure
        self.domainroot = f"DC={domain.split('.')[0]},DC={domain.split('.')[1]}"
        self.dnsroot = f"DC={domain},CN=MicrosoftDNS,DC=DomainDnsZones,{self.domainroot}"
        self.conn = self.connect_to_ldap()

    def connect_to_ldap(self):
        dc_url = f"ldaps://{self.dc_ip}:636" if self.secure else f"ldap://{self.dc_ip}:389"
        if not self.base_dn:
            self.base_dn = self.domainroot

        server = Server(dc_url, get_info=ALL)
        conn = Connection(server, user=self.sam, password=self.password, auto_bind=True)
        return conn

    def disconnect(self):
        self.conn.unbind()

    class DNS_RECORD(Structure):
        """
        dnsRecord - used in LDAP
        [MS-DNSP] section 2.3.2.2
        """
        structure = (
            ('DataLength', '<H-Data'),
            ('Type', '<H'),
            ('Version', 'B=5'),
            ('Rank', 'B'),
            ('Flags', '<H=0'),
            ('Serial', '<L'),
            ('TtlSeconds', '>L'),
            ('Reserved', '<L=0'),
            ('TimeStamp', '<L=0'),
            ('Data', ':')
        )

    class DNS_RPC_RECORD_A(Structure):
        """
        DNS_RPC_RECORD_A
        [MS-DNSP] section 2.2.2.2.4.1
        """
        structure = (
            ('address', ':'),
        )

        def formatCanonical(self):
            return socket.inet_ntoa(self['address'])

        def fromCanonical(self, canonical):
            self['address'] = socket.inet_aton(canonical)

    class DNS_RPC_RECORD_TS(Structure):
        """
        DNS_RPC_RECORD_TS
        [MS-DNSP] section 2.2.2.2.4.23
        """
        structure = (
            ('entombedTime', '<Q'),
        )
        def toDatetime(self):
            microseconds = self['entombedTime'] / 10.
            return datetime.datetime(1601,1,1) + datetime.timedelta(microseconds=microseconds)

    def new_record(self, rtype):
        nr = self.DNS_RECORD()
        nr['Type'] = rtype
        nr['Serial'] = self.get_next_serial(self.dc_ip, self.domain)
        nr['TtlSeconds'] = 180
        # From authoritive zone
        nr['Rank'] = 240
        return nr

    def get_next_serial(self, dc, zone):
        # Create a resolver object
        dnsresolver = dns.resolver.Resolver()
        dnsresolver.nameservers = [dc]

        res = dnsresolver.resolve(zone, 'SOA',tcp=False)
        for answer in res:
            return answer.serial + 1

    def get_DNSentries(self):
        filter = "(objectClass=*)"
        self.conn.search(search_base=self.dnsroot, search_filter=filter, search_scope=SUBTREE)
        entries = self.conn.entries
        return [entry.entry_dn for entry in entries if "._tcp" not in entry.entry_dn and "._udp" not in entry.entry_dn]

    def get_raw_entry(self, target):
        filter = f'(&(objectClass=dnsNode)(name={target}))'
        self.conn.search(search_base=self.dnsroot, search_filter=filter, attributes=['dnsRecord','dNSTombstoned','name'])
        for entry in self.conn.response:
            if entry['type'] != 'searchResEntry':
                continue
            return entry

    def get_DNSentry(self, target):
        record_data = self.get_raw_entry(target)['raw_attributes']['dnsRecord'][0][-4:]
        parsed_record = self.DNS_RPC_RECORD_A(record_data)
        ip_address = parsed_record.formatCanonical()
        return {'name': self.get_raw_entry(target)['attributes']['name'], 'ip': ip_address}

    def add_DNSentry(self, target, data):
        record_dn = f'DC={target},{self.dnsroot}'
        node_data = {
            # Schema is in the root domain (take if from schemaNamingContext to be sure)
            'objectCategory': f'CN=Dns-Node,CN=Schema,CN=Configuration,{self.domainroot}',
            'dNSTombstoned': False,
            'name': target
        }
        record = self.new_record(1)
        record['Data'] = self.DNS_RPC_RECORD_A()
        record['Data'].fromCanonical(data)
        node_data['dnsRecord'] = [record.getData()]
        self.conn.add(record_dn, ['top', 'dnsNode'], node_data)
        return self.get_DNSentry(target)

    def modify_DNSentry(self, target, data):
        targetentry = self.get_raw_entry(target)
        records = []
        for record in targetentry['raw_attributes']['dnsRecord']:
            dr = self.DNS_RECORD(record)
            if dr['Type'] == 1:
                targetrecord = dr
            else:
                records.append(record)
        targetrecord['Serial'] = self.get_next_serial(self.dc_ip, self.domain)
        targetrecord['Data'] = self.DNS_RPC_RECORD_A()
        targetrecord['Data'].fromCanonical(data)
        records.append(targetrecord.getData())
        self.conn.modify(targetentry['dn'], {'dnsRecord': [(MODIFY_REPLACE, records)]})
        return self.get_DNSentry(target)

    def del_DNSentry(self, target):
        targetentry = self.get_raw_entry(target)
        diff = datetime.datetime.today() - datetime.datetime(1601,1,1)
        tstime = int(diff.total_seconds()*10000)
        # Add a null record
        record = self.new_record(0)
        record['Data'] = self.DNS_RPC_RECORD_TS()
        record['Data']['entombedTime'] = tstime
        self.conn.modify(targetentry['dn'], {'dnsRecord': [(MODIFY_REPLACE, [record.getData()])],'dNSTombstoned': [(MODIFY_REPLACE, True)]})

    # List all user, group and computer objects
    def get_ADobjects(self):
        search_filter = f"(|(objectClass=user)(objectClass=group)(objectClass=computer))"
        self.conn.search(self.base_dn, search_filter, attributes=['*'])

        if self.conn.entries:
            return self.conn.entries

    # Search for user, group, or computer objects with sAMAccountName value
    def get_ADobject(self, _object):
        search_filter = f"(&(|(objectClass=user)(objectClass=group)(objectClass=computer))(sAMAccountName={_object}))"
        self.conn.search(self.base_dn, search_filter, attributes=['*'])

        if self.conn.entries:
            return self.conn.entries[0]

    # Adding users, computers or groups
    def add_ADobject(self, ou, attributes):
        if attributes['objectClass'] == 'user':
            sam = f"{attributes['givenName'].lower()[0]}{attributes['sn'].lower()}"
            cn = f"{attributes['givenName']} {attributes['sn']}"

            password = attributes['password']
            del attributes['password']

            attributes['mail'] = f"{attributes['givenName'].lower()}.{attributes['sn'].lower()}@{self.domain}"
            attributes['sAMAccountName'] = sam
            attributes['displayName'] = cn
            attributes['cn'] = cn
            attributes['userPrincipalName'] = f"{sam}@{self.domain}"

            self.conn.add(f"cn={cn},{ou}", attributes=attributes)

            self.reset_password(sam, password)
            self.modify_ADobject_attributes(sam, attributes={'userAccountControl': '512'})
            
    
        if attributes['objectClass'] == 'computer':
            sam = f"{attributes['cn'].lower()}$"
            cn = attributes['cn']
            attributes['sAMAccountName'] = sam

            self.conn.add(f"cn={cn},{ou}", attributes=attributes)


            import string, secrets
            characters = string.ascii_letters + string.digits + string.punctuation
            password = ''.join(secrets.choice(characters) for _ in range(20))
            self.reset_password(sam, password)

            changes = {
                'primaryGroupID': '515',
                'userAccountControl': '4096'
            }

            self.modify_ADobject_attributes(sam, changes)
        
        if attributes['objectClass'] == 'group':
            sam = f"{attributes['cn'].lower()}"
            cn = attributes['cn']
            attributes['sAMAccountName'] = sam

            self.conn.add(f"cn={cn},{ou}", attributes=attributes)
        
        return self.get_ADobject(sam)

    # Removing users, computers or groups
    def del_ADobject(self, _object):
        _object_dn = self.get_ADobject(_object).distinguishedName
        if self.conn.delete(_object_dn[0]):
            return 200
        else:
            return None

    # List members of group
    def get_member(self, group_name):
        search_filter = f"(&(objectClass=group)(sAMAccountName={group_name}))"
        self.conn.search(self.base_dn, search_filter, attributes=['member'])

        if self.conn.entries:
            return self.conn.entries[0].member
        

    # List groups of users
    def get_memberOf(self, username):
        search_filter = f"(&(objectClass=user)(sAMAccountName={username}))"
        self.conn.search(self.base_dn, search_filter, attributes=['memberOf'])

        if self.conn.entries:
            return self.conn.entries[0].memberOf


    # Adding users, computers, or groups to groups
    def add_ADobject_to_group(self, _object, group):
        _object_dn = self.get_ADobject(_object).distinguishedName
        group_dn = self.get_ADobject(group).distinguishedName

        self.conn.modify(group_dn[0], {'member': [(MODIFY_ADD, [_object_dn[0]])]})
        
        return self.get_ADobject(group).member


    # Removing users, computers, or groups from groups
    def del_ADobject_from_group(self, _object, group):
        _object_dn = self.get_ADobject(_object).distinguishedName
        group_dn = self.get_ADobject(group).distinguishedName

        self.conn.modify(group_dn[0], {'member': [(MODIFY_DELETE, _object_dn[0])]})
        
        return self.get_ADobject(group).member

    # Updating user, computer, or group attributes.
    def modify_ADobject_attributes(self, _object, attributes):
        _object_dn = self.get_ADobject(_object).distinguishedName

        for key, value in attributes.items():
            self.conn.modify(_object_dn[0], {key: [(MODIFY_REPLACE, [value])]})
        
        return self.get_ADobject(_object)


    # Reset password (Only work with ssl bind)
    def reset_password(self, username, password):
        user_dn = self.get_ADobject(username).distinguishedName

        if self.conn and self.secure:
            if ldap3.extend.microsoft.modifyPassword.ad_modify_password(self.conn, user_dn[0], password, old_password=None):
                return 200
            else:
                return None
        else:
            return 401


    # Enable users or computers
    def enable_ADobject(self, _object):
        uacFlag = 2
        old_uac = self.get_ADobject(_object).userAccountControl
        new_uac = int(str(old_uac)) & ~uacFlag

        attributes = {
            'userAccountControl': new_uac
        }

        self.modify_ADobject_attributes(_object, attributes)
        return self.get_ADobject(_object)


    # Disable users or computers
    def disable_ADobject(self, _object):
        uacFlag = 2
        old_uac = self.get_ADobject(_object).userAccountControl
        new_uac = int(str(old_uac)) | uacFlag

        attributes = {
            'userAccountControl': new_uac
        }

        self.modify_ADobject_attributes(_object, attributes)
        return self.get_ADobject(_object)
