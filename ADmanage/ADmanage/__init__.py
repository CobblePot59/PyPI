import ldap3
from ldap3 import Server, Connection, ALL, MODIFY_ADD, MODIFY_DELETE, MODIFY_REPLACE

class ADclient:
    def __init__(self, domain, username, password, dc_ip, base_dn=None, secure=False):
        self.domain = domain
        self.username = username
        self.sam = f"{username}@{domain}"
        self.password = password
        self.dc_ip = dc_ip
        self.base_dn = base_dn
        self.secure = secure
        self.conn = self.connect_to_ldap()

    def connect_to_ldap(self):
        dc_url = f"ldaps://{self.dc_ip}:636" if self.secure else f"ldap://{self.dc_ip}:389"
        if not self.base_dn:
            self.base_dn = f"DC={self.domain.split('.')[0]},DC={self.domain.split('.')[1]}"

        server = Server(dc_url, get_info=ALL)
        conn = Connection(server, user=self.sam, password=self.password, auto_bind=True)
        return conn

    def disconnect(self):
        self.conn.unbind()

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
