from ldap3 import Server, Connection, ALL

class LDAPManager:
    def __init__(self, app):
        self.app = app
        self.server = self._initialize_server()
        self.connection = self._initialize_connection()

    def _initialize_server(self):
        dc_url = f"{self.app.config['LDAP_SCHEMA']}://{self.app.config['LDAP_HOST']}:{self.app.config['LDAP_PORT']}"
        return Server(dc_url, get_info=ALL)

    def _initialize_connection(self):
        sam = f"{self.app.config['LDAP_USERNAME']}@{self.app.config['LDAP_DOMAIN']}"
        return Connection(self.server, user=sam, password=self.app.config['LDAP_PASSWORD'], auto_bind=self.app.config['LDAP_BIND_DIRECT_CREDENTIALS'])

    def get_connection(self):
        if self.connection:
            return 'Successfully bound to LDAP server'

    def authenticate(self, username, password):
        self.connection.rebind(user=f"{username}@{self.app.config['LDAP_DOMAIN']}", password=password)
        search_filter = f"(&(objectClass=user)(sAMAccountName={username}))"
        result = self.connection.search(self.app.config['LDAP_BASE_DN'], search_filter, attributes=['distinguishedName'])
        return result