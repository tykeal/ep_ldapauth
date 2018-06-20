# Etherpad lite LDAP authentication and authorization

## Install

In your etherpad-lite dir:

    npm install ep_ldapauth

Add to settings.json:

    "users": {
        "ldapauth": {
            "url": "ldaps://ldap.example.com",
            "accountBase": "ou=Users,dc=example,dc=com",
            "accountPattern": "(&(objectClass=*)(uid={{username}}))",
            "displayNameAttribute": "cn",
            "searchDN": "uid=searchuser,dc=example,dc=com",
            "searchPWD": "supersecretpassword",
            "groupSearchBase": "ou=Groups,dc=example,dc=com",
            "groupAttribute": "member",
            "groupAttributeIsDN": true,
            "searchScope": "sub",
            "groupSearch": "(&(cn=admin)(objectClass=groupOfNames))",
            "anonymousReadonly": false
        }
    },

Users who are in the matches group have *admin* access to
etherpad-lite.

## Using with FreeIPA

First setup a read-only LDAP proxy user as described
[here](https://www.freeipa.org/page/HowTo/LDAP). Then adapt this settings.json
to match your IPA server URL, domain, LDAP proxy user and preferred admin group.

    "users": {
        "ldapauth": {
            "url": "ldap://ipa.example.org:389",
            "accountBase": "cn=users,cn=accounts,dc=example,dc=org",
            "accountPattern": "(&(objectClass=posixaccount)(uid={{username}}))",
            "displayNameAttribute": "displayname",
            "searchDN": "uid=ldapproxy,cn=sysaccounts,cn=etc,dc=example,dc=org",
            "searchPWD": "ldapproxy_password",
            "searchScope": "sub",
            "groupSearchBase": "cn=groups,cn=accounts,dc=example,dc=org",
            "groupAttribute": "member",
            "groupAttributeIsDN": true,
            "groupSearch": "(&(cn=sysadmins)(objectClass=posixgroup))",
        }
    },

## License

GPL-2.0
