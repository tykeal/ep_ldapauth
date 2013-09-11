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
            "groupSearch": "(&(cn=admin)(objectClass=groupOfNames))"
            "anonymousReadonly": false
        }
    },

## License

GPL-2.0
