// Copyright 2013 Andrew Grimberg <tykeal@bardicgrove.org>
//
// @License GPL-2.0 <http://spdx.org/licenses/GPL-2.0>

var util = require('util');
var LdapAuth = require('ldapauth');

/**
 * Create the MyLdapAuth class which is a super class of LdapAuth
 *
 * Additional @params opts (see LdapAuth for base params)
 *  groupSearchBase {string} Base search location for groups
 *    E.g. 'ou=Groups,dc=example,dc=com'
 *  groupAttribute {string} Attribute of group that members belong to
 *    E.g. 'member'
 *  groupAttributeIsDN {boolean} If the groupAttribute is a DN or simple username
 *  searchScope {string} LDAP search scobe to use for group searching
 *    E.g. 'sub'
 *  groupSearch {string} LDAP search filter for administrative group.
 *    NOTE: filter must return only 1 group to work correctly
 *    E.g.: 'cn=admin,ou=Groups,dc=example,dc=com'
 */
function MyLdapAuth(opts) {
  MyLdapAuth.super_.call(this, opts);
}

util.inherits(MyLdapAuth, LdapAuth);

/**
 * Searches groups to see if a given user is in them
 *
 * @param username {string} Username to lookup against groupSearch
 */
MyLdapAuth.prototype.groupsearch = function (username, cb) {
  var self = this;
  if (!username) {
    return cb('empty username');
  }

  var usersearch = username;

  // Do we need to look up the user DN?
  if (self.opts.groupAttributeIsDN) {
    // We need to lookup the user DN
    self._findUser(username, function (err, user) {
      if (err)
        return cb(err);
      if (!user)
        return cb(util.format('no such user: "%s"', username));
      usersearch = user.dn;
    });
  }

  // Do group lookup
  self._adminBind(function (err) {
    if (err)
      return cb(err);

    var opts = {filter: self.opts.groupSearch, scope: self.opts.searchScope};
    self._adminClient.search(self.opts.groupSearchBase, opts,
                              function (err, result) {
      if (err) {
        self.log && self.log.trace('LDAP groupsearch: search error: %s', err);
        return cb(err);
      }
      if (!result)
        return cb('no groups match: "%s"', self.opts.groupSearch);

      var items = [];
      result.on('searchEntry', function (entry) {
        items.push(entry.object);
      });
      result.on('error', function (err) {
        self.log && self.log.trace(
          'ldap groupsearch: search error event: %s', err);
        return cb(err);
      });
      result.on('end', function (result) {
        if (result.status !== 0) {
          var err = 'non-zero status from LDAP search: ' + result.status;
          self.log && self.log.trace('ldap groupsearch: %s', err);
          return cb(err);
        }
        switch (items.length) {
          case 0:
            return cb();
          case 1:
            if (items[0].member.some(function (item) {
              return (item === usersearch);
            }))
              return cb(null, items[0]);

            return cb(util.format('LDAP groupsearch: "%s" is not a member of "%s"',
              username, items[0].dn));
          default:
            return cb(util.format(
              'unexpected number of matches (%s) for "%s" groups',
              items.length, self.opts.groupSearch));
        }
      });
    });
  });
}

module.exports = MyLdapAuth;

// vim: sw=2 ts=2 sts=2 et ai
