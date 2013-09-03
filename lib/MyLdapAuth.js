// Copyright 2013 Andrew Grimberg <tykeal@bardicgrove.org>
//
// @License GPL-2.0 <http://spdx.org/licenses/GPL-2.0>

var assert = require('assert');
var util = require('util');
var ldap = require('ldapjs');

/**
 * Create the MyLdapAuth class which is a former super class of LdapAuth
 * until I ended up having to reimplement too much of it
 *
 * @param opts {Object} config options. Keys (required, unless stated
 *    otherwise) are:
 *  url {String} E.g. 'ldaps://ldap.example.com:663'
 *  adminDn {String} E.g. 'uid=myapp,ou=users,o=example.com'
 *  adminPassword {String} Password for adminDn
 *  searchBase {String} The base DN from which to search for users by
 *    username. E.g. 'ou=users,o=example.com'
 *  searchFilter {String} LDAP search filter with which to find a user by
 *    username, e.g. '(uid={{username}})'. Use the literal '{{username}}'
 *    to have the given username be interpolated in for the LDAP search.
 *  log4js {Module} Optional. The require'd log4js module to use for logging.
 *    If given this will result in TRACE-level loggin for MyLdapAuth
 *  verbose {Boolean} Optional, default false. if `log4js` is also given,
 *    this will add TRACE-level logging for ldapjs (quite verbose).
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
  this.opts = opts;
  assert.ok(opts.url);
  assert.ok(opts.adminDn);
  assert.ok(opts.searchBase);
  assert.ok(opts.searchFilter);

  this.log = opts.log4js && opts.log4js.getLogger('ldapauth');

  var clientOpts = {url: opts.url};
  if (opts.log4js && opts.verbose) {
    clientOpts.log4js = opts.log4js;
  }
}

MyLdapAuth.prototype.close = function (cb) {
  var self = this;
  if (typeof(self._adminClient) !== 'undefined') {
    self._adminClient.unbind(function (err) {
      if (err) {
        return cb(err);
      }
      self._adminClient = null;
      return cb();
    });
  }
}

MyLdapAuth.prototype._adminBind = function (cb) {
  var self = this;
  if (typeof(self._adminClient) !== 'undefined') {
    return cb();
  }
  var clientOpts = {url: self.opts.url};
  self._adminClient = ldap.createClient(clientOpts);
  self._adminClient.bind(self.opts.adminDn, self.opts.adminPassword,
    function (err) {
    if (err) {
      return cb(err);
    }
    return cb();
  });
}

/**
 * Find the user record for the given username.
 *
 * @param username {String}
 * @param cb {Function} `function (err, user)`. If not such user is
 *  found but no error processing, then `user` is undefined.
 */
MyLdapAuth.prototype._findUser = function (username, cb) {
  var self = this;
  if (!username) {
    return cb("empty username");
  }

  self._adminBind(function (err) {
    if (err)
      return cb(err);

    var searchFilter = self.opts.searchFilter.replace('{{username}}', username);
    var opts = {filter: searchFilter, scope: 'sub'};
    self._adminClient.search(self.opts.searchBase, opts,
      function (err, result) {
      if (err) {
        return cb(err);
      }
      var items = [];
      result.on('searchEntry', function (entry) {
        items.push(entry.object);
      });
      result.on('error', function (err) {
        return cb(err);
      });
      result.on('end', function (result) {
        if (result.status !== 0) {
          var err = 'non-zero status from LDAP search: ' + result.status;
          return cb(err);
        }
        switch (items.length) {
          case 0:
            return cb();
          case 1:
            return cb(null, items[0]);
          default:
            return cb(util.format(
              'unexpected number of matches (%s) for "%s" username',
              items.length, username));
        }
      });
    });
  });
}

MyLdapAuth.prototype.authenticate = function (username, password, cb) {
  var self = this;

  // 1. Find the user DN in question.
  self._findUser(username, function (err, user) {
    if (err)
      return cb(err);
    if (!user)
      return cb(util.format('no such user: "%s"', username));
    // 2. Attempt to bind as that user to check password.
    var clientOpts = {url: self.opts.url};
    var userClient = ldap.createClient(clientOpts);
    userClient.bind(user.dn, password, function (err) {
      if (err) {
        return cb(err);
      }
      // User auth's cleanly, destroy the LDAP bind
      userClient.unbind();
      userClient = null;
      return cb(null, user);
    });
  });
}

/**
 * Searches groups to see if a given user is in them
 *
 * @param username {string} Username to lookup against groupSearch
 * @param userDN {string}
 */
MyLdapAuth.prototype.groupsearch = function (username, userDN, cb) {
  var self = this;
  if (!username) {
    return cb('empty username');
  }

  var usersearch = username;

  // Do we need to look up the user DN?
  if (self.opts.groupAttributeIsDN) {
    usersearch = userDN;
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
            if (self.opts.groupAttribute in items[0]) {
              if (typeof items[0][self.opts.groupAttribute] === 'string') {
                items[0][self.opts.groupAttribute]=new Array(items[0][self.opts.groupAttribute]);
              }
              if (items[0][self.opts.groupAttribute].some(function (item) {
                return (item === usersearch);
              })) {
                return cb(null, items[0]);
              }
            }

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
