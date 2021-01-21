// Copyright 2013 Andrew Grimberg <tykeal@bardicgrove.org>
//
// @License GPL-2.0 <http://spdx.org/licenses/GPL-2.0>

//var LdapAuth = require('ldapauth');
var MyLdapAuth = require('./lib/MyLdapAuth.js');
var util = require('util');
var fs = require('fs');

var ERR = require('async-stacktrace');
var settings = require('ep_etherpad-lite/node/utils/Settings');
var authorManager = require('ep_etherpad-lite/node/db/AuthorManager');

function ldapauthSetUsername(token, username) {
  console.debug('ep_ldapauth.ldapauthSetUsername: getting authorid for token %s', token);
  let author = authorManager.getAuthor4Token(token)
  author.then(
    function(author_id) {
      console.debug('ep_ldapauth.ldapauthSetUsername: have authorid %s, setting username to "%s"', author_id, username);
      authorManager.setAuthorName(author_id, username);
    });
  return;
}

exports.authenticate = function(hook_name, context, cb) {
  console.debug('ep_ldapauth.authenticate');
  // If auth headers are present use them to authenticate
  if (context.req.headers.authorization && context.req.headers.authorization.search('Basic ') === 0) {
    var userpass = new Buffer(context.req.headers.authorization.split(' ')[1], 'base64').toString().split(":");
    var username = userpass.shift();
    var password = userpass.join(':');
    var express_sid = context.req.sessionID;
    var myLdapAuthOpts = {
      url: settings.users.ldapauth.url,
      adminDn: settings.users.ldapauth.searchDN,
      adminPassword: settings.users.ldapauth.searchPWD,
      searchBase: settings.users.ldapauth.accountBase,
      searchFilter: settings.users.ldapauth.accountPattern,
      groupSearchBase: settings.users.ldapauth.groupSearchBase,
      groupAttribute: settings.users.ldapauth.groupAttribute,
      groupAttributeIsDN: settings.users.ldapauth.groupAttributeIsDN,
      searchScope: settings.users.ldapauth.searchScope,
      groupSearch: settings.users.ldapauth.groupSearchUser,
      cache: true
    };

    if (typeof(settings.users.ldapauth.tls_ca_file) !== 'undefined') {
      myLdapAuthOpts.tls_ca = fs.readFileSync(settings.users.ldapauth.tls_ca_file);
    }

    var authenticateLDAP = new MyLdapAuth(myLdapAuthOpts);

    // Attempt to authenticate the user
    authenticateLDAP.authenticate(username, password, function(err, user) {
      if (err) {
        console.error('ep_ldapauth.authenticate: LDAP auth error: %s', err);
        authenticateLDAP.close(function (err) {
          if (err) {
            console.error('ep_ldapauth.authenticate: LDAP close error: %s', err);
          }
        });
        authenticateLDAP = null;
        return cb([false]);
      }

      // User authenticated, save off some information needed for authorization
      context.req.session.user = { username: username };
      if ('displayNameAttribute' in settings.users.ldapauth && settings.users.ldapauth.displayNameAttribute in user) {
        context.req.session.user['displayName']=user[settings.users.ldapauth.displayNameAttribute];
      }
      else if ('cn' in user) {
        context.req.session.user['displayName']=user.cn;
      }
      if (settings.users.ldapauth.groupAttributeIsDN) {
        context.req.session.user.userDN = user.dn;
      }
      settings.globalUserName = username;
      console.debug('ep_ldapauth.authenticate: deferring setting of username [%s] to CLIENT_READY for express_sid = %s', username, express_sid);

      // Define userDN to search in groupSearchUser
      userDN = null;

      if (typeof(context.req.session.user) !== 'undefined' &&
        typeof(context.req.session.user.username) !== 'undefined') {
        username = context.req.session.user.username;
        if (typeof(context.req.session.user.userDN !== 'undefined')) {
          userDN = context.req.session.user.userDN;
        }
      } else {
        console.debug('ep_ldapauth.authenticate: no username in user object');
        return cb([false]);
      }

      // Search if our user is in the groupSearchUser
      authenticateLDAP.groupsearch(username, userDN, function(err, groups) {
        if (err) {
          console.error('ep_ldapauth.authenticate: LDAP groupsearch error: %s', err);
          authenticateLDAP.close(function (err) {
            if (err) {
              console.error('ep_ldapauth.authenticate: LDAP close error: %s', err);
            }
          });
          authenticateLDAP = null;
          return cb([false]);
        }

        // We've recieved back group(s) that the user matches
        // Given our current auth scheme (only checking on admin) we'll auth
        if (groups) {
          context.req.session.user.is_admin = true;
          authenticateLDAP.close(function (err) {
            if (err) {
              console.error('ep_ldapauth.authenticate: LDAP close error: %s', err);
            }
          });
          authenticateLDAP = null;
          console.debug('ep_ldapauth.authenticate: successful authorization');
          return cb([true]);
        } else {
          context.req.session.user.is_admin = false;
          authenticateLDAP.close(function (err) {
            if (err) {
              console.error('ep_ldapauth.authenticate: LDAP close error: %s', err);
            }
          });
          authenticateLDAP = null;
          console.debug('ep_ldapauth.authenticate: failed authorization');
          return cb([false]);
        }
      });
      
    });
  } else {
    console.debug('ep_ldapauth.authenticate: failed authentication no auth headers');
    return cb([false]);
  }
};

exports.authorize = function(hook_name, context, cb) {
  console.debug('ep_ldapauth.authorize');

  if(settings.users.ldapauth.anonymousReadonly &&
      /^\/(p\/r\..{16}|locales.json|static|javascripts|pluginfw|favicon.ico)/.test(context.resource)) {
    console.debug('ep_ldapauth.authorize.anonymous: authorizing static path %s', context.resource);
    return cb([true]);
  }

  userDN = null;

  if (typeof(context.req.session.user) !== 'undefined' &&
    typeof(context.req.session.user.username) !== 'undefined') {
    username = context.req.session.user.username;
    if (typeof(context.req.session.user.userDN) !== 'undefined') {
      userDN = context.req.session.user.userDN;
    }
  } else {
    console.debug('ep_ldapauth.authorize: no username in user object');
    return cb([false]);
  }

  if (/^\/(static|javascripts|pluginfw|favicon.ico|api)/.test(context.resource)) {
    console.debug('ep_ldapauth.authorize: authorizing static path %s', context.resource);
    return cb([true]);
  } else if (context.resource.match(/^\/admin/)) {
    console.debug('ep_ldapauth.authorize: attempting to authorize along administrative path %s', context.resource);
    var myLdapAuthOpts = {
      url: settings.users.ldapauth.url,
      adminDn: settings.users.ldapauth.searchDN,
      adminPassword: settings.users.ldapauth.searchPWD,
      searchBase: settings.users.ldapauth.accountBase,
      searchFilter: settings.users.ldapauth.accountPattern,
      groupSearchBase: settings.users.ldapauth.groupSearchBase,
      groupAttribute: settings.users.ldapauth.groupAttribute,
      groupAttributeIsDN: settings.users.ldapauth.groupAttributeIsDN,
      searchScope: settings.users.ldapauth.searchScope,
      groupSearch: settings.users.ldapauth.groupSearch,
      cache: true
    };

    if (typeof(settings.users.ldapauth.tls_ca_file) !== 'undefined') {
      myLdapAuthOpts.tls_ca = fs.readFileSync(settings.users.ldapauth.tls_ca_file);
    }

    var authorizeLDAP = new MyLdapAuth(myLdapAuthOpts);

    authorizeLDAP.groupsearch(username, userDN, function(err, groups) {
      if (err) {
        console.error('ep_ldapauth.authorize: LDAP groupsearch error: %s', err);
        authorizeLDAP.close(function (err) {
          if (err) {
            console.error('ep_ldapauth.authorize: LDAP close error: %s', err);
          }
        });
        authorizeLDAP = null;
        return cb([false]);
      }

      // We've recieved back group(s) that the user matches
      // Given our current auth scheme (only checking on admin) we'll auth
      if (groups) {
        context.req.session.user.is_admin = true;
        authorizeLDAP.close(function (err) {
          if (err) {
            console.error('ep_ldapauth.authorize: LDAP close error: %s', err);
          }
        });
        authorizeLDAP = null;
        console.debug('ep_ldapauth.authorize: successful authorization');
        return cb([true]);
      } else {
        context.req.session.user.is_admin = false;
        authorizeLDAP.close(function (err) {
          if (err) {
            console.error('ep_ldapauth.authorize: LDAP close error: %s', err);
          }
        });
        authorizeLDAP = null;
        console.debug('ep_ldapauth.authorize: failed authorization');
        return cb([false]);
      }
    });
  } else {
    console.debug('ep_ldapauth.authorize: passing authorize along for path %s', context.resource);
    return cb([false]);
  }
};

exports.handleMessage = function(hook_name, context, cb) {
  console.debug("ep_ldapauth.handleMessage");
  if ( context.message.type == "CLIENT_READY" ) {
    if (!context.message.token) {
      console.debug('ep_ldapauth.handleMessage: intercepted CLIENT_READY message has no token!');
    } else {
      var client_id = context.client.id;
      if ('user' in context.client.client.request.session) {
        var displayName = context.client.client.request.session.user.displayName;
        if(settings.users.ldapauth.anonymousReadonly && !displayName) displayName = 'guest';
        console.debug('ep_ldapauth.handleMessage: intercepted CLIENT_READY message for client_id = %s, setting username for token %s to %s', client_id, context.message.token, displayName);
        ldapauthSetUsername(context.message.token, displayName);
      }
      else {
        console.debug('ep_ldapauth.handleMessage: intercepted CLIENT_READY but user does have displayName !');
      }
    }
  } else if ( context.message.type == "COLLABROOM" && context.message.data.type == "USERINFO_UPDATE" ) {
    console.debug('ep_ldapauth.handleMessage: intercepted USERINFO_UPDATE and dropping it!');
    return cb([null]);
  }
  return cb([context.message]);
};

// vim: sw=2 ts=2 sts=2 et ai
