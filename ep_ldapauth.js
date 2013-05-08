// Copyright 2013 Andrew Grimberg <tykeal@bardicgrove.org>
//
// @License GPL-2.0 <http://spdx.org/licenses/GPL-2.0>

//var LdapAuth = require('ldapauth');
var MyLdapAuth = require('./lib/MyLdapAuth.js');
var util = require('util');

var ERR = require('async-stacktrace');
var settings = require('ep_etherpad-lite/node/utils/Settings');
var authorManager = require('ep_etherpad-lite/node/db/AuthorManager');

function ldapauthSetUsername(token, username) {
  console.debug('ep_ldapauth.ldapauthSetUsername: getting authorid for token %s', token);
  authorManager.getAuthor4Token(token, function(err, author) {
    if (ERR(err)) {
      console.debug('ep_ldapauth.ldapauthSetUsername: could not get authorid for token %s', token);
    } else {
      console.debug('ep_ldapauth.ldapauthSetUsername: have authorid %s, setting username to "%s"', author, username);
      authorManager.setAuthorName(author, username);
    }
  });
  return;
}

exports.authenticate = function(hook_name, context, cb) {
  console.debug('ep_ldapauth.authenticate');
  // If auth headers are present use them to authenticate
  if (context.req.headers.authorization && context.req.headers.authorization.search('Basic ') === 0) {
    var userpass = new Buffer(context.req.headers.authorization.split(' ')[1], 'base64').toString().split(":");
    var username = userpass[0];
    var password = userpass[1];
    var express_sid = context.req.sessionID;

    var ldap = new MyLdapAuth({
      url: settings.users.ldapauth.url,
      adminDn: settings.users.ldapauth.searchDN,
      adminPassword: settings.users.ldapauth.searchPWD,
      searchBase: settings.users.ldapauth.accountBase,
      searchFilter: settings.users.ldapauth.accountPattern,
      cache: true
    });

    // Attempt to authenticate the user
    ldap.authenticate(username, password, function(err, user) {
      if (err) {
        console.error('ep_ldapauth.authenticate: LDAP auth error: %s', err);
        return cb([false]);
      }

      // User authenticated, save off some information needed for authorization
      context.req.session.user = { username: username, displayName: user.cn };
      settings.globalUserName = username;
      console.debug('ep_ldapauth.authenticate: deferring setting of username [%s] to CLIENT_READY for express_sid = %s', username, express_sid);
      return cb([true]);
    });
  } else {
    return cb([false]);
  }
}

exports.authorize = function(hook_name, context, cb) {
  console.debug('ep_ldapauth.authorize');

  var ldap = new MyLdapAuth({
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
  });

  if (typeof(context.req.session.user) != 'undefined' &&
    typeof(context.req.session.user.username) != 'undefined') {
    username = context.req.session.user.username;
  } else {
    console.debug('ep_ldapauth.authorize: no username in user object');
    return cb([false]);
  }

  if (context.resource.match(/^\/(static|javascripts|pluginfw|favicon.ico|api)/)) {
    console.debug('ep_ldapauth.authorize: authorizing static path %s', context.resource);
    return cb([true]);
  } else if (context.resource.match(/^\/admin/)) {
    console.debug('ep_ldapauth.authorize: authorizing along administrative path %s', context.resource);
    ldap.groupsearch(username, function(err, groups) {
      if (err) {
        console.error('ep_ldapauth.authorize: LDAP groupsearch error: %s', err);
        return cb([false]);
      }

      // We've recieved back group(s) that the user matches
      // Given our current auth scheme (only checking on admin) we'll auth
      if (groups) {
        context.req.session.user.is_admin = true;
        return cb([true]);
      } else {
        context.req.session.user.is_admin = false;
        return cb([false]);
      }
    });
  } else {
    console.debug('ep_ldapauth.authorize: passing authorize along for path %s', context.resource);
    return cb([false]);
  }
}

exports.handleMessage = function(hook_name, context, cb) {
  console.debug("ep_ldapauth.handleMessage");
  if ( context.message.type == "CLIENT_READY" ) {
    if (!context.message.token) {
      console.debug('ep_ldapauth.handleMessage: intercepted CLIENT_READY message has no token!');
    } else {
      var client_id = context.client.id;
      var displayName = context.client.manager.handshaken[client_id].session.user.displayName;
      console.debug('ep_ldapauth.handleMessage: intercepted CLIENT_READY message for client_id = %s, setting username for token %s to %s', client_id, context.message.token, displayName);
      ldapauthSetUsername(context.message.token, displayName);
    }
  } else if ( context.message.type == "COLLABROOM" && context.message.data.type == "USERINFO_UPDATE" ) {
    console.debug('ep_ldapauth.handleMessage: intercepted USERINFO_UPDATE and dropping it!');
    return cb([null]);
  }
  return cb([context.message]);
}

// vim: sw=2 ts=2 sts=2 et ai
