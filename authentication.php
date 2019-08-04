<?php

/*
Copyright © 2019 Nick Gammon.

  Author: Nick Gammon <nick@gammon.com.au>
  Web:    http://www.gammon.com.au/
  Date:   February 2019


 PERMISSION TO DISTRIBUTE

 Permission is hereby granted, free of charge, to any person obtaining a copy of this software
 and associated documentation files (the "Software"), to deal in the Software without restriction,
 including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense,
 and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so,
 subject to the following conditions:

 The above copyright notice and this permission notice shall be included in
 all copies or substantial portions of the Software.

 LIMITATION OF LIABILITY

 The software is provided "as is", without warranty of any kind, express or implied,
 including but not limited to the warranties of merchantability, fitness for a particular
 purpose and noninfringement. In no event shall the authors or copyright holders be liable
 for any claim, damages or other liability, whether in an action of contract,
 tort or otherwise, arising from, out of or in connection with the software
 or the use or other dealings in the software.


*/

// for bcrypt stuff (password_hash / password_verify)
require ($INCLUDE_DIRECTORY . "password.php");

// database tables

$SSO_USER_TABLE           = 'sso_users';
$SSO_FAILED_LOGINS_TABLE  = 'sso_failed_logins';
$SSO_TOKENS_TABLE         = 'sso_tokens';
$SSO_AUTHENTICATORS_TABLE = 'sso_authenticators';
$SSO_BANNED_IPS_TABLE     = 'sso_banned_ips';
$SSO_SUSPECT_IPS_TABLE    = 'sso_suspect_ips';
$SSO_AUDIT_TABLE          = 'sso_audit';

// name of cookie token
$SSO_COOKIE_NAME          = 'sso_cookie';

// actions
$SSO_LOGON           = 'sso_logon'           ;
$SSO_LOGON_FORM      = 'sso_logon_form'      ;
$SSO_LOGOFF          = 'sso_logoff'          ;
$SSO_FORGOT_PASSWORD = 'sso_forgot_password' ;
$SSO_AUTHENTICATOR   = 'sso_authenticator'   ;
$SSO_SHOW_SESSIONS   = 'sso_show_sessions'   ;


$loginInfo = array (
        'errors'    => array (),  // put here reasons for login failure
        'info'      => array (),  // put here success messages (eg. "logged in OK")
        'try_again' => false,     // make true to redisplay the login form
        );

function showVariables ($which)
  {
  echo '<p>Here is some debugging info:';
  echo '<pre>';
  $debug = print_r($which, true);
  echo (htmlspecialchars ($debug));
  echo '</pre>';
  } // end of showVariables


function SSO_Login_Failure ($email_address, $password, $remote_ip)
  {
  global $SSO_USER_TABLE, $SSO_FAILED_LOGINS_TABLE, $SSO_TOKENS_TABLE, $SSO_AUTHENTICATORS_TABLE,
         $SSO_BANNED_IPS_TABLE, $SSO_SUSPECT_IPS_TABLE, $SSO_AUDIT_TABLE;

  global $MAX_LOGIN_FAILURES, $MAX_UNKNOWN_USER_FAILURES;
  global $loginInfo;

  $loginInfo ['try_again'] = true;

  $email_address = strtolower ($email_address);
  $password      = strtolower ($password);

  // generate login failure tracking record
  $query = "INSERT INTO $SSO_FAILED_LOGINS_TABLE "
       . "(email_address, password, date_failed, failure_ip) "
       . "VALUES (?, ?, NOW(), ?);";

  dbUpdateParam ($query, array ('sss', &$email_address, &$password, &$remote_ip));

  $query = "UPDATE $SSO_USER_TABLE SET "
         . "count_failed_logins = count_failed_logins + 1 "
         . "WHERE email_address = ? ";

  dbUpdateParam ($query, array ('s', &$email_address));

  // clear old login failure tracking records (so they can reset by waiting a day)
  $query = "DELETE FROM $SSO_FAILED_LOGINS_TABLE "
         . "WHERE email_address = ? AND failure_ip = ? "
         . "AND date_failed < DATE_ADD(NOW(), INTERVAL -1 DAY) ";
  dbUpdateParam ($query, array ('ss', &$email_address, &$remote_ip));

  // delete old tracking records so the database doesn't get too cluttered
  dbUpdate ("DELETE FROM $SSO_FAILED_LOGINS_TABLE WHERE date_failed < DATE_ADD(NOW(), INTERVAL -1 YEAR)");

  // see how many times they failed from this IP address
  $query = "SELECT count(*) AS counter "
          . "FROM $SSO_FAILED_LOGINS_TABLE "
          . "WHERE failure_ip  = ? "
          . "AND email_address = ?";

  $failure_row = dbQueryOneParam ($query, array ('ss', &$remote_ip, &$email_address));

  if ($failure_row ['counter'] > $MAX_LOGIN_FAILURES)
    {
    // now block that IP address
    $query = "INSERT INTO $SSO_BANNED_IPS_TABLE (ip_address, date_banned, reason) "
           . "VALUES ( ?, NOW(), CONCAT('Too many login failures for: ', ?) )";
    // don't check query, maybe already on file
    dbUpdateParam ($query, array ('ss', &$remote_ip, &$email_address), false);
    }

  // Extra code to allow for bots trying non-existent usernames:

  // see if user exists
  $row = dbQueryOneParam ("SELECT email_address FROM $SSO_USER_TABLE WHERE email_address = ? ",
                          array ('s', &$email_address));

  if ($row)
    return;  // username exists, all is OK

  $row = dbQueryOneParam ("SELECT * FROM $SSO_SUSPECT_IPS_TABLE WHERE ip_address = ? ",
                          array ('s', &$remote_ip));

  if ($row)
    {
    if ($row ['count'] >= $MAX_UNKNOWN_USER_FAILURES)
      {
      // right! that does it!
      // now block that IP address
      $query = "INSERT INTO $SSO_BANNED_IPS_TABLE (ip_address, date_banned, reason) "
             . "VALUES ( ?, NOW(), 'Too many attempts to login with unknown username' )";
      dbUpdateParam ($query, array ('s', &$remote_ip));
      // get rid of from $SSO_FAILED_LOGINS_TABLE
      dbUpdateParam ("DELETE FROM $SSO_FAILED_LOGINS_TABLE WHERE failure_ip = ? ",
                     array ('s', &$remote_ip));
      // get rid of from bbsuspect_ip
      dbUpdateParam ("DELETE FROM $SSO_SUSPECT_IPS_TABLE WHERE ip_address = ?",
                     array ('s', &$remote_ip));
      }
    else
      {
      // increment counter - haven't hit limit yet
      dbUpdateParam ("UPDATE $SSO_SUSPECT_IPS_TABLE SET count = count + 1 WHERE ip_address = ?",
                     array ('s', &$remote_ip));
      }

    } // if already on file
  else
    {
    dbUpdateParam ("INSERT INTO $SSO_SUSPECT_IPS_TABLE (ip_address, count) VALUES (?, 1)",
                   array ('s', &$remote_ip));
    }

  }  // end of SSO_Login_Failure

  // find the token on their cookie
  // do NOT get POST variable or we switch users when editing the user table
//  if (isset ($_COOKIE [$SSO_COOKIE_NAME]))
//    $token = $_COOKIE [$SSO_COOKIE_NAME];

// finish the logon process (this guy is OK)
//
// this is done as part of a normal logon (if no authenticator is required)
// or after successful authentication if an authenticator is required

function SSO_Complete_Logon ($sso_id)
  {
  global $SSO_USER_TABLE, $SSO_FAILED_LOGINS_TABLE, $SSO_TOKENS_TABLE, $SSO_AUTHENTICATORS_TABLE,
         $SSO_BANNED_IPS_TABLE, $SSO_SUSPECT_IPS_TABLE, $SSO_AUDIT_TABLE;
  global $SSO_UserDetails, $loginInfo;
  global $remote_ip;
  global $SSO_COOKIE_NAME;

 global $AUDIT_LOGGED_ON, $AUDIT_LOGGED_OFF;

  $server_name = $_SERVER["HTTP_HOST"];

  // note when they logged on last and from where
  $query = "UPDATE $SSO_USER_TABLE SET "
         . "  date_logged_on = "
         . "  '" . strftime ("%Y-%m-%d %H:%M:%S", utctime()) . "', "
         . "  last_remote_ip = ? "
         . "WHERE sso_id = ?";
  dbUpdateParam ($query, array ('ss', &$remote_ip, &$sso_id));

  // delete out-of-date tokens
  $query = "DELETE FROM $SSO_TOKENS_TABLE WHERE sso_id = ? AND date_expires <= NOW()";
  dbUpdateParam ($query, array ('s', &$sso_id));

  // generate token
  $token = MakeToken ();

  // work out token (cookie) expiry date
  $expiry = $SSO_UserDetails ['cookie_expiry'];
  if (!$expiry)
    $expiry = 60 * 60 * 24 * 7;    // expire in 7 days as default

  $days = ceil ($expiry / (60 * 60 * 24));

  // add token to good tokens table
  $query = "INSERT INTO $SSO_TOKENS_TABLE "
         .        "(sso_id, token, date_logged_on, last_remote_ip, server_name, date_expires) "
         . "VALUES ( ?,           ?,     NOW(),             ?,           ?, "      // see below
         . "DATE_ADD(NOW(), INTERVAL '$days' DAY))";

  dbUpdateParam ($query, array ('ssss', &$sso_id, &$token, &$remote_ip, &$server_name ));

  // audit that they logged on
  audit ($AUDIT_LOGGED_ON, $sso_id);

  // set their cookie
  setcookie ($SSO_COOKIE_NAME, $token, utctime() + $expiry, "/");

  // clear login failure tracking records (so they don't accumulate)
  $query = "DELETE FROM $SSO_FAILED_LOGINS_TABLE "
         . "WHERE email_address = ? AND failure_ip = ?";
  dbUpdateParam ($query, array ('ss', &$email_address, &$remote_ip));

  // get rid of from bbsuspect_ip - this IP seems OK now
  dbUpdateParam ("DELETE FROM $SSO_SUSPECT_IPS_TABLE WHERE ip_address = ?",
                 array ('s', &$remote_ip));

  $email_address = $SSO_UserDetails ['email_address'];
  // confirmation message
  $loginInfo ['info'] [] = "Logged on for email: $email_address";

  } // end of SSO_Complete_Logon

function SSO_Handle_Logon ()
  {
  global $SSO_USER_TABLE, $SSO_FAILED_LOGINS_TABLE, $SSO_TOKENS_TABLE, $SSO_AUTHENTICATORS_TABLE,
         $SSO_BANNED_IPS_TABLE, $SSO_SUSPECT_IPS_TABLE, $SSO_AUDIT_TABLE;

  global $SSO_COOKIE_NAME;
  global $SSO_UserDetails, $loginInfo;
  global $remote_ip;
  global $email_address;

  $SSO_UserDetails = false;    // no user found yet

  $banned_row = dbQueryOneParam ("SELECT * FROM $SSO_BANNED_IPS_TABLE WHERE ip_address  = ?",
                                array ('s', &$remote_ip));
  if ($banned_row)
    {
    $loginInfo ['errors'] [] = "That TCP/IP address is not permitted to log on";
    return; // give up
    } // end of a match

  // get email_address and password
  $email_address = getP ('email_address', 30);
  $password      = getP ('password', 50);

  if (!$email_address || !$password)
    {
    $loginInfo ['try_again'] = true;  // just assume they didn't see the form
    return;
    } // end of no email_address or no password

  if (!validateEmail ($email_address))
    {
    $loginInfo ['errors'] [] = "Email address is not in valid format";
    SSO_Login_Failure ($email_address, $password, $remote_ip);
    return;
    } // end of bad email address

  // look user up on users table
  $SSO_UserDetails = dbQueryOneParam ("SELECT * FROM $SSO_USER_TABLE WHERE email_address = ? ",
                               array ('s', &$email_address) );

  // user not found - immediate failure
  if (!$SSO_UserDetails)
    {
    $loginInfo ['errors'] [] = "Email address/password combination is not correct";
    $SSO_UserDetails = false;  // wrong password
    SSO_Login_Failure ($email_address, $password, $remote_ip);
    return;
    } // end of wrong password

  // if no password on the database, logging in MUST fail
  if (!$SSO_UserDetails ['password'])
    {
    $loginInfo ['errors'] [] = "User has not been set up correctly on the database";
    $SSO_UserDetails = false;    // discard user information
    return;
    }

  // check password with bcrypt
  if (PasswordCompat\binary\check() &&
      PasswordCompat\binary\_strlen ($SSO_UserDetails ['password']) > 32)
    {
    if (!password_verify ($password, $SSO_UserDetails ['password']))
      {
      $loginInfo ['errors'] [] = "Email address/password combination is not correct";
      $SSO_UserDetails = false;  // wrong password
      SSO_Login_Failure ($email_address, $password, $remote_ip);
      return;
      } // end of wrong password
    } // end of password > 32 bytes
  else
    {
    $loginInfo ['errors'] [] = "Authentication system not set up correctly";
    $SSO_UserDetails = false;    // discard user information
    return;
    } // end of <= 32 bytes

  if ($SSO_UserDetails ['blocked'])
    {
    $loginInfo ['errors'] [] = "You are not permitted to log on (banned)";
    $SSO_UserDetails = false;
    return; // give up
    }

  if ($SSO_UserDetails ['required_ip'])
    if ($SSO_UserDetails ['required_ip'] != $remote_ip)
      {
      $loginInfo ['errors'] [] = "You cannot log on from that IP address";
      $SSO_UserDetails = false;
      return;  // don't generate a cookie
      }

  $sso_id = $SSO_UserDetails ['sso_id'];

  // generate token
  $token = MakeToken ();

  // see if this guy needs authentication
  $authrow = dbQueryOneParam ("SELECT COUNT(*) AS counter FROM $SSO_AUTHENTICATORS_TABLE WHERE sso_id = ?",
                              array ('i', &$sso_id));

  // no, so log them in
  if ($authrow ['counter'] == 0 )
    {
    SSO_Complete_Logon ($sso_id);
    return;
    }

  // security check for when they respond - the token identifies who we are authenticating
  dbUpdateParam ("UPDATE $SSO_AUTHENTICATORS_TABLE SET Token = ?, Date_Token_Sent = NOW() WHERE sso_id = ?",
                 array ('si', &$token, &$sso_id));


  SSO_ShowAuthenticatorForm ($token);

  } // end of SSO_Handle_Logon

function SSO_ShowLoginForm ()
  {
  global $SSO_LOGON, $SSO_LOGON_FORM, $SSO_LOGOFF, $SSO_FORGOT_PASSWORD, $SSO_AUTHENTICATOR, $SSO_SHOW_SESSIONS;
  global $PHP_SELF;
  global $email_address;

// show the form in a nice blue box
echo <<< EOD
<form METHOD="post" ACTION="$PHP_SELF">
<div style="margin-left:1em;
    margin-bottom:2em;
    border-spacing:10px 10px;
    border-width:7px;
    border-color:DeepSkyBlue;
    border-style:solid;
    border-radius:10px;
    background-color:AliceBlue;
    padding:1em;
    display: inline-block;
    font-size:80%;
    width:60%;
    ">

<table>
<tr>
<th align=right>Email address:</th>
<td><input type="text"      name="email_address" size=50 maxlength=255
    value="$email_address" autofocus style="width:95%;" ></td>
</tr>
<tr>
<th align=right>Password:</th>
<td><input type="password"  name="password" size=50 maxlength=60 required style="width:95%;"></td>
</tr>
<tr><td></td>
<td><a href="$PHP_SELF?action=$SSO_FORGOT_PASSWORD">Forgot password</a></td>
</tr>
<tr><td></td>
<td><input type="submit"    value="Log on"></td>
</tr>
</table>
</div>
<input type="hidden"    name="action" value="$SSO_LOGON">
</form>
EOD;
  } // end of SSO_ShowLoginForm

function SSO_ShowAuthenticatorForm ($token)
  {
  global $SSO_LOGON, $SSO_LOGON_FORM, $SSO_LOGOFF, $SSO_FORGOT_PASSWORD, $SSO_AUTHENTICATOR, $SSO_SHOW_SESSIONS;
  global $PHP_SELF;
  global $email_address;

// show the form in a nice blue box
echo <<< EOD
<form METHOD="post" ACTION="$PHP_SELF">
<div style="margin-left:1em;
    margin-bottom:2em;
    border-spacing:10px 10px;
    border-width:7px;
    border-color:DeepSkyBlue;
    border-style:solid;
    border-radius:10px;
    background-color:AliceBlue;
    padding:1em;
    display: inline-block;
    font-size:80%;
    width:60%;
    ">

<h2>Authenticator required</h2>
<p><table>
<tr>
<th align=right>Authenticator:</th>
<td><input type="text"      name="authenticator" size=50 maxlength=100 autofocus style="width:95%;" ></td>
</tr>
<tr><td></td>
<td><input type="submit"    value="Submit"></td>
</tr>
</table>
</div>
<input type="hidden"  name="action" value="$SSO_AUTHENTICATOR">
<input type="token"   name="action" value="$token">
</form>
EOD;
  } // end of SSO_ShowAuthenticatorForm

function SSO_ShowLoginInfo ()
  {
  global $SSO_LOGON, $SSO_LOGON_FORM, $SSO_LOGOFF, $SSO_FORGOT_PASSWORD, $SSO_AUTHENTICATOR, $SSO_SHOW_SESSIONS;
  global $SSO_UserDetails, $loginInfo;
  global $action;

  // show errors
  foreach ($loginInfo ['errors'] as $error)
      ShowWarning ($error);

  // show successes
  foreach ($loginInfo ['info'] as $info)
      ShowInfo ($info);

  // redisplay login form if wanted
  if ($loginInfo ['try_again'] || $action == $SSO_LOGON_FORM)
    SSO_ShowLoginForm ();

  return $SSO_UserDetails;    // will be false if login failed
  } // end of SSO_ShowLoginInfo

// *****************************************************************
//      authenticate - call for all authentication actions
// *****************************************************************

function SSO_Authenticate ()
  {
  global $DATABASE_SERVER, $GENERAL_DATABASE_USER, $GENERAL_DATABASE_NAME, $GENERAL_DATABASE_PASSWORD;
  global $SSO_LOGON, $SSO_LOGON_FORM, $SSO_LOGOFF, $SSO_FORGOT_PASSWORD, $SSO_AUTHENTICATOR, $SSO_SHOW_SESSIONS;
  global $action;
  global $PHP_SELF, $remote_ip;
  global $loginInfo;

  // Note: $action is already set by common.php

  // find this page
  $PHP_SELF = $_SERVER['PHP_SELF'];  // what page this is
  // find their IP address
  $remote_ip = getIPaddress ();

  // open the database, parameters are in the general_config.php file
  OpenDatabase ($DATABASE_SERVER, $GENERAL_DATABASE_USER, $GENERAL_DATABASE_NAME, $GENERAL_DATABASE_PASSWORD);

  GetControlItems ();

  // logon form is handled in SSO_ShowLoginInfo (as we need to have shown the HTML header)
  switch ($action)
    {
    case $SSO_LOGON           : SSO_Handle_Logon (); break;
    case $SSO_LOGOFF          : SSO_Handle_Logoff (); break;
    case $SSO_FORGOT_PASSWORD : SSO_Handle_Forgot_Password (); break;
    case $SSO_AUTHENTICATOR   : SSO_Handle_Authenticator (); break;
    case $SSO_SHOW_SESSIONS   : SSO_Handle_Show_Sessions (); break;
    } // end of switch on $action
  } // end of SSO_Authenticate
?>
