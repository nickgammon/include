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

SSO = Single Sign On

My new system for having one set of credentials rather than one each for administration (eg. of home database),
forum, and Historical Society.

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
$SSO_EMAIL_GUESS_TABLE    = 'sso_email_guess_ip';

// name of cookie token
$SSO_COOKIE_NAME          = 'sso_cookie';

// actions
$SSO_LOGON           = 'sso_logon'           ;    // handle logon form being sent
$SSO_LOGON_FORM      = 'sso_logon_form'      ;    // show the logon form
$SSO_LOGOFF          = 'sso_logoff'          ;    // log off this particular session
$SSO_LOGOFF_ALL      = 'sso_logoff_all'      ;    // log off all sessions
$SSO_FORGOT_PASSWORD = 'sso_forgot_password' ;    // forgot my password, duh! (show the form)
$SSO_REQUEST_PASSWORD_RESET = 'sso_request_password_reset' ;  // handle the password form being filled in
$SSO_PASSWORD_RESET  = 'sso_password_reset' ;     // process the password reset
$SSO_AUTHENTICATOR   = 'sso_authenticator'   ;    // handle authenticator input being sent
$SSO_SHOW_SESSIONS   = 'sso_show_sessions'   ;    // show list of sessions

// audit types
$SSO_AUDIT_LOGON      = 1;
$SSO_AUDIT_LOGOFF     = 2;
$SSO_AUDIT_LOGOFF_ALL = 3;
$SSO_AUDIT_REQUEST_PASSWORD_RESET = 4;
$SSO_AUDIT_CHANGED_PASSWORD = 5;
$SSO_AUDIT_CHANGED_EMAIL = 6;

$MAX_EMAIL_GUESSES = 5;  // number of times they can guess their own email address


$loginInfo = array (
        'errors'      => array (),  // put here reasons for login failure
        'info'        => array (),  // put here success messages (eg. "logged in OK")
        'show_login'  => false,     // make true to redisplay the login form
        'show_authenticator' => false,  // make true to show the authenticator form
        'show_forgotten_password' => false, // show the forgotten password form
        );

$FORM_STYLE = <<< EOD
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
EOD;

function showVariables ($which)
  {
  echo '<p>Here is some debugging info:';
  echo '<pre>';
  $debug = print_r($which, true);
  echo (htmlspecialchars ($debug));
  echo '</pre>';
  } // end of showVariables

// audit something they have done
function SSO_Audit ($audit_type_id, $sso_id)
  {
  global $SSO_USER_TABLE, $SSO_FAILED_LOGINS_TABLE, $SSO_TOKENS_TABLE, $SSO_AUTHENTICATORS_TABLE,
         $SSO_BANNED_IPS_TABLE, $SSO_SUSPECT_IPS_TABLE, $SSO_AUDIT_TABLE;
  global $remote_ip;

  $query =  "INSERT INTO $SSO_AUDIT_TABLE (audit_date, audit_type_id, sso_id, ip_address)
                          VALUES (            NOW(),       ?,           ?,        ?)";

  $count = dbUpdateParam ($query,
                          array ('sss', &$audit_type_id, &$sso_id, &$remote_ip));
  if ($count == 0)
    Problem ("Could not insert audit record");
  } // end of SSO_Audit


function SSO_Login_Failure ($email_address, $password, $remote_ip)
  {
  global $SSO_USER_TABLE, $SSO_FAILED_LOGINS_TABLE, $SSO_TOKENS_TABLE, $SSO_AUTHENTICATORS_TABLE,
         $SSO_BANNED_IPS_TABLE, $SSO_SUSPECT_IPS_TABLE, $SSO_AUDIT_TABLE;

  global $MAX_LOGIN_FAILURES, $MAX_UNKNOWN_USER_FAILURES;
  global $loginInfo;

  $loginInfo ['show_login'] = true;

  $email_address = strtolower ($email_address);
  $password      = strtolower ($password);

  // generate login failure tracking record
  $query = "INSERT INTO $SSO_FAILED_LOGINS_TABLE "
       . "(email_address, password, date_failed, failure_ip) "
       . "VALUES (?, ?, NOW(), ?);";

  dbUpdateParam ($query, array ('sss', &$email_address, &$password, &$remote_ip));

  // delete old tracking records so the database doesn't get too cluttered
  dbUpdate ("DELETE FROM $SSO_FAILED_LOGINS_TABLE WHERE date_failed < DATE_ADD(NOW(), INTERVAL -1 YEAR)");

  $query = "UPDATE $SSO_USER_TABLE SET "
         . "count_failed_logins = count_failed_logins + 1 "
         . "WHERE email_address = ? ";

  dbUpdateParam ($query, array ('s', &$email_address));

  // clear old login failure tracking records (so they can reset by waiting a day)
  $query = "DELETE FROM $SSO_FAILED_LOGINS_TABLE "
         . "WHERE email_address = ? AND failure_ip = ? "
         . "AND date_failed < DATE_ADD(NOW(), INTERVAL -1 DAY) ";
  dbUpdateParam ($query, array ('ss', &$email_address, &$remote_ip));

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

  // turn suspect IPs into banned IPs
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

  global $SSO_AUDIT_LOGON, $SSO_AUDIT_LOGOFF, $SSO_AUDIT_LOGOFF_ALL, $SSO_AUDIT_REQUEST_PASSWORD_RESET,
         $SSO_AUDIT_CHANGED_PASSWORD, $SSO_AUDIT_CHANGED_EMAIL;

  $server_name = $_SERVER["HTTP_HOST"];

  // note when they logged on last and from where
  $query = "UPDATE $SSO_USER_TABLE SET "
         . "  date_logged_on = "
         . "  '" . strftime ("%Y-%m-%d %H:%M:%S", utctime()) . "', "
         . "  last_remote_ip = ? "
         . "WHERE sso_id = ?";
  dbUpdateParam ($query, array ('ss', &$remote_ip, &$sso_id));

  // grab user details in case we came in via the authenticator
  $SSO_UserDetails = dbQueryOneParam ("SELECT * from $SSO_USER_TABLE WHERE sso_id = ?",
                                      array ('s', &$sso_id));

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
  SSO_Audit ($SSO_AUDIT_LOGON, $sso_id);

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

  // save the token for this session on case they want to log off
  $SSO_UserDetails ['token'] = $token;
  } // end of SSO_Complete_Logon

function SSO_Handle_Logon ()
  {
  global $SSO_USER_TABLE, $SSO_FAILED_LOGINS_TABLE, $SSO_TOKENS_TABLE, $SSO_AUTHENTICATORS_TABLE,
         $SSO_BANNED_IPS_TABLE, $SSO_SUSPECT_IPS_TABLE, $SSO_AUDIT_TABLE;

  global $SSO_COOKIE_NAME;
  global $SSO_UserDetails, $loginInfo;
  global $remote_ip;
  global $email_address;

  if ($SSO_UserDetails)
    {
    $loginInfo ['info'] [] = "You are already logged on.";
    return; // give up
    }

  $banned_row = dbQueryOneParam ("SELECT * FROM $SSO_BANNED_IPS_TABLE WHERE ip_address  = ?",
                                array ('s', &$remote_ip));
  if ($banned_row)
    {
    $loginInfo ['errors'] [] = "That TCP/IP address is not permitted to log on";
    return; // give up
    } // end of a match

  // get email_address and password
  $email_address = getP ('email_address', 255);
  $password      = getP ('password', 50);

  if (!$email_address || !$password)
    {
    $loginInfo ['show_login'] = true;  // just assume they didn't see the form
    return;
    } // end of no email_address or no password

  if (!validateEmail ($email_address))
    {
    $loginInfo ['errors'] [] = "That email address is not in a valid format\n" .
           "It should be something like: yourName@yourProvider.com.au\n" .
           "Do not use quotes or '<' and '>' symbols.";

    $loginInfo ['show_login'] = true;  // show the form again
    return;
    } // end of bad email address

  // look user up on users table
  $SSO_UserDetails = dbQueryOneParam ("SELECT * FROM $SSO_USER_TABLE WHERE email_address = ?",
                               array ('s', &$email_address) );

  // user not found - immediate failure
  if (!$SSO_UserDetails)
    {
    $loginInfo ['errors'] [] = "Email address/password combination is not correct";
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
  // if the user has multiple authenticators all will get this token
  dbUpdateParam ("UPDATE $SSO_AUTHENTICATORS_TABLE SET Token = ?, Date_Token_Sent = NOW() WHERE sso_id = ?",
                 array ('si', &$token, &$sso_id));

  $loginInfo ['show_authenticator'] = true; // get the authenticator form to appear once we have our HTML header
  $loginInfo ['token'] = $token;            // token to be put into the form

  } // end of SSO_Handle_Logon

function SSO_ShowLoginForm ()
  {
  global $SSO_LOGON, $SSO_LOGON_FORM, $SSO_LOGOFF, $SSO_FORGOT_PASSWORD, $SSO_AUTHENTICATOR, $SSO_SHOW_SESSIONS;
  global $PHP_SELF;
  global $email_address;
  global $SSO_UserDetails, $loginInfo;
  global $FORM_STYLE;

  if ($SSO_UserDetails)
    {
    $loginInfo ['info'] [] = "You are already logged on.";
    return; // give up
    }

// show the form in a nice blue box
echo <<< EOD
<form METHOD="post" ACTION="$PHP_SELF">
$FORM_STYLE

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

function SSO_ShowAuthenticatorForm ()
  {
  global $SSO_LOGON, $SSO_LOGON_FORM, $SSO_LOGOFF, $SSO_FORGOT_PASSWORD, $SSO_AUTHENTICATOR, $SSO_SHOW_SESSIONS;
  global $PHP_SELF;
  global $SSO_UserDetails, $loginInfo;
  global $FORM_STYLE;

  $token  = $loginInfo ['token'];
  $sso_id = $SSO_UserDetails ['sso_id'];

// show the form in a nice blue box
echo <<< EOD
<form METHOD="post" ACTION="$PHP_SELF">
$FORM_STYLE

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
<input type="hidden"  name="token"  value="$token">
<input type="hidden"  name="sso_id" value="$sso_id">
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

  // show login form if wanted
  if ($loginInfo ['show_login'])
    SSO_ShowLoginForm ();
  // or the authenticator form
  elseif ($loginInfo ['show_authenticator'])
    SSO_ShowAuthenticatorForm ();
  elseif ($loginInfo ['show_forgotten_password'])
    SSO_Show_Forgot_Password_Form ();

  // show successes
  foreach ($loginInfo ['info'] as $info)
      ShowInfo ($info);

  return $SSO_UserDetails;    // will be false if login failed
  } // end of SSO_ShowLoginInfo

function SSO_Handle_Authenticator ()
  {
  global $SSO_USER_TABLE, $SSO_FAILED_LOGINS_TABLE, $SSO_TOKENS_TABLE, $SSO_AUTHENTICATORS_TABLE,
         $SSO_BANNED_IPS_TABLE, $SSO_SUSPECT_IPS_TABLE, $SSO_AUDIT_TABLE;

  global $VALID_NUMBER, $VALID_FLOAT, $VALID_DATE, $VALID_ACTION, $VALID_BOOLEAN, $VALID_SQL_ID,
         $VALID_COLOUR, $VALID_REGISTRATION_NUMBER;
  global $SSO_UserDetails, $loginInfo;
  global $PHP_SELF, $remote_ip;

  if ($SSO_UserDetails)
    {
    $loginInfo ['info'] [] = "You are already logged on.";
    return; // give up
    }

  $sso_id  = getP ('sso_id', 8, $VALID_NUMBER);
  $token  =  getP ('token', 50, '^[a-zA-Z0-9]+$');

  // check user ID and token are OK
  $authRow = dbQueryOneParam ("SELECT COUNT(*) AS counter FROM $SSO_AUTHENTICATORS_TABLE " .
                              "WHERE sso_id = ? ".
                              "AND   Token = ? " .
                              "AND   NOW() < DATE_ADD(Date_Token_Sent, INTERVAL 5 MINUTE) ",
                              array ('ss', &$sso_id, &$token));

  if ($authRow ['counter'] == 0)
   {
   $loginInfo ['errors'] [] = "Authenticator request out of date or invalid";
   $SSO_UserDetails = false;
   SSO_Login_Failure ('(unknown)', '(unknown)', $remote_ip);
   return;
   }

  $log_on_error = HandleAuthenticator ($sso_id, $SSO_AUTHENTICATORS_TABLE, 'sso_id');
  if ($log_on_error)
   {
   // find email address for the failure log
   $row = dbQueryOneParam ("SELECT email_address from $SSO_USER_TABLE WHERE sso_id = ?",
                           array ('s', &$sso_id));
   $loginInfo ['errors'] [] = $log_on_error;
   $SSO_UserDetails = false;
   SSO_Login_Failure ($row ['email_address'], '(unknown)', $remote_ip);
   return;
   }

  // cancel that token string on the authenticator table
  dbUpdateParam ("UPDATE $SSO_AUTHENTICATORS_TABLE SET Token = '' WHERE sso_id = ?", array ('i', &$sso_id));
  SSO_Complete_Logon ($sso_id);
  } // end of SSO_Handle_Authenticator

function SSO_See_If_Logged_On ()
  {
  global $SSO_USER_TABLE, $SSO_FAILED_LOGINS_TABLE, $SSO_TOKENS_TABLE, $SSO_AUTHENTICATORS_TABLE,
         $SSO_BANNED_IPS_TABLE, $SSO_SUSPECT_IPS_TABLE, $SSO_AUDIT_TABLE;

  global $SSO_COOKIE_NAME;
  global $SSO_UserDetails, $loginInfo;
  global $remote_ip;

  // find the token on their cookie
  // do NOT get POST variable or we switch users when editing the user table
  if (isset ($_COOKIE [$SSO_COOKIE_NAME]))
    $token = $_COOKIE [$SSO_COOKIE_NAME];
  else
    return; // no cookie, can't be logged on

  $tokenRow = dbQueryOneParam ("SELECT sso_id FROM $SSO_TOKENS_TABLE WHERE token = ? "  .
                                "AND date_expires >= NOW()",
                                array ('s', &$token) );

  if (!$tokenRow)
    return;   // token not on file

  $sso_id = $tokenRow ['sso_id'];

  // grab user details
  $SSO_UserDetails = dbQueryOneParam ("SELECT * from $SSO_USER_TABLE WHERE sso_id = ?",
                                      array ('s', &$sso_id));

  // see if they have been blocked since they logged in
  if ($SSO_UserDetails ['blocked'])
    {
    $loginInfo ['errors'] [] = "You are not permitted to log on (banned)";
    $SSO_UserDetails = false;
    return; // give up
    }

  // check if they carried a good token to a bad IP
  if ($SSO_UserDetails ['required_ip'])
    if ($SSO_UserDetails ['required_ip'] != $remote_ip)
      {
      $loginInfo ['errors'] [] = "You cannot log on from that IP address";
      $SSO_UserDetails = false;
      return;  // don't generate a cookie
      }

  // in case they want to log off
  $SSO_UserDetails ['token'] = $token;

  } // end of SSO_See_If_Logged_On

function SSO_Handle_Logoff ($all)
  {
  global $SSO_USER_TABLE, $SSO_FAILED_LOGINS_TABLE, $SSO_TOKENS_TABLE, $SSO_AUTHENTICATORS_TABLE,
         $SSO_BANNED_IPS_TABLE, $SSO_SUSPECT_IPS_TABLE, $SSO_AUDIT_TABLE;

  global $SSO_UserDetails, $loginInfo;
  global $SSO_AUDIT_LOGON, $SSO_AUDIT_LOGOFF, $SSO_AUDIT_LOGOFF_ALL, $SSO_AUDIT_REQUEST_PASSWORD_RESET,
         $SSO_AUDIT_CHANGED_PASSWORD, $SSO_AUDIT_CHANGED_EMAIL;

  if (!$SSO_UserDetails)
    {
    $loginInfo ['info'] [] = "You are already logged off.";
    return; // give up
    }

  $sso_id = $SSO_UserDetails ['sso_id'];
  $token  = $SSO_UserDetails ['token'];

  // delete token from tokens table
  if ($all)
    {
    dbUpdateParam ("DELETE FROM $SSO_TOKENS_TABLE WHERE sso_id = ?",
                  array ('s', &$sso_id));

    $loginInfo ['info'] [] = "Logged off from all devices.";
    // audit that they logged on
    SSO_Audit ($SSO_AUDIT_LOGOFF_ALL, $sso_id);
    }
  else
    {
    dbUpdateParam ("DELETE FROM $SSO_TOKENS_TABLE WHERE sso_id = ? AND token = ?",
                  array ('ss', &$sso_id, &$token));
    $loginInfo ['info'] [] = "Logged off from this device.";
    // audit that they logged on
    SSO_Audit ($SSO_AUDIT_LOGOFF, $sso_id);
    }

  // invalidate their login details
  $SSO_UserDetails = false;

  } // end of SSO_Handle_Logoff

function SSO_Show_Forgot_Password_Form ()
  {
  global $SSO_LOGON, $SSO_LOGON_FORM, $SSO_LOGOFF, $SSO_FORGOT_PASSWORD, $SSO_REQUEST_PASSWORD_RESET,
         $SSO_AUTHENTICATOR, $SSO_SHOW_SESSIONS;
  global $PHP_SELF;
  global $SSO_UserDetails, $loginInfo;
  global $FORM_STYLE;
  global $email_address;

  if ($SSO_UserDetails)
    {
    $loginInfo ['info'] [] = "You are already logged on - no password reset required.";
    return; // give up
    }

// show the form in a nice blue box
echo <<< EOD
<form METHOD="post" ACTION="$PHP_SELF">
$FORM_STYLE

<h2>Password reset request</h2>
<table>
<tr>
<th align=right>Email address:</th>
<td><input type="text"      name="email_address" size=50 maxlength=255
    value="$email_address" autofocus style="width:95%;" required></td>
</tr>
<tr><td></td>
<td><input type="submit"    value="Reset password"></td>
</tr>
</table>
</div>
<input type="hidden"    name="action" value="$SSO_REQUEST_PASSWORD_RESET">
</form>
EOD;
  } // end of SSO_Show_Forgot_Password_Form

function SSO_Handle_Password_Reset_Request ()
  {
  global $SSO_LOGON, $SSO_LOGON_FORM, $SSO_LOGOFF, $SSO_FORGOT_PASSWORD, $SSO_REQUEST_PASSWORD_RESET,
         $SSO_PASSWORD_RESET, $SSO_AUTHENTICATOR, $SSO_SHOW_SESSIONS;
  global $PHP_SELF;
  global $SSO_UserDetails, $loginInfo;
  global $FORM_STYLE;
  global $remote_ip;
  global $control;
  global $MAX_EMAIL_GUESSES;

  global $SSO_USER_TABLE, $SSO_FAILED_LOGINS_TABLE, $SSO_TOKENS_TABLE, $SSO_AUTHENTICATORS_TABLE,
         $SSO_BANNED_IPS_TABLE, $SSO_SUSPECT_IPS_TABLE, $SSO_AUDIT_TABLE, $SSO_EMAIL_GUESS_TABLE;

  global $SSO_AUDIT_LOGON, $SSO_AUDIT_LOGOFF, $SSO_AUDIT_LOGOFF_ALL, $SSO_AUDIT_REQUEST_PASSWORD_RESET,
         $SSO_AUDIT_CHANGED_PASSWORD, $SSO_AUDIT_CHANGED_EMAIL;


  if ($SSO_UserDetails)
    {
    $loginInfo ['info'] [] = "You are already logged on - no password reset required.";
    return; // give up
    }

  $banned_row = dbQueryOneParam ("SELECT * FROM $SSO_BANNED_IPS_TABLE WHERE ip_address  = ?",
                                array ('s', &$remote_ip));
  if ($banned_row)
    {
    $loginInfo ['errors'] [] = "That TCP/IP address is not permitted to log on";
    return; // give up
    } // end of a match

  // get email_address
  $email_address = getP ('email_address', 255);

  if (!$email_address)
    {
    $loginInfo ['errors'] [] = "Email address must be given";
    return;
    } // end of no email_address

  if (!validateEmail ($email_address))
    {
    $loginInfo ['errors'] [] = "That email address is not in a valid format\n" .
           "It should be something like: yourName@yourProvider.com.au\n" .
           "Do not use quotes or '<' and '>' symbols.";
    $loginInfo ['show_forgotten_password'] = true;  // show the form again

    return;
    } // end of bad email address


  // clear old email guess failure tracking records (so they can reset by waiting a day)
  dbUpdate ("DELETE FROM $SSO_EMAIL_GUESS_TABLE
             WHERE date_failed < DATE_ADD(NOW(), INTERVAL -1 DAY)");

  $failureRow = dbQueryOneParam ("SELECT * FROM $SSO_EMAIL_GUESS_TABLE WHERE failure_ip = ?",
                                  array ('s', &$remote_ip));
  if ($failureRow && $failureRow ['count'] >= $MAX_EMAIL_GUESSES)
    {
    $loginInfo ['errors'] [] = "Too many attempts to guess your email address.\n" .
                                "You can try again tomorrow if necessary.";
    return;
    }

/* TESTING
  if ($failureRow && $failureRow ['password_sent'] == 1)
    {
    $loginInfo ['errors'] [] = "A password has already been emailed to this IP address in the last 24 hours.\n" .
                                "You can try again later if necessary.";
    return;
    }
*/
  // look user up on users table
  $SSO_UserDetails = dbQueryOneParam ("SELECT * FROM $SSO_USER_TABLE WHERE email_address = ? ",
                               array ('s', &$email_address) );

  if (!$SSO_UserDetails)
    {
    // track their attempts
    if ($failureRow)
      dbUpdateParam ("UPDATE $SSO_EMAIL_GUESS_TABLE SET count = count + 1, date_failed = NOW(), password_sent = NULL " .
                "WHERE failure_ip = ?", array ('s', &$remote_ip));
    else
      dbUpdateParam ("INSERT INTO $SSO_EMAIL_GUESS_TABLE (count, date_failed, failure_ip) VALUES " .
                "(1, NOW(), ?) ", array ('s', &$remote_ip));
    $loginInfo ['errors'] [] = "That email address is not on file";
    $SSO_UserDetails = false;  // wrong email
    SSO_Login_Failure ($email_address, '(unknown)', $remote_ip);
    return;
    }

   $todayRow = dbQueryOne ("SELECT CURDATE() as today");  // no user input

  // don't let them keep asking for it
  if ($SSO_UserDetails ['password_sent_date'] == $todayRow ['today'])
    {
    $loginInfo ['errors'] [] = "You have already been sent your password today.\n" .
                               "Please check your email.\n" .
                               "You can try again tomorrow if necessary.";
    $SSO_UserDetails = false;
    return;
    }

  $sso_id = $SSO_UserDetails ['sso_id'];

  // generate a hash for when they agree to change the password
  srand ((double) microtime () * 1000000);
  $password = base64_encode (openssl_random_pseudo_bytes (12));

  $md5_password = md5 ($password);   // the validation hash, not the password

  // update the password on file
  $query = "UPDATE $SSO_USER_TABLE SET password_reset_hash = ? WHERE sso_id = ?";

  dbUpdateParam ($query, array ('ss', &$md5_password, &$sso_id )) ;

  $sso_name = $control ['sso_name'];
  $sso_url  = $control ['sso_url'];

  // send mail message

  $mailresult = mail ($email_address,
        "$sso_name password",
        "Hi $email_address,\n\n" .
        "Someone (possibly you) requested that your $sso_name password be reset.\n\n" .
        "To reset your password, please click on:\n\n" .
        "  $sso_url$PHP_SELF?action=$SSO_PASSWORD_RESET&sso_id=$sso_id&hash=$md5_password\n\n" .
        "The password must be reset on the same day the request was made.\n\n" .
        "If you do not want your password reset, just ignore this message.\n\n" .
        $control ['email_signature'],
      // mail header
      "From: " . $control ['email_from'] . "\r\n" .
      "Content-Type: text/plain\r\n" .
      "X-mailer: PHP/" . phpversion()
      );

  if (!$mailresult)
    Problem ("An error occurred sending the email message");

  $loginInfo ['info'] [] = "Your password reset request is now being emailed to: $email_address";

  // remember when we sent the password
  dbUpdateParam ("UPDATE $SSO_USER_TABLE SET password_sent_date = NOW() WHERE sso_id = ?",
                  array ('s', &$sso_id));

  // remember we sent one for this IP
  if ($failureRow)
    dbUpdateParam ("UPDATE $SSO_EMAIL_GUESS_TABLE SET count = 0, date_failed = NOW(), password_sent = 1
                   WHERE failure_ip = ?", array ('s', &$remote_ip));
  else
    dbUpdateParam ("INSERT INTO $SSO_EMAIL_GUESS_TABLE  (count, date_failed, failure_ip, password_sent) VALUES
                   (0, NOW(), ?, 1) ", array ('s', &$remote_ip));

  // audit password reset requests
  SSO_Audit ($SSO_AUDIT_REQUEST_PASSWORD_RESET, $sso_id);

  } // end of SSO_Handle_Password_Reset_Request

function SSO_Handle_Password_Reset ()
  {
  global $SSO_LOGON, $SSO_LOGON_FORM, $SSO_LOGOFF, $SSO_FORGOT_PASSWORD, $SSO_REQUEST_PASSWORD_RESET,
         $SSO_PASSWORD_RESET, $SSO_AUTHENTICATOR, $SSO_SHOW_SESSIONS;
  global $PHP_SELF;
  global $SSO_UserDetails, $loginInfo;
  global $FORM_STYLE;
  global $remote_ip;
  global $control;

  $loginInfo ['errors'] [] = "foo";
  } // end of SSO_Handle_Password_Reset

// *****************************************************************
//      SSO_Authenticate - call for all authentication actions
// *****************************************************************

function SSO_Authenticate ()
  {
  global $DATABASE_SERVER, $GENERAL_DATABASE_USER, $GENERAL_DATABASE_NAME, $GENERAL_DATABASE_PASSWORD;
  global $SSO_LOGON, $SSO_LOGON_FORM, $SSO_LOGOFF, $SSO_LOGOFF_ALL, $SSO_FORGOT_PASSWORD,
         $SSO_REQUEST_PASSWORD_RESET, $SSO_PASSWORD_RESET, $SSO_AUTHENTICATOR, $SSO_SHOW_SESSIONS;
  global $action;
  global $PHP_SELF, $remote_ip;
  global $SSO_UserDetails, $loginInfo;

  // Note: $action is already set by common.php

  $SSO_UserDetails = false;    // no user found yet

  // find this page
  $PHP_SELF = $_SERVER['PHP_SELF'];  // what page this is
  // find their IP address
  $remote_ip = getIPaddress ();

  // open the database, parameters are in the general_config.php file
  OpenDatabase ($DATABASE_SERVER, $GENERAL_DATABASE_USER, $GENERAL_DATABASE_NAME, $GENERAL_DATABASE_PASSWORD);

  GetControlItems ();

  // first see if our cookie gives us logged-on status
  SSO_See_If_Logged_On ();

  // logon form is handled in SSO_ShowLoginInfo (as we need to have shown the HTML header)
  switch ($action)
    {
    case $SSO_LOGON           : SSO_Handle_Logon (); break;
    case $SSO_LOGON_FORM      : $loginInfo ['show_login'] = true; break;
    case $SSO_LOGOFF          : SSO_Handle_Logoff (false); break;
    case $SSO_LOGOFF_ALL      : SSO_Handle_Logoff (true); break;
    case $SSO_FORGOT_PASSWORD : $loginInfo ['show_forgotten_password'] = true; break;
    case $SSO_REQUEST_PASSWORD_RESET  : SSO_Handle_Password_Reset_Request (); break;
    case $SSO_PASSWORD_RESET  : SSO_Handle_Password_Reset (); break;
    case $SSO_AUTHENTICATOR   : SSO_Handle_Authenticator (); break;
    case $SSO_SHOW_SESSIONS   : SSO_Handle_Show_Sessions (); break;
    } // end of switch on $action
  } // end of SSO_Authenticate
?>
