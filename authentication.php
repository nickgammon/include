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

EXPLANATION
-----------

This system provides a centralized authentication of users without providing extra functionality per se
(like a forum, Historical Society membership, or administrative rights).

A user "logs on" by authenticating with a username or email, and a password. They possibly may be asked
for an authenticator as well. Once authenticated they are considered logged on, and a token is passed in a cookie
to the user's browser so they stay logged on until the token expires.

We can't display stuff to the user initially because we may need to set a cookie, which is done BEFORE sending
any data to them, and we may be planning to send non-display stuff, like a CSV file, SVG file, image file etc.

The function SSO_Authenticate is called automatically as part of the common.php (last line). This does the initial
work of seeing if they are already authenticated (via the cookie) or are trying to authenticate (via some POST
action). Any confirmation or error messages are not displayed at this time but placed in the $SSO_loginInfo array
with subsections for errors and information messages. Also if a menu needs to be displayed a boolean is set there
(for example, a failed password means that the login form needs to be displayed again).

The first thing that user scripts will normally do (after some preliminary checking of actions) is to call Init which
then tries to tie the authenticated user (if they are indeed logged in) to any subsystems that uses the SSO system.
For example, if the 'user' table has an entry for this user then they are considered logged into that as well. Ditto
for the forum user table, and the HHS members table.


UPDATE SQL:

// copy users over
INSERT INTO sso_users (username, email_address, password, cookie_expiry, blocked, last_remote_ip)
    SELECT username, email, password, cookie_expiry, blocked, last_remote_ip FROM bbuser

// fix up old reset passwords
UPDATE sso_users SET password = '' WHERE password LIKE '%***%'

// fix up the SSO ID
UPDATE bbuser INNER JOIN sso_users ON bbuser.email = sso_users.email_address
    SET bbuser.sso_id = sso_users.sso_id

// authenticators
INSERT INTO sso_authenticators  (Auth_ID, Public_UID, Secret_UID, AES_key, sso_id, Counter, Date_Last_Used)
    SELECT Auth_ID, Public_UID, Secret_UID, AES_key, User, Counter, Date_Last_Used FROM authenticator

*/

// for bcrypt stuff (password_hash / password_verify)
require ($INCLUDE_DIRECTORY . "password.php");

// database tables

$SSO_USER_TABLE           = 'sso_users';
$SSO_FAILED_LOGINS_TABLE  = 'sso_failed_logins';
$SSO_TOKENS_TABLE         = 'sso_tokens';
$SSO_AUTHENTICATORS_TABLE = 'sso_authenticators';
$SSO_BANNED_IPS_TABLE     = 'sso_banned_ips';
$SSO_BANNED_EMAIL_TABLE   = 'sso_banned_email';
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
$SSO_LOGOFF_OTHERS   = 'sso_logoff_others'   ;    // log off all sessions except this one
$SSO_FORGOT_PASSWORD = 'sso_forgot_password' ;    // forgot my password, duh! (show the form)
$SSO_REQUEST_PASSWORD_RESET = 'sso_request_password_reset' ;  // handle the password form being filled in
$SSO_PASSWORD_RESET  = 'sso_password_reset' ;     // process the password reset
$SSO_AUTHENTICATOR   = 'sso_authenticator'   ;    // handle authenticator input being sent
$SSO_SHOW_SESSIONS   = 'sso_show_sessions'   ;    // show list of sessions
$SSO_CHANGE_PASSWORD = 'sso_change_password'   ;  // change the password
$SSO_SHOW_CHANGE_PASSWORD = 'sso_show_change_password'   ;  // show the change the password form
$SSO_SHOW_CHANGE_NAME = 'sso_show_change_name'   ;  // show the change the screen name form
$SSO_CHANGE_NAME      = 'sso_change_name'   ;    // handle the change name request

// audit types
$SSO_AUDIT_LOGON                  = 1;
$SSO_AUDIT_LOGOFF                 = 2;
$SSO_AUDIT_LOGOFF_ALL             = 3;
$SSO_AUDIT_LOGOFF_OTHERS          = 4;
$SSO_AUDIT_REQUEST_PASSWORD_RESET = 5;
$SSO_AUDIT_CHANGED_PASSWORD       = 6;
$SSO_AUDIT_CHANGED_EMAIL          = 7;
$SSO_AUDIT_CHANGED_NAME           = 8;

$MAX_EMAIL_GUESSES = 5;  // number of times they can guess their own email address

// Stuff carried forwards from the preliminary processing in SSO_Authenticate to what is
// eventually displayed in SSO_ShowLoginInfo.

$SSO_loginInfo = array (
        // messages
        'errors'      => array (),  // put here reasons for login failure
        'info'        => array (),  // put here success messages (eg. "logged in OK")

        // flags
        'show_login'  => false,     // make true to redisplay the login form
        'show_authenticator' => false,  // make true to show the authenticator form
        'show_forgotten_password' => false, // show the forgotten password form
        'show_new_password' => false, // show the new password form
        'show_sessions'     => false, // show logoff button etc.
        'show_name_change'  => false, // show name change form

        // data
        'new_password_hash' => false, // no hash yet
        'sso_id'            => false, // for password changing
        );

// styles for our forms boxes, and also the information box on the right
$FORM_STYLE = <<< EOD

<style type="text/css">
 .form_style
    {
    margin-left:1em;
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
    }

  .info_style
    {
    margin-left:1em;
    margin-bottom:1em;
    padding:5px;
    background-color:AliceBlue;
    opacity:0.7;
    display: inline-block;
    font-size:70%;
    text-align:center;
    float:right;
    }

 .motd_style
    {
    margin-left:1em;
    margin-bottom:2em;
    border-spacing:10px 10px;
    border-width:3px;
    border-color:SandyBrown;
    border-style:solid;
    border-radius:10px;
    background-color:SeaShell;
    padding:1em;
    display: inline-block;
    box-shadow:3px 3px 5px black;
    }

</style>
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
                          array ('iis', &$audit_type_id, &$sso_id, &$remote_ip));
  if ($count == 0)
    Problem ("Could not insert audit record");
  } // end of SSO_Audit


function SSO_Login_Failure ($email_address, $password, $remote_ip, $sso_id = 0)
  {
  global $SSO_USER_TABLE, $SSO_FAILED_LOGINS_TABLE, $SSO_TOKENS_TABLE, $SSO_AUTHENTICATORS_TABLE,
         $SSO_BANNED_IPS_TABLE, $SSO_SUSPECT_IPS_TABLE, $SSO_AUDIT_TABLE;

  global $MAX_LOGIN_FAILURES, $MAX_UNKNOWN_USER_FAILURES;
  global $SSO_loginInfo;

  $SSO_loginInfo ['show_login'] = true;

  $email_address = strtolower ($email_address);
  $password      = strtolower ($password);

  // generate login failure tracking record
  $query = "INSERT INTO $SSO_FAILED_LOGINS_TABLE
            (email_address, password, date_failed, failure_ip)
            VALUES (?, ?, NOW(), ?);";

  dbUpdateParam ($query, array ('sss', &$email_address, &$password, &$remote_ip));

  // delete old tracking records so the database doesn't get too cluttered
  dbUpdate ("DELETE FROM $SSO_FAILED_LOGINS_TABLE WHERE date_failed < DATE_ADD(NOW(), INTERVAL -1 YEAR)");

  // log a failure (bad password presumably) against the correct user
  if ($sso_id)
    dbUpdateParam ("UPDATE $SSO_USER_TABLE SET
                  count_failed_logins = count_failed_logins + 1,
                  date_last_failed_login = NOW()
                  WHERE sso_id = ? ",
                   array ('i', &$sso_id));

  // clear old login failure tracking records (so they can reset by waiting a day)
  $query = "DELETE FROM $SSO_FAILED_LOGINS_TABLE
            WHERE email_address = ? AND failure_ip = ?
            AND date_failed < DATE_ADD(NOW(), INTERVAL -1 DAY) ";
  dbUpdateParam ($query, array ('ss', &$email_address, &$remote_ip));

  // see how many times they failed from this IP address
  $query = "SELECT count(*) AS counter
            FROM $SSO_FAILED_LOGINS_TABLE
            WHERE failure_ip  = ?
            AND email_address = ?";

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
  global $SSO_UserDetails, $SSO_loginInfo;
  global $remote_ip;
  global $SSO_COOKIE_NAME;

  global $SSO_AUDIT_LOGON, $SSO_AUDIT_LOGOFF, $SSO_AUDIT_LOGOFF_ALL, $SSO_AUDIT_REQUEST_PASSWORD_RESET,
         $SSO_AUDIT_CHANGED_PASSWORD, $SSO_AUDIT_CHANGED_EMAIL;

  $server_name = $_SERVER["HTTP_HOST"];

  $loginTime = strftime ("%Y-%m-%d %H:%M:%S", utctime());

  // note when they logged on last and from where
  $query = "UPDATE $SSO_USER_TABLE SET
           date_logged_on = ?,
           last_remote_ip = ?,
           count_logins = count_logins + 1
           WHERE sso_id = ?";
  dbUpdateParam ($query, array ('ssi', &$loginTime, &$remote_ip, &$sso_id));

  // grab user details in case we came in via the authenticator
  $SSO_UserDetails = dbQueryOneParam ("SELECT * from $SSO_USER_TABLE WHERE sso_id = ?",
                                      array ('i', &$sso_id));

  // Delete out-of-date tokens for this user.
  // Don't delete for all users on the off-chance that a randomly-generated token
  // might give you access to a different user.
  // The unique key on the tokens table will then stop that from happening.
  $query = "DELETE FROM $SSO_TOKENS_TABLE WHERE sso_id = ? AND date_expires <= NOW()";
  dbUpdateParam ($query, array ('i', &$sso_id));

  // generate token
  $token = MakeToken ();

  // work out token (cookie) expiry date
  $cookie_expiry = $SSO_UserDetails ['cookie_expiry'];
  if (!$cookie_expiry)
    $cookie_expiry = 60 * 60 * 24 * 7;    // expire in 7 days as default

  $expiryTime = time() + $cookie_expiry;

  // add token to good tokens table
  $query = "INSERT INTO $SSO_TOKENS_TABLE "
         .        "(sso_id, token, date_logged_on, last_remote_ip, server_name, date_expires) "
         . "VALUES ( ?,           ?,     NOW(),             ?,           ?,    FROM_UNIXTIME(?) )";

  dbUpdateParam ($query, array ('isssi', &$sso_id, &$token, &$remote_ip, &$server_name, &$expiryTime));

  // audit that they logged on
  SSO_Audit ($SSO_AUDIT_LOGON, $sso_id);

  // we will JSON-encode the token *and* the expiry date, so we can find the expiry date later
  // See: https://stackoverflow.com/questions/4203225/how-to-get-cookies-expire-time
  $cookieData = (object) array( "token" => $token, "expiry" => $expiryTime );
  setcookie($SSO_COOKIE_NAME, json_encode($cookieData ), $expiryTime , "/");

  // clear login failure tracking records (so they don't accumulate)
  $query = "DELETE FROM $SSO_FAILED_LOGINS_TABLE "
         . "WHERE email_address = ? AND failure_ip = ?";
  dbUpdateParam ($query, array ('ss', &$email_address, &$remote_ip));

  // get rid of from bbsuspect_ip - this IP seems OK now
  dbUpdateParam ("DELETE FROM $SSO_SUSPECT_IPS_TABLE WHERE ip_address = ?",
                 array ('s', &$remote_ip));

  $username = $SSO_UserDetails ['username'];
  $email_address = $SSO_UserDetails ['email_address'];
  // confirmation message
  $SSO_loginInfo ['info'] [] = "Logged on for user: $username (Email: $email_address)";

  // save the token for this session on case they want to log off
  $SSO_UserDetails ['token'] = $token;
  } // end of SSO_Complete_Logon

function SSO_Handle_Logon ()
  {
  global $SSO_USER_TABLE, $SSO_FAILED_LOGINS_TABLE, $SSO_TOKENS_TABLE, $SSO_AUTHENTICATORS_TABLE,
         $SSO_BANNED_IPS_TABLE, $SSO_SUSPECT_IPS_TABLE, $SSO_AUDIT_TABLE;

  global $SSO_COOKIE_NAME;
  global $SSO_UserDetails, $SSO_loginInfo;
  global $remote_ip;
  global $email_address;

  if ($SSO_UserDetails)
    {
    $SSO_loginInfo ['info'] [] = "You are already logged on.";
    return; // give up
    }

  $banned_row = dbQueryOneParam ("SELECT * FROM $SSO_BANNED_IPS_TABLE WHERE ip_address  = ?",
                                array ('s', &$remote_ip));
  if ($banned_row)
    {
    $SSO_loginInfo ['errors'] [] = "That TCP/IP address is not permitted to log on";
    return; // give up
    } // end of a match

  // get email_address and password
  $email_address = getP ('email_address', 255);
  $password      = getP ('password', 50);

  if (!$email_address || !$password)
    {
    $SSO_loginInfo ['show_login'] = true;  // just assume they didn't see the form
    return;
    } // end of no email_address or no password

  // we'll let them use their screen name or email address

  if (strpos ($email_address, '@') === false)
    { // have a username
    // look user up on users table
    $SSO_UserDetails = dbQueryOneParam ("SELECT * FROM $SSO_USER_TABLE WHERE username = ?",
                                 array ('s', &$email_address) );

    // user not found (based on username) - immediate failure
    if (!$SSO_UserDetails)
      {
      $SSO_loginInfo ['errors'] [] = "User name/password combination is not correct";
      $SSO_loginInfo ['show_login'] = true;  // show the form again
      SSO_Login_Failure ($email_address, $password, $remote_ip, 0);  // no sso_id known
      return;
      } // end of user not on file
    }
  else
    { // have an email address
    if (!validateEmail ($email_address))
      {
      $SSO_loginInfo ['errors'] [] = "That email address is not in a valid format\n" .
             "It should be something like: yourName@yourProvider.com.au\n" .
             "Do not use quotes or '<' and '>' symbols.";

      $SSO_loginInfo ['show_login'] = true;  // show the form again
      return;
      } // end of bad email address

      // look user up on users table
      $SSO_UserDetails = dbQueryOneParam ("SELECT * FROM $SSO_USER_TABLE WHERE email_address = ?",
                                   array ('s', &$email_address) );

    // user not found (based on email) - immediate failure
    if (!$SSO_UserDetails)
      {
      $SSO_loginInfo ['errors'] [] = "Email address/password combination is not correct";
      $SSO_loginInfo ['show_login'] = true;  // show the form again
      SSO_Login_Failure ($email_address, $password, $remote_ip, 0);  // no sso_id known
      return;
      } // end of user not on file
    } // end of email address given rather than username


  // if no password on the database, logging in MUST fail
  if (!$SSO_UserDetails ['password'])
    {
    $SSO_loginInfo ['errors'] [] = "No password created yet, please use the 'Forgot Password' link to make a new one";
    $SSO_UserDetails = false;    // discard user information
    return;
    }

  // check password with bcrypt
  if (PasswordCompat\binary\check() &&
      PasswordCompat\binary\_strlen ($SSO_UserDetails ['password']) > 32)
    {
    if (!password_verify ($password, $SSO_UserDetails ['password']))
      {
      SSO_Login_Failure ($email_address, $password, $remote_ip, $SSO_UserDetails ['sso_id']);
      $SSO_loginInfo ['errors'] [] = "Email address/password combination is not correct";
      $SSO_UserDetails = false;  // wrong password
      $SSO_loginInfo ['show_login'] = true;  // show the form again
      return;
      } // end of wrong password
    } // end of password > 32 bytes
  else
    {
    $SSO_loginInfo ['errors'] [] = "Authentication system not set up correctly";
    $SSO_UserDetails = false;    // discard user information
    return;
    } // end of <= 32 bytes

  if ($SSO_UserDetails ['blocked'])
    {
    $SSO_loginInfo ['errors'] [] = "You are not permitted to log on (banned)";
    $SSO_UserDetails = false;
    return; // give up
    }

  if ($SSO_UserDetails ['required_ip'])
    if ($SSO_UserDetails ['required_ip'] != $remote_ip)
      {
      $SSO_loginInfo ['errors'] [] = "You cannot log on from that IP address";
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

  $SSO_loginInfo ['show_authenticator'] = true; // get the authenticator form to appear once we have our HTML header
  $SSO_loginInfo ['token'] = $token;            // token to be put into the form
  $SSO_loginInfo ['sso_id'] = $sso_id;          // sso_id to be put into the form
  $SSO_UserDetails = false;                 // important! this user is not logged in yet

  } // end of SSO_Handle_Logon

function SSO_ShowLoginForm ()
  {
  global $SSO_LOGON, $SSO_LOGON_FORM, $SSO_LOGOFF, $SSO_FORGOT_PASSWORD, $SSO_AUTHENTICATOR, $SSO_SHOW_SESSIONS;
  global $PHP_SELF;
  global $email_address;
  global $SSO_UserDetails, $SSO_loginInfo;
  global $control;

  if ($SSO_UserDetails)
    {
    $SSO_loginInfo ['info'] [] = "You are already logged on.";
    return; // give up
    }

  $sso_name = htmlspecialchars ($control ['sso_name']);

// show the form in a nice blue box
echo <<< EOD
<form METHOD="post" ACTION="$PHP_SELF">
<div class="form_style">
<h2>Log on to $sso_name</h2>
<table>
<tr>
<th align=right>User name or email address:</th>
<td><input type="text"      name="email_address" size=50 maxlength=255
    value="$email_address" autofocus style="width:95%;" ></td>
</tr>
<tr>
<th align=right>Password:</th>
<td><input type="password"  name="password" size=50 maxlength=60 required style="width:95%;"></td>

<tr><td></td>
<td><input type="submit"    value="Log on"></td>
</tr>
</table>
<a href="$PHP_SELF">Cancel log on</a>
<a href="$PHP_SELF?action=$SSO_FORGOT_PASSWORD" style="float:right;">Forgot password</a>
</div>
<input type="hidden"    name="action" value="$SSO_LOGON">
</form>
EOD;
  } // end of SSO_ShowLoginForm

function SSO_ShowNameChangeForm ()
  {
  global $SSO_LOGON, $SSO_LOGON_FORM, $SSO_LOGOFF, $SSO_LOGOFF_ALL, $SSO_LOGOFF_OTHERS,
         $SSO_FORGOT_PASSWORD, $SSO_REQUEST_PASSWORD_RESET, $SSO_PASSWORD_RESET, $SSO_AUTHENTICATOR,
         $SSO_SHOW_SESSIONS, $SSO_CHANGE_PASSWORD, $SSO_SHOW_CHANGE_PASSWORD,
         $SSO_SHOW_CHANGE_NAME, $SSO_CHANGE_NAME;
  global $PHP_SELF;
  global $email_address;
  global $SSO_UserDetails, $SSO_loginInfo;
  global $control;

  if (!$SSO_UserDetails)
    {
    $SSO_loginInfo ['info'] [] = "You are not logged on.";
    return; // give up
    }

  $sso_name = htmlspecialchars ($control ['sso_name']);
  $sso_max_username_length = $control ['sso_max_username_length'];

  $username = htmlspecialchars ($SSO_UserDetails ['username']);
  $new_name      = getP ('new_name', 60);
  if (!$new_name)
    $new_name = $username;

// show the form in a nice blue box
echo <<< EOD
<form METHOD="post" ACTION="$PHP_SELF">
<div class="form_style">
<h2>User name change for $sso_name</h2>
<p>Your existing user name is: <b>$username</b>
<table>
<tr>
<th align=right>New name:</th>
<td><input type="text"      name="new_name" size="$sso_max_username_length" maxlength="$sso_max_username_length"
     autofocus value="$new_name" required style="width:95%;" ></td>
</tr>
<tr><td></td>
<td><input type="submit"    value="Change name"></td>
</tr>
</table>
<a href="$PHP_SELF">Cancel name change</a>
</div>
<input type="hidden"    name="action" value="$SSO_CHANGE_NAME">
</form>
EOD;
  } // end of SSO_ShowNameChangeForm

function SSO_ShowAuthenticatorForm ()
  {
  global $SSO_LOGON, $SSO_LOGON_FORM, $SSO_LOGOFF, $SSO_FORGOT_PASSWORD, $SSO_AUTHENTICATOR, $SSO_SHOW_SESSIONS;
  global $PHP_SELF;
  global $SSO_UserDetails, $SSO_loginInfo;

  $token  = $SSO_loginInfo ['token'];
  $sso_id = $SSO_loginInfo ['sso_id'];

// show the form in a nice blue box
echo <<< EOD
<form METHOD="post" ACTION="$PHP_SELF">
<div class="form_style">

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
<a href="$PHP_SELF">Cancel log in</a>
</div>
<input type="hidden"  name="action" value="$SSO_AUTHENTICATOR">
<input type="hidden"  name="token"  value="$token">
<input type="hidden"  name="sso_id" value="$sso_id">
</form>
EOD;
  } // end of SSO_ShowAuthenticatorForm

function SSO_ShowNewPasswordForm ()
  {
  global $SSO_LOGON, $SSO_LOGON_FORM, $SSO_LOGOFF, $SSO_FORGOT_PASSWORD, $SSO_AUTHENTICATOR, $SSO_SHOW_SESSIONS, $SSO_CHANGE_PASSWORD;
  global $PHP_SELF;
  global $email_address;
  global $SSO_UserDetails, $SSO_loginInfo;
  global $control;

  $hash   = $SSO_loginInfo ['new_password_hash'];  // possibly not there if we are logged in
  $sso_id = $SSO_loginInfo ['sso_id'];

  $sso_name = htmlspecialchars ($control ['sso_name']);
  $sso_min_password_length = $control ['sso_min_password_length'];

// show the form in a nice blue box
echo <<< EOD
<form METHOD="post" ACTION="$PHP_SELF">
<div class="form_style">
<input type="hidden" name="hash" value="$hash">
<input type="hidden" name="sso_id" value="$sso_id">
<h2>New password for $sso_name</h2>
<table>
EOD;

// for forgotten passwords they will have a hash from an email, otherwise they must know the old password
if (!$hash && $SSO_UserDetails)
  {
  $sso_id = $SSO_UserDetails ['sso_id'];
  echo <<< EOD
  <tr>
  <th align=right>Old password:</th>
  <td><input type="password"      name="old_password" size=50 maxlength=50 required
      style="width:95%;" ></td>
  </tr>
EOD;
  }

// this stuff is always there
echo <<< EOD
<tr>
<th align=right>New password:</th>
<td><input type="password"  name="new_password" size=50 maxlength=50 required style="width:95%;"></td>
</tr>
<tr>
<th align=right>Confirm new password:</th>
<td><input type="password"  name="confirm_password" size=50 maxlength=50 required style="width:95%;"></td>
</tr>
<tr><td></td>
<td><input type="submit"    value="Change password"></td>
</tr>
</table>
<h2>Rules for passwords</h2>
<p>The password:
<ul>
<li>Must be at least <b>$sso_min_password_length characters</b> long.
<li>Must contain <b>at least</b> one number, one upper-case letter, one lower-case letter, and one punctuation character.
<li>Must <b>not be in a dictionary</b> of the most common 100 passwords (eg. "password" or "letmein")
<li>May not consist of more than 6 of the <b>same character</b> in any position (eg. "a1a2a3a4a5a6" would not be allowed).
<li>May not contain <b>sequences</b> of 3 or more characters going up or down (eg. "abc", "456", "ZYX", "765").
<li>May not contain <b>repeats</b> of 3 or more characters in a row (eg. "aaa" or "666" would not be allowed).
<li>May <b>not end with a number</b> (so you can't just add numbers to a word, like "gorilla489")
<li>May not contain <b>part of your email address</b> (so if your name is "barbara@gmail.com" the password can't be "barb9642")
</ul>

<p>Note: Leading and trailing spaces are discarded.
<p><a href="$PHP_SELF">Cancel password change</a>
</div>
<input type="hidden"    name="action" value="$SSO_CHANGE_PASSWORD">
</form>
EOD;
  } // end of SSO_ShowNewPasswordForm

function SSO_ShowLoginInfo ($extra = '')
  {
  global $SSO_LOGON, $SSO_LOGON_FORM, $SSO_LOGOFF, $SSO_FORGOT_PASSWORD, $SSO_AUTHENTICATOR, $SSO_SHOW_SESSIONS;
  global $SSO_UserDetails, $SSO_loginInfo;
  global $action, $control;
  global $PHP_SELF;
  global $FORM_STYLE;

  // set up the style sheet for displaying forms like the login form
  echo ($FORM_STYLE);

  // name of our system
  $sso_name             = htmlspecialchars ($control ['sso_name']);

  // messages of the day
  $sso_motd             = $control ['sso_motd'];
  $sso_motd_logged_on   = $control ['sso_motd_logged_on'];
  $sso_motd_logged_off  = $control ['sso_motd_logged_off'];

  // MOTD - always shown
  if ($sso_motd && $sso_motd != "NONE")
    echo "<div class = \"motd_style\">$sso_motd</div>\n";

  // MOTD - conditional
  if ($SSO_UserDetails) // logged on
    {
    if ($sso_motd_logged_on && $sso_motd_logged_on != "NONE")
      echo "<div class = \"motd_style\">$sso_motd_logged_on</div>\n";
    }
  else  // logged off
    {
    if ($sso_motd_logged_off && $sso_motd_logged_off != "NONE")
      echo "<div class = \"motd_style\">$sso_motd_logged_off</div>\n";
    }

  // show errors
  foreach ($SSO_loginInfo ['errors'] as $error)
      ShowWarning ($error);

  // show login form if wanted
  if ($SSO_loginInfo ['show_login'])
    SSO_ShowLoginForm ();
  // or the authenticator form
  elseif ($SSO_loginInfo ['show_authenticator'])
    SSO_ShowAuthenticatorForm ();
  elseif ($SSO_loginInfo ['show_forgotten_password'])
    SSO_Show_Forgot_Password_Form ();
  elseif ($SSO_loginInfo ['show_new_password'])
    SSO_ShowNewPasswordForm ();
  elseif ($SSO_loginInfo ['show_name_change'])
    SSO_ShowNameChangeForm ();
  elseif ($SSO_loginInfo ['show_sessions'])
    SSO_Handle_Show_Sessions ();

  // show successes
  foreach ($SSO_loginInfo ['info'] as $info)
      ShowInfo ($info);

if (!$SSO_loginInfo ['show_sessions'] && !$SSO_loginInfo ['show_new_password'])
  {

echo '<div class = "info_style">';

  // show that we are logged on
  if ($SSO_UserDetails)
    {
    echo ("You are logged on as: <b>" . htmlspecialchars ($SSO_UserDetails ['username']) . "</b> ");
    // putting up the form won't work if we already have arguments on the URI
    if (count ($_GET) == 0)
      echo ("<a href=\"$PHP_SELF?action=$SSO_SHOW_SESSIONS\" title=\"Log off, change password, or change user name\">
              <img src=\"/images/gear.svg\" style=\"vertical-align:bottom;\" ></a>\n");
    }
  // or show the logon link, unless we have already displayed the logon form or another form
  elseif (!$SSO_loginInfo ['show_login'] &&
          !$SSO_loginInfo ['show_authenticator'] &&
          !$SSO_loginInfo ['show_forgotten_password'] &&
          !$SSO_loginInfo ['show_new_password'] )
    hLink ("Log on", $PHP_SELF, "action=sso_logon_form");  //  to $sso_name

  echo ($extra);

  echo "</div><br>\n";
  } // end of not showing the sessions

  return $SSO_UserDetails;    // will be false if login failed
  } // end of SSO_ShowLoginInfo

function SSO_Handle_Authenticator ()
  {
  global $SSO_USER_TABLE, $SSO_FAILED_LOGINS_TABLE, $SSO_TOKENS_TABLE, $SSO_AUTHENTICATORS_TABLE,
         $SSO_BANNED_IPS_TABLE, $SSO_SUSPECT_IPS_TABLE, $SSO_AUDIT_TABLE;

  global $VALID_NUMBER, $VALID_FLOAT, $VALID_DATE, $VALID_ACTION, $VALID_BOOLEAN, $VALID_SQL_ID,
         $VALID_COLOUR, $VALID_REGISTRATION_NUMBER;
  global $SSO_UserDetails, $SSO_loginInfo;
  global $PHP_SELF, $remote_ip;

  if ($SSO_UserDetails)
    {
    $SSO_loginInfo ['info'] [] = "You are already logged on.";
    return; // give up
    }

  $sso_id  = getP ('sso_id', 8, $VALID_NUMBER);
  $token  =  getP ('token', 50, '^[a-zA-Z0-9]+$');

  // check user ID and token are OK
  $authRow = dbQueryOneParam ("SELECT COUNT(*) AS counter FROM $SSO_AUTHENTICATORS_TABLE " .
                              "WHERE sso_id = ? ".
                              "AND   Token = ? " .
                              "AND   NOW() < DATE_ADD(Date_Token_Sent, INTERVAL 5 MINUTE) ",
                              array ('is', &$sso_id, &$token));

  if ($authRow ['counter'] == 0)
   {
   $SSO_loginInfo ['errors'] [] = "Authenticator request out of date or invalid";
   $SSO_loginInfo ['show_authenticator'] = true;  // show the form again
   $SSO_UserDetails = false;
   SSO_Login_Failure ('(unknown)', '(unknown)', $remote_ip);
   return;
   }

  $log_on_error = HandleAuthenticator ($sso_id, $SSO_AUTHENTICATORS_TABLE, 'sso_id');
  if ($log_on_error)
   {
   // find email address for the failure log
   $row = dbQueryOneParam ("SELECT email_address from $SSO_USER_TABLE WHERE sso_id = ?",
                           array ('i', &$sso_id));
   $SSO_loginInfo ['errors'] [] = $log_on_error;
   $SSO_loginInfo ['show_authenticator'] = true;  // show the form again
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
  global $SSO_UserDetails, $SSO_loginInfo;
  global $remote_ip;

  // find the token on their cookie
  // do NOT get POST variable or we switch users when editing the user table
  if (isset ($_COOKIE [$SSO_COOKIE_NAME]))
    $cookie = json_decode( $_COOKIE[$SSO_COOKIE_NAME] );
  else
    return; // no cookie, can't be logged on

  // fail if it isn't a JSON object
  if (gettype ($cookie) != 'object')
    return;

  $token = $cookie->token;
  $tokenExpiry = $cookie->expiry;

  $tokenRow = dbQueryOneParam ("SELECT sso_id FROM $SSO_TOKENS_TABLE WHERE token = ? "  .
                                "AND date_expires >= NOW()",
                                array ('s', &$token) );

  if (!$tokenRow)
    return;   // token not on file

  $sso_id = $tokenRow ['sso_id'];

  // grab user details
  $SSO_UserDetails = dbQueryOneParam ("SELECT * from $SSO_USER_TABLE WHERE sso_id = ?",
                                      array ('i', &$sso_id));

  // see if they have been blocked since they logged in
  if ($SSO_UserDetails ['blocked'])
    {
    $SSO_loginInfo ['errors'] [] = "You are not permitted to log on (banned)";
    $SSO_UserDetails = false;
    return; // give up
    }

  // check if they carried a good token to a bad IP
  if ($SSO_UserDetails ['required_ip'])
    if ($SSO_UserDetails ['required_ip'] != $remote_ip)
      {
      $SSO_loginInfo ['errors'] [] = "You cannot log on from that IP address";
      $SSO_UserDetails = false;
      return;  // don't generate a cookie
      }

  // in case they want to log off
  $SSO_UserDetails ['token'] = $token;
  $SSO_UserDetails ['token_expiry'] = $tokenExpiry;

  } // end of SSO_See_If_Logged_On

function SSO_Handle_Logoff ()
  {
  global $SSO_USER_TABLE, $SSO_FAILED_LOGINS_TABLE, $SSO_TOKENS_TABLE, $SSO_AUTHENTICATORS_TABLE,
         $SSO_BANNED_IPS_TABLE, $SSO_SUSPECT_IPS_TABLE, $SSO_AUDIT_TABLE;

  global $SSO_UserDetails, $SSO_loginInfo;
  global $SSO_AUDIT_LOGON, $SSO_AUDIT_LOGOFF, $SSO_AUDIT_LOGOFF_ALL, $SSO_AUDIT_LOGOFF_OTHERS,
         $SSO_AUDIT_REQUEST_PASSWORD_RESET, $SSO_AUDIT_CHANGED_PASSWORD, $SSO_AUDIT_CHANGED_EMAIL;

  global $SSO_LOGON, $SSO_LOGON_FORM, $SSO_LOGOFF, $SSO_LOGOFF_ALL, $SSO_LOGOFF_OTHERS,
         $SSO_FORGOT_PASSWORD, $SSO_REQUEST_PASSWORD_RESET, $SSO_PASSWORD_RESET, $SSO_AUTHENTICATOR,
         $SSO_SHOW_SESSIONS, $SSO_CHANGE_PASSWORD, $SSO_SHOW_CHANGE_PASSWORD;

  global $action;

  if (!$SSO_UserDetails)
    {
    $SSO_loginInfo ['info'] [] = "You are already logged off.";
    return; // give up
    }

  $sso_id = $SSO_UserDetails ['sso_id'];
  $token  = $SSO_UserDetails ['token'];

  // delete token from tokens table
  if ($action == $SSO_LOGOFF_ALL)
    {
    dbUpdateParam ("DELETE FROM $SSO_TOKENS_TABLE WHERE sso_id = ?",
                  array ('i', &$sso_id));

    $SSO_loginInfo ['info'] [] = "Logged off from all devices.";
    // audit that they logged off
    SSO_Audit ($SSO_AUDIT_LOGOFF_ALL, $sso_id);
    // invalidate their login details
    $SSO_UserDetails = false;
    }
  else if ($action == $SSO_LOGOFF_OTHERS)
    {
    dbUpdateParam ("DELETE FROM $SSO_TOKENS_TABLE WHERE sso_id = ? AND token <> ?",
                  array ('is', &$sso_id, &$token));

    $SSO_loginInfo ['info'] [] = "Logged off from all other devices (except this one).";
    // audit that they logged off
    SSO_Audit ($SSO_AUDIT_LOGOFF_OTHERS, $sso_id);
    }
  else
    {
    dbUpdateParam ("DELETE FROM $SSO_TOKENS_TABLE WHERE sso_id = ? AND token = ?",
                  array ('is', &$sso_id, &$token));
    $SSO_loginInfo ['info'] [] = "Logged off from this device.";
    // audit that they logged off
    SSO_Audit ($SSO_AUDIT_LOGOFF, $sso_id);
    // invalidate their login details
    $SSO_UserDetails = false;
    }

  } // end of SSO_Handle_Logoff

function SSO_Show_Forgot_Password_Form ()
  {
  global $SSO_LOGON, $SSO_LOGON_FORM, $SSO_LOGOFF, $SSO_FORGOT_PASSWORD, $SSO_REQUEST_PASSWORD_RESET,
         $SSO_AUTHENTICATOR, $SSO_SHOW_SESSIONS;
  global $PHP_SELF;
  global $SSO_UserDetails, $SSO_loginInfo;
  global $email_address, $control;

  $sso_name = htmlspecialchars ($control ['sso_name']);

  if ($SSO_UserDetails)
    {
    $SSO_loginInfo ['info'] [] = "You are already logged on - no password reset required.";
    return; // give up
    }

// show the form in a nice blue box
echo <<< EOD
<form METHOD="post" ACTION="$PHP_SELF">
<div class="form_style">
<h2>Password reset request for $sso_name</h2>
<table>
<tr>
<th align=right>Your email address:</th>
<td><input type="text"      name="email_address" size=50 maxlength=255
    value="$email_address" autofocus style="width:95%;" required></td>
</tr>
<tr><td></td>
<td><input type="submit"    value="Reset password">
<p>Click the button <b>once</b> and then please <b>be patient</b> while a reset email is generated.
<p>A password reset message will be emailed to you. Please check for that
email and follow the link in it, to have your password reset.
</td>
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
  global $SSO_UserDetails, $SSO_loginInfo;
  global $remote_ip;
  global $control;
  global $MAX_EMAIL_GUESSES;

  global $SSO_USER_TABLE, $SSO_FAILED_LOGINS_TABLE, $SSO_TOKENS_TABLE, $SSO_AUTHENTICATORS_TABLE,
         $SSO_BANNED_IPS_TABLE, $SSO_SUSPECT_IPS_TABLE, $SSO_AUDIT_TABLE, $SSO_EMAIL_GUESS_TABLE;

  global $SSO_AUDIT_LOGON, $SSO_AUDIT_LOGOFF, $SSO_AUDIT_LOGOFF_ALL, $SSO_AUDIT_REQUEST_PASSWORD_RESET,
         $SSO_AUDIT_CHANGED_PASSWORD, $SSO_AUDIT_CHANGED_EMAIL;


  if ($SSO_UserDetails)
    {
    $SSO_loginInfo ['info'] [] = "You are already logged on - no password reset required.";
    return; // give up
    }

  $banned_row = dbQueryOneParam ("SELECT * FROM $SSO_BANNED_IPS_TABLE WHERE ip_address  = ?",
                                array ('s', &$remote_ip));
  if ($banned_row)
    {
    $SSO_loginInfo ['errors'] [] = "That TCP/IP address is not permitted to log on";
    return; // give up
    } // end of a match

  // get email_address
  $email_address = getP ('email_address', 255);

  if (!$email_address)
    {
    $SSO_loginInfo ['errors'] [] = "Email address must be given";
    return;
    } // end of no email_address

  if (!validateEmail ($email_address))
    {
    $SSO_loginInfo ['errors'] [] = "That email address is not in a valid format\n" .
           "It should be something like: yourName@yourProvider.com.au\n" .
           "Do not use quotes or '<' and '>' symbols.";
    $SSO_loginInfo ['show_forgotten_password'] = true;  // show the form again

    return;
    } // end of bad email address


  // clear old email guess failure tracking records (so they can reset by waiting a day)
  dbUpdate ("DELETE FROM $SSO_EMAIL_GUESS_TABLE
             WHERE date_failed < DATE_ADD(NOW(), INTERVAL -1 DAY)");

  $failureRow = dbQueryOneParam ("SELECT * FROM $SSO_EMAIL_GUESS_TABLE WHERE failure_ip = ?",
                                  array ('s', &$remote_ip));
  if ($failureRow && $failureRow ['count'] >= $MAX_EMAIL_GUESSES)
    {
    $SSO_loginInfo ['errors'] [] = "Too many attempts to guess your email address.\n" .
                                "You can try again tomorrow if necessary.";
    return;
    }

  if ($failureRow && $failureRow ['password_sent'] == 1)
    {
    $SSO_loginInfo ['errors'] [] = "A password has already been emailed to this IP address in the last 24 hours.\n" .
                                "You can try again later if necessary.";
    return;
    }

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
    $SSO_loginInfo ['errors'] [] = "That email address is not on file";
    $SSO_UserDetails = false;  // wrong email
    SSO_Login_Failure ($email_address, '(unknown)', $remote_ip);
    return;
    }

   $todayRow = dbQueryOne ("SELECT CURDATE() as today");  // no user input

  // don't let them keep asking for it
  if ($SSO_UserDetails ['password_sent_date'] == $todayRow ['today'])
    {
    $SSO_loginInfo ['errors'] [] = "You have already been sent your password today.\n" .
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

  dbUpdateParam ($query, array ('si', &$md5_password, &$sso_id )) ;

  $sso_name = $control ['sso_name'];
  $sso_url  = $control ['sso_url'];

  // send mail message

  $mailresult = mail ($email_address,
        "$sso_name password",
        "Hi $email_address,\n\n" .
        "Someone (possibly you) requested that your $sso_name password be reset.\n\n" .
        "To reset your password, please click on:\n\n" .
        "  $sso_url$PHP_SELF?action=$SSO_PASSWORD_RESET&id=$sso_id&hash=$md5_password\n\n" .
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

  $SSO_loginInfo ['info'] [] = "Your password reset request is now being emailed to: $email_address";

  // remember when we sent the password
  dbUpdateParam ("UPDATE $SSO_USER_TABLE SET password_sent_date = NOW() WHERE sso_id = ?",
                  array ('i', &$sso_id));

  // remember we sent one for this IP
  if ($failureRow)
    dbUpdateParam ("UPDATE $SSO_EMAIL_GUESS_TABLE SET count = 0, date_failed = NOW(), password_sent = 1
                   WHERE failure_ip = ?", array ('s', &$remote_ip));
  else
    dbUpdateParam ("INSERT INTO $SSO_EMAIL_GUESS_TABLE  (count, date_failed, failure_ip, password_sent) VALUES
                   (0, NOW(), ?, 1) ", array ('s', &$remote_ip));

  // audit password reset requests
  SSO_Audit ($SSO_AUDIT_REQUEST_PASSWORD_RESET, $sso_id);

  $SSO_UserDetails = false;

  } // end of SSO_Handle_Password_Reset_Request

function SSO_Handle_Password_Reset ()
  {
  global $SSO_USER_TABLE, $SSO_FAILED_LOGINS_TABLE, $SSO_TOKENS_TABLE, $SSO_AUTHENTICATORS_TABLE,
         $SSO_BANNED_IPS_TABLE, $SSO_SUSPECT_IPS_TABLE, $SSO_AUDIT_TABLE, $SSO_EMAIL_GUESS_TABLE;

  global $SSO_UserDetails, $SSO_loginInfo;

  if ($SSO_UserDetails)
    {
    $SSO_loginInfo ['info'] [] = "You are already logged on - no password reset required.";
    return; // give up
    }

  $hash             = getG ('hash', 32);
  $id               = getG ('id', 8);

  if (strlen ($hash) != 32
      || !strlen ($id)
      || !preg_match ("/^[0-9A-Fa-f]+$/", $hash)
      || !preg_match ("/^[0-9]+$/", $id))
      {
      $SSO_loginInfo ['errors'] [] = "Password reset URL invalid format";
      return;
      }

  $query = "SELECT * FROM $SSO_USER_TABLE WHERE sso_id = ?
            AND password_reset_hash = ? AND password_sent_date = DATE(NOW())";

  $row = dbQueryOneParam ($query, array ('is', &$id, &$hash)) ;

  if (!$row)
     {
     $SSO_loginInfo ['errors'] [] = "That password reset request is not on file or has expired";
     return;
     }

  $SSO_loginInfo ['show_new_password'] = true;
  $SSO_loginInfo ['new_password_hash'] = $hash;
  $SSO_loginInfo ['sso_id'] = $id;

  } // end of SSO_Handle_Password_Reset

function SSO_Handle_Change_Password ()
  {
  global $SSO_USER_TABLE, $SSO_FAILED_LOGINS_TABLE, $SSO_TOKENS_TABLE, $SSO_AUTHENTICATORS_TABLE,
         $SSO_BANNED_IPS_TABLE, $SSO_SUSPECT_IPS_TABLE, $SSO_AUDIT_TABLE, $SSO_EMAIL_GUESS_TABLE;

  global $SSO_AUDIT_LOGON, $SSO_AUDIT_LOGOFF, $SSO_AUDIT_LOGOFF_ALL, $SSO_AUDIT_REQUEST_PASSWORD_RESET,
         $SSO_AUDIT_CHANGED_PASSWORD, $SSO_AUDIT_CHANGED_EMAIL;

  global $SSO_UserDetails, $SSO_loginInfo;
  global $control;

  $hash             = getP ('hash', 32);
  $sso_id           = getP ('sso_id', 8);
  $oldpassword      = getP ('old_password', 50);
  $newpassword      = getP ('new_password', 50);
  $confirmpassword  = getP ('confirm_password', 50);

  $sso_min_password_length = $control ['sso_min_password_length'];

  if ($SSO_UserDetails)
    {
    $hash = false;
    $sso_id = $SSO_UserDetails ['sso_id'];
    $email_address = $SSO_UserDetails ['email_address'];
    }
  else
    {   // must have a hash
    if (strlen ($hash) != 32
        || !strlen ($sso_id)
        || !preg_match ("/^[0-9A-Fa-f]+$/", $hash)
        || !preg_match ("/^[0-9]+$/", $sso_id))
        {
        $SSO_loginInfo ['errors'] [] = "Password change hash invalid format";
        return;
        }
    } // end of not logged on

  // get the user from the hash and ID
  if ($hash)
    {
    $query = "SELECT * FROM $SSO_USER_TABLE WHERE sso_id = ?
              AND password_reset_hash = ? AND password_sent_date = DATE(NOW())";

    $row = dbQueryOneParam ($query, array ('is', &$sso_id, &$hash)) ;

    if (!$row)
       {
       $SSO_loginInfo ['errors'] [] = "That password reset request is not on file or has expired";
       return;
       }
     $email_address = $row ['email_address'];
     } // end of having a hash and therefore finding the user record
   else
    {
     // check password with bcrypt
      if (PasswordCompat\binary\check() &&
          PasswordCompat\binary\_strlen ($SSO_UserDetails ['password']) > 32)
        {
        if (!password_verify ($oldpassword, $SSO_UserDetails ['password']))
          {
          $SSO_loginInfo ['errors'] [] = "Old password is not correct";
          $SSO_loginInfo ['sso_id'] = $sso_id;
          $SSO_loginInfo ['new_password_hash'] = $hash;
          $SSO_loginInfo ['show_new_password'] = true;
          return;
          } // end of wrong password
        } // end of password > 32 bytes
      else
        {
        $SSO_loginInfo ['errors'] [] = "Authentication system not set up correctly";
        $SSO_UserDetails = false;    // discard user information
        return;
        } // end of <= 32 bytes
    } // end of user being logged on, and therefore having to check the old password

  // check confirmation agrees
  if ($newpassword != $confirmpassword)
    {
    $SSO_loginInfo ['errors'] [] = "New password and confirmation password do not match";
    $SSO_loginInfo ['sso_id'] = $sso_id;
    $SSO_loginInfo ['new_password_hash'] = $hash;
    $SSO_loginInfo ['show_new_password'] = true;
    return;
    }

  // check reasonable password given, such as: foobar12AB.,
  $validation = passwordCheck ($newpassword, $email_address, 'email address', $sso_min_password_length);
  if ($validation)
    {
    $SSO_loginInfo ['errors'] [] = $validation;
    $SSO_loginInfo ['new_password_hash'] = $hash;
    $SSO_loginInfo ['sso_id'] = $sso_id;
    $SSO_loginInfo ['show_new_password'] = true;
    return;
    }

  // seems to have passed the tests, let's change the password

  $md5_password = password_hash($newpassword, PASSWORD_BCRYPT, array("cost" => 13));

  $query = "UPDATE $SSO_USER_TABLE SET password = ? WHERE sso_id = ?";

  $count = dbUpdateParam ($query, array ('si', &$md5_password, &$sso_id )) ;

  if ($count > 0)
    {
    $SSO_loginInfo ['info'] [] = 'Password changed';
    sso_audit ($SSO_AUDIT_CHANGED_PASSWORD, $sso_id);
    }
  else
    $SSO_loginInfo ['info'] [] = 'Password not changed';

  // that old reset hash is no longer valid
  dbUpdateParam ("UPDATE $SSO_USER_TABLE SET password_reset_hash = NULL,
                  password_sent_date = NULL WHERE sso_id = ?",
                    array ('i', &$sso_id ));

  // may as well log them on once they have reset their password
  if (!$SSO_UserDetails)
      SSO_Complete_Logon ($sso_id);

  } // end of SSO_Handle_Change_Password

// new username validation - made into a separate function so forum user creation (etc.) can call it
function SSO_Validate_UserName (&$new_name, $sso_id)
  {
  global $SSO_USER_TABLE, $SSO_FAILED_LOGINS_TABLE, $SSO_TOKENS_TABLE, $SSO_AUTHENTICATORS_TABLE,
         $SSO_BANNED_IPS_TABLE, $SSO_SUSPECT_IPS_TABLE, $SSO_AUDIT_TABLE, $SSO_EMAIL_GUESS_TABLE;
  global $control;

  $sso_max_username_length = $control ['sso_max_username_length'];

  $new_name = preg_replace ('/\s+/', ' ', $new_name);  // get rid of weird multiple spaces
  if (strlen ($new_name) < 4)
    return "New name is too short (must be 4 or more characters).";

  if (strlen ($new_name) > $sso_max_username_length)
    return "New name is too long (maximum of $sso_max_username_length characters).";

  // count actual letters
  preg_match_all('`[A-Za-z]`', $new_name, $letters);
  $letter_counts = count($letters[0]);

  // we don't want them making a name like "&&--.."
  if ($letter_counts < 4)
    return "Name must contain at least 4 letters (A-Z).";

  // count non letters
  preg_match_all('`[^A-Za-z ]`', $new_name, $letters);
  $letter_counts = count($letters[0]);

  // we don't want them making a name like "Fred Smith&&&&&&"
  if ($letter_counts > 4)
    return "Name contains too much punctuation.";

  // name should be letters, single quote (O'Brien), ampersand (Nick & Helen) or dash (Gibly-Smith)
  if (!preg_match ("`^[A-Za-z '&\.\-]+$`", $new_name))
    return "New name contains symbols that are not permitted. Use letters, single quotes, spaces, ampersand or dash";

  // capitalize words - break new name into individual words
  preg_match_all('`[^ ]+`', $new_name, $words);

  $specialWords = array (
    'am'  => true,  // Member of the Order of Australia
    'ac'  => true,  // Companion of the Order of Australia
    'ao'  => true,  // Officer of the Order of Australia
    'ak'  => true,  // Knight of the Order of Australia
    'ad'  => true,  // Dame of the Order of Australia
    'oam' => true,  // Medal of the Order of Australia
    );

  $fixedName = array ();  // the new name
  // check each word
  foreach ($words [0] as $word)
    {
    $word = strtolower ($word);  // start by forcing lower-case
    if (isset ($specialWords [$word]))   // OAM, AM etc.
      $word = strtoupper ($word);
    elseif ($word == 'and')     // leave "and" alone
      { }  // leave alone
    else
      $word = ucfirst ($word);  // make first character upper-case
    $fixedName [] = $word;      // add back into fixed name
    }

  // put name back together at spaces
  $new_name = implode (' ', $fixedName);

  // fix names like O'Brien to capitalize the B
  $new_name = preg_replace_callback("`['\-][a-z]`",
              function ($matches)
              {
              return strtoupper($matches[0]);
              },
        $new_name);

  // now that we have got our nice new name, check it isn't already on file by someone else

  $row = dbQueryOneParam ("SELECT * FROM $SSO_USER_TABLE WHERE username = ? AND sso_id <> ?",
                          array ('si', &$new_name, &$sso_id ));

  // we don't want them making a name like "&&--.."
  if ($row)
    return "The name \"$new_name\" is in use by someone else. Names are required to be unique.";

  return false;
  } // end of SSO_Validate_UserName

function SSO_Handle_Change_Name ()
  {
  global $SSO_USER_TABLE, $SSO_FAILED_LOGINS_TABLE, $SSO_TOKENS_TABLE, $SSO_AUTHENTICATORS_TABLE,
         $SSO_BANNED_IPS_TABLE, $SSO_SUSPECT_IPS_TABLE, $SSO_AUDIT_TABLE, $SSO_EMAIL_GUESS_TABLE;

  global $SSO_AUDIT_LOGON, $SSO_AUDIT_LOGOFF, $SSO_AUDIT_LOGOFF_ALL, $SSO_AUDIT_REQUEST_PASSWORD_RESET,
         $SSO_AUDIT_CHANGED_PASSWORD, $SSO_AUDIT_CHANGED_EMAIL, $SSO_AUDIT_CHANGED_NAME;

  global $SSO_UserDetails, $SSO_loginInfo;
  global $control;

  $new_name      = getP ('new_name', 60);
  $sso_id = $SSO_UserDetails ['sso_id'];
  $sso_max_username_length = $control ['sso_max_username_length'];

  if (!$SSO_UserDetails)
    {
    $SSO_loginInfo ['errors'] [] = "You are not logged on.";
    return; // give up
    }

  // validate name, capitalize it, get rid of multiple spaces, etc.
  $error = SSO_Validate_UserName ($new_name, $sso_id);

  if ($error)
    {
    $SSO_loginInfo ['errors'] [] = $error;
    $SSO_loginInfo ['show_name_change'] = true;
    return; // give up
    }

  $query = "UPDATE $SSO_USER_TABLE SET username = ? WHERE sso_id = ?";

  $count = dbUpdateParam ($query, array ('si', &$new_name, &$sso_id )) ;

  $SSO_UserDetails ['username'] = $new_name;

  if ($count > 0)
    {
    $SSO_loginInfo ['info'] [] = "Name changed to: $new_name";
    sso_audit ($SSO_AUDIT_CHANGED_NAME, $sso_id);
    }
  else
    $SSO_loginInfo ['info'] [] = 'Name not changed';

  } // end of SSO_Handle_Change_Name

function SSO_Handle_Show_Sessions ()
  {
  global $SSO_USER_TABLE, $SSO_FAILED_LOGINS_TABLE, $SSO_TOKENS_TABLE, $SSO_AUTHENTICATORS_TABLE,
         $SSO_BANNED_IPS_TABLE, $SSO_SUSPECT_IPS_TABLE, $SSO_AUDIT_TABLE, $SSO_EMAIL_GUESS_TABLE;

  global $SSO_LOGON, $SSO_LOGON_FORM, $SSO_LOGOFF, $SSO_LOGOFF_ALL, $SSO_LOGOFF_OTHERS,
         $SSO_FORGOT_PASSWORD, $SSO_REQUEST_PASSWORD_RESET, $SSO_PASSWORD_RESET, $SSO_AUTHENTICATOR,
         $SSO_SHOW_SESSIONS, $SSO_CHANGE_PASSWORD, $SSO_SHOW_CHANGE_PASSWORD,
         $SSO_SHOW_CHANGE_NAME, $SSO_CHANGE_NAME;
  global $PHP_SELF;
  global $SSO_UserDetails, $SSO_loginInfo;
  global $control;

  if (!$SSO_UserDetails)
    {
    $SSO_loginInfo ['info'] [] = "You are not logged on.";
    return; // give up
    }
  $sso_id = $SSO_UserDetails ['sso_id'];
  $token = $SSO_UserDetails ['token'];
  $count_logins = $SSO_UserDetails ['count_logins'];
  $count_failed_logins = $SSO_UserDetails ['count_failed_logins'];


  $sso_name = htmlspecialchars ($control ['sso_name']);
  $username = htmlspecialchars ($SSO_UserDetails ['username']);
  $email_address = htmlspecialchars ($SSO_UserDetails ['email_address']);

  $row = dbQueryOneParam ("SELECT COUNT(*) AS counter FROM $SSO_TOKENS_TABLE WHERE sso_id = ?",
                      array ('i', &$sso_id ));
  $counter = $row ['counter'];

  // find when this token logged on
  $row = dbQueryOneParam ("SELECT DATE_FORMAT(date_logged_on, '%a %D %M %Y at %l:%i %p') AS date_logged_on_formatted
                          FROM $SSO_TOKENS_TABLE WHERE token = ?",
                          array ('s', &$token ));

  $date_logged_on_formatted = htmlspecialchars ($row ['date_logged_on_formatted']);

  // get a formatted date when we failed to logon
  $row = dbQueryOneParam ("SELECT DATE_FORMAT(date_last_failed_login, '%a %D %M %Y at %l:%i %p')
                          AS date_last_failed_login_formatted FROM $SSO_USER_TABLE WHERE sso_id = ?",
                          array ('i', &$sso_id ));

  $date_last_failed_login_formatted = htmlspecialchars ($row ['date_last_failed_login_formatted']);

  if ($counter == 1)
    $s1 = '';
  else
    $s1 = 's';

  if ($count_logins == 1)
    $s2 = '';
  else
    $s2 = 's';

  if ($count_failed_logins == 1)
    $s3 = '';
  else
    $s3 = 's';

  if ($count_failed_logins > 0)
    $failedInfo = "<li>You have <b>$count_failed_logins</b> failed login$s3, the most recent at <b>$date_last_failed_login_formatted</b>";
  else
    $failedInfo = "";

$logonExpiry = date ('D jS M Y \a\t g:i A', $SSO_UserDetails ['token_expiry']);

// show in a nice blue box
echo <<< EOD
<div class="form_style">
<h2>User management for $sso_name</h2>
<h3>Information</h3>
<ul>
<li>You are logged on as: <b>$username</b>
<li>You are logged on at <b>$counter</b> device$s1. (A device being a computer, laptop, tablet, phone etc.)
<li>Your email address is: <b>$email_address</b>
<li>You have been logged on here since: <b>$date_logged_on_formatted</b>
<li>Your session expires here on: <b>$logonExpiry </b>
<li>You have logged on <b>$count_logins</b> time$s2
$failedInfo
</ul>
<h3>Actions</h3>
<ul>
EOD;

if ($counter > 1)
  echo <<< EOD
  <li><a href="$PHP_SELF?action=$SSO_LOGOFF">Log off <b>this</b> device</a>
  <li><a href="$PHP_SELF?action=$SSO_LOGOFF_OTHERS">Log off all <b>other</b> devices (except this one)</a>
  <li><a href="$PHP_SELF?action=$SSO_LOGOFF_ALL">Log off <b>all</b> your devices ($counter of them, including this one)</a>
EOD;
else
  echo <<< EOD
  <li><a href="$PHP_SELF?action=$SSO_LOGOFF">Log off</a>
EOD;

echo <<< EOD
<li><a href="$PHP_SELF?action=$SSO_SHOW_CHANGE_PASSWORD">Change your password</a>
<li><a href="$PHP_SELF?action=$SSO_SHOW_CHANGE_NAME">Change your user name from <b>$username</b> to something else.</a>
</ul>
<a href="$PHP_SELF">Close</a>
</div>
EOD;


  } // end of SSO_Handle_Show_Sessions

// for things like the forum where we want to get rid of someone
function SSO_Delete_User ($sso_id)
  {
  global $SSO_USER_TABLE, $SSO_FAILED_LOGINS_TABLE, $SSO_TOKENS_TABLE, $SSO_AUTHENTICATORS_TABLE,
         $SSO_BANNED_IPS_TABLE, $SSO_SUSPECT_IPS_TABLE, $SSO_AUDIT_TABLE;

  // get rid of their tokens first
  dbUpdateParam ("DELETE FROM $SSO_TOKENS_TABLE WHERE sso_id = ?",
                    array ('i', &$sso_id ));

  // get rid of the user
  dbUpdateParam ("DELETE FROM $SSO_USER_TABLE WHERE sso_id = ?",
                    array ('i', &$sso_id ));

  } // SSO_Delete_User

// *****************************************************************
//      SSO_Authenticate - call for all authentication actions
// *****************************************************************

function SSO_Authenticate ()
  {
  global $DATABASE_SERVER, $GENERAL_DATABASE_USER, $GENERAL_DATABASE_NAME, $GENERAL_DATABASE_PASSWORD;
  global $SSO_LOGON, $SSO_LOGON_FORM, $SSO_LOGOFF, $SSO_LOGOFF_ALL, $SSO_LOGOFF_OTHERS,
         $SSO_FORGOT_PASSWORD, $SSO_REQUEST_PASSWORD_RESET, $SSO_PASSWORD_RESET, $SSO_AUTHENTICATOR,
         $SSO_SHOW_SESSIONS, $SSO_CHANGE_PASSWORD, $SSO_SHOW_CHANGE_PASSWORD,
         $SSO_SHOW_CHANGE_NAME, $SSO_CHANGE_NAME;
  global $action;
  global $PHP_SELF, $remote_ip;
  global $SSO_UserDetails, $SSO_loginInfo;

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
    case $SSO_LOGON                   : SSO_Handle_Logon ();                            break;
    case $SSO_LOGON_FORM              : $SSO_loginInfo ['show_login'] = true;           break;
    case $SSO_LOGOFF                  : SSO_Handle_Logoff ();                           break;
    case $SSO_LOGOFF_ALL              : SSO_Handle_Logoff ();                           break;
    case $SSO_LOGOFF_OTHERS           : SSO_Handle_Logoff ();                           break;
    case $SSO_FORGOT_PASSWORD         : $SSO_loginInfo ['show_forgotten_password'] = true;  break;
    case $SSO_REQUEST_PASSWORD_RESET  : SSO_Handle_Password_Reset_Request ();           break;
    case $SSO_CHANGE_PASSWORD         : SSO_Handle_Change_Password ();                  break;
    case $SSO_CHANGE_NAME             : SSO_Handle_Change_Name ();                      break;
    case $SSO_PASSWORD_RESET          : SSO_Handle_Password_Reset ();                   break;
    case $SSO_AUTHENTICATOR           : SSO_Handle_Authenticator ();                    break;
    case $SSO_SHOW_SESSIONS           : $SSO_loginInfo ['show_sessions'] = true;        break;
    case $SSO_SHOW_CHANGE_PASSWORD    : $SSO_loginInfo ['show_new_password'] = true;    break;
    case $SSO_SHOW_CHANGE_NAME        : $SSO_loginInfo ['show_name_change'] = true;     break;
    } // end of switch on $action
  } // end of SSO_Authenticate
?>
