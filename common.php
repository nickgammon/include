<?php

/*
Copyright © 2001 Nick Gammon.

  Author: Nick Gammon <nick@gammon.com.au>
  Web:    http://www.gammon.com.au/
  Date:   February 2001

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License,
  or (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
  See the GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to

  The Free Software Foundation, Inc.,
  59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.


  The Free Software Foundation maintains a web page at: http://www.fsf.org

  See the file gpl.txt for the full GNU General Public License.

  TO TAKE THE SERVER DOWN (eg. for maintenance, uploading SQL, etc.):

    Make a file: ServerDown.txt in the document root, eg.

    touch /var/www/ServerDown.txt

    If this file exists then the contents of the file ServerDown.htm
    in the document root will be echoed to all users.

    Afterwards, remove the file ServerDown.txt, eg.

    rm /var/www/ServerDown.txt

*/

// for bcrypt stuff (password_hash / password_verify)
require ($INCLUDE_DIRECTORY . "password.php");

// stop XSS injection  - get rid of stuff like <!'/*!"/*!\'/*\"/*--!><svg/onload=prompt(/OPENBUGBOUNTY/)>
//     (added to the end of the URL, which we would then echo back as part of $PHP_SELF)
// we trim the URL after letters, numbers, hyphens, underscores, slashes and dots.
$VALID_URL_REGEXP = '|^([\w/\-\.]+).*$|';
$_SERVER['PHP_SELF'] = preg_replace ($VALID_URL_REGEXP, '\1', $_SERVER['PHP_SELF']);
$_SERVER['REQUEST_URI'] = preg_replace ($VALID_URL_REGEXP, '\1', $_SERVER['REQUEST_URI']);
$_SERVER['SCRIPT_NAME'] = preg_replace ($VALID_URL_REGEXP, '\1', $_SERVER['SCRIPT_NAME']);

$MAX_LOGIN_FAILURES = 5;  // number of times you can get your password wrong for a username
$MAX_UNKNOWN_USER_FAILURES = 10;  // number of times an IP address can try a non-existent username

$MAX_FILE_SIZE = 600 * 1000 * 1000;      // bytes (600 Mb!)

// major problems - white on brown
$COLOUR_ERROR_TEXT = "#FFFFFF"; // white
$COLOUR_ERROR_BGND = "#A52A2A"; // brown

// my timing information - green on white
$COLOUR_TIMING_TEXT = "#FFFFFF";  // white
$COLOUR_TIMING_BGND = "#008000";  // green

$log_on_error = "That username/password combination is not on file";

// validation regexps for getP, getG etc.

$VALID_NUMBER  = '^[+\-]?\d+$';             // just digits with optional sign
$VALID_FLOAT   = '^[+\-]?(\d*\.)?(\d+)$';   // optional sign, optional number and decimal point, then number
$VALID_DATE    = '^[\w \-]+$';              // Expect letters, numbers spaces, hyphens
$VALID_ACTION  = '^[\w ]+$';                // actions are usually just words with underscore and maybe numbers and spaces
$VALID_BOOLEAN = '^[01]$';                  // must be 0 or 1
$VALID_SQL_ID  = '^\w+$';                   // SQL names are usually just words with underscore and maybe numbers (max 30 probably)
$VALID_COLOUR  = '^(#[0-9A-F]{1,6}|\w+)$';  // HTML colour name
$VALID_REGISTRATION_NUMBER = '^[A-Z]+\-?[0-9]+((\.[0-9]+)|[A-Z]+)?$';   // HHS registration numbers

$sql_evaluations = array ();

/*
global $VALID_NUMBER, $VALID_FLOAT, $VALID_DATE, $VALID_ACTION, $VALID_BOOLEAN, $VALID_SQL_ID,
       $VALID_COLOUR, $VALID_REGISTRATION_NUMBER;
*/

// save doing this in every file
$action      = getGPC ('action', 40, $VALID_ACTION);

DefaultColours ();

// initialize random numbers
srand ((double) microtime (true));

// die quickly if we have to take the server down for maintenance
if (is_file (str_replace ("//", "/", $_SERVER['DOCUMENT_ROOT'] . '/ServerDown.txt')))
  {
  echo file_get_contents (str_replace ("//", "/", $_SERVER['DOCUMENT_ROOT'] . '/ServerDown.htm'));
  die ();
  }

$MONTHS = array
  (
   1 => 'january',
   2 => 'february',
   3 => 'march',
   4 => 'april',
   5 => 'may',
   6 => 'june',
   7 => 'july',
   8 => 'august',
   9 => 'september',
  10 => 'october',
  11 => 'november',
  12 => 'december',
  );  // end of array

$DAYS_IN_MONTHS = array
  (
   1 => 31,
   2 => 28,
   3 => 31,
   4 => 30,
   5 => 31,
   6 => 30,
   7 => 31,
   8 => 31,
   9 => 30,
  10 => 31,
  11 => 30,
  12 => 31,
  );  // end of array

$debugInfo = array ();

// fix up magic quotes, <sigh>

if (get_magic_quotes_gpc()) {
    function stripslashes_gpc(&$value)
    {
        $value = stripslashes($value);
    }
    array_walk_recursive($_GET, 'stripslashes_gpc');
    array_walk_recursive($_POST, 'stripslashes_gpc');
    array_walk_recursive($_COOKIE, 'stripslashes_gpc');
    array_walk_recursive($_REQUEST, 'stripslashes_gpc');
}

function DefaultColours ()
  {
  global $colours;

  $colours = array
    (

    'colour_body'                 => array (    // COLOUR_BODY
      'default' => '#F5F5F5',
      'title' => 'Body of page',
      'description' => 'Colour for the body of each page.' ),

    'colour_sections_bgnd'        => array (    // COLOUR_SECTIONS_BGND
      'default' => '#DEDEDE',
      'title' => 'Sections list background',
      'description' => 'Colour to use for the background of sections (main page) listing.' ),

    'colour_read_unread_separator'           => array (    // COLOUR_READ_UNREAD_SEPARATOR
      'default' => '#008000',
      'no_text' => true,
      'title' => 'Read/unread separator line',
      'description' => 'Colour for the line separating read and unread posts.' ),

    'colour_frequent_posters_bgnd'=> array (    // COLOUR_FREQUENT_POSTERS_BGND
      'default' => '#E5E5E5',
      'title' => 'Frequent posters background',
      'description' => 'Colour for the background of frequent posters, new topics etc.' ),

    'colour_topics_heading_bgnd'  => array (    // COLOUR_TOPICS_HEADING_BGND
      'default' => '#ADD8E6',
      'title' => 'Topics heading background',
      'description' => 'Colour for the background of topics heading.' ),

    'colour_topics_bgnd'          => array (    // COLOUR_TOPICS_BGND
      'default' => '#DEDEDE',
      'title' => 'Topics list background',
      'description' => 'Colour for the background of list of topics.' ),

    'colour_lh_table'             => array (    // COLOUR_TABLE_LEFT_BGND
      'default' => '#ADD8E6',
      'title' => 'LH table',
      'description' => 'Colour for LH side of general table data (such as this page).' ),

    'colour_rh_table'             => array (    // COLOUR_TABLE_RIGHT_BGND
      'default' => '#FAF0E6',
      'title' => 'RH table',
      'description' => 'Colour for RH side of general table data (such as this page).' ),

   'colour_threads_heading_bgnd' => array (    // COLOUR_THREADS_HEADING_BGND
      'default' => '#ADD8E6',
      'title' => 'Threads heading background',
      'description' => 'Colour for the background of heading row for thread lists.' ),

    'colour_read_threads_bgnd'    => array (    // COLOUR_READ_THREADS_BGND
      'default' => '#E1E1E1',
      'title' => 'Read threads background',
      'description' => 'Colour for the background of read threads.' ),

    'colour_unread_threads_bgnd'  => array (    // COLOUR_UNREAD_THREADS_BGND
      'default' => '#BAFCBA',
      'title' => 'Unread threads background',
      'description' => 'Colour for the background of unread threads.' ),

    'colour_thread_heading_text'  => array (    // COLOUR_THREAD_HEADING_TEXT
      'default' => '#FFFFFF',
      'sample_text' => 'colour_thread_heading_text',
      'sample_bgnd' => 'colour_thread_heading_bgnd',
      'title' => 'Thread heading text',
      'description' => 'Colour for text of thread headings' ),

    'colour_thread_heading_bgnd'  => array (    // COLOUR_THREAD_HEADING_BGND
      'default' => '#CD5C5C',
      'sample_text' => 'colour_thread_heading_text',
      'sample_bgnd' => 'colour_thread_heading_bgnd',
      'title' => 'Thread heading background',
      'description' => 'Colour for background of thread headings.' ),

    'colour_lh_message'           => array (    // COLOUR_MESSAGE_LEFT_BGND
      'default' => '#ADD8E6',
      'title' => 'Post heading background',
      'description' => 'Colour to use for the background of post headings (eg. Posted By, Date, Message).' ),

    'colour_rh_message'           => array (    // COLOUR_MESSAGE_RIGHT_BGND
      'default' => '#FAF0E6',
      'title' => 'Posts background',
      'description' => 'Colour for the background of posts.' ),

    'colour_signature_line'       => array (    // COLOUR_SIGNATURE_LINE
      'default' => '#C0C0C0',
      'no_text' => true,
      'title' => 'Signature rule',
      'description' => 'Colour for the horizonal rule before signatures.' ),

    'colour_signature'            => array (    // COLOUR_SIGNATURE
      'default' => '#808080',
      'sample_text' => 'colour_signature',
      'sample_bgnd' => 'colour_rh_message',
      'title' => 'Signature',
      'description' => 'Colour to use for the text of signatures at the end of posts.' ),

    'colour_form_error'                 => array (    // COLOUR_FORM_ERROR_TEXT
      'default' => '#FF0000',
      'sample_text' => 'colour_form_error',
      'sample_bgnd' => 'colour_rh_table',
      'title' => 'Errors',
      'description' => 'Colour for errors in form submission.' ),

   'colour_text'                 => array (    // COLOUR_TEXT
      'default' => '#000000',
      'sample_text' => 'colour_text',
      'sample_bgnd' => 'colour_body',
      'title' => 'Text',
      'description' => 'Colour for most text (excluding exceptions above).' ),

    );  // end of colour table

  // set up current values
  reset ($colours);
  while (list ($colourname, $value) = each ($colours))
    $colours [$colourname] ['current'] = $value ['default'];

   } // end of DefaultColours

function GetColour ($which)
  {
  global $colours;
  return $colours [$which]['current'];
  } // end of GetColour

// common routines

function ShowError ($theerror)
  {
  global $COLOUR_ERROR_TEXT, $COLOUR_ERROR_BGND;

  echo "<table border=\"0\" cellpadding=\"5\"> <tr bgcolor=\"$COLOUR_ERROR_BGND\"> "
     . "<td><font color=\"$COLOUR_ERROR_TEXT\"><b>\n";
  echo (htmlspecialchars ($theerror, ENT_SUBSTITUTE | ENT_QUOTES | ENT_HTML5) . "\n");
  echo "</b></font></td></tr></table>\n";
  } // end of ShowError

function ShowWarningH ($theWarning)
  {
  echo ("<p style=\"color:darkred; font-weight:bold;\">" . $theWarning . "</p>\n");
  } // end of ShowWarningH

function ShowWarning ($theWarning)
  {
  ShowWarningH (nl2br_http (htmlspecialchars ($theWarning, ENT_SUBSTITUTE | ENT_QUOTES | ENT_HTML5)));
  } // end of ShowWarning

function ColourEchoH ($theMessage, $theColour, $bold = false, $italic = false)
  {
  if ($bold)
    $boldStyle = "font-weight:bold;";
  else
    $boldStyle = "";

  if ($italic)
    $italicStyle = "font-style:italic;";
  else
    $italicStyle = "";

  echo ("<span style=\"color:$theColour; $boldStyle $italicStyle\">" . $theMessage . "</span>");
  } // end of ColourEchoH

function ColourEcho ($theMessage, $theColour, $bold = false, $italic = false)
  {
  ColourEchoH (htmlspecialchars ($theMessage, ENT_SUBSTITUTE | ENT_QUOTES | ENT_HTML5), $theColour, $bold, $italic);
  } // end of ColourEcho

// Use this before database opened or if we cannot read styles
function MajorProblem ($why)
  {
  global $WEBMASTER;
  echo "<html><head><title>System error</title></head>\n";
  echo "<h3>We apologise that there has been a problem with the web server ...</h3>\n";
  ShowError ($why);
  echo "<p>Error occurred at " . strftime ("%Y-%m-%d %H:%M:%S", time()) . "</p>\n";
  echo "<p>Please notify <a href=\"mailto:$WEBMASTER\">$WEBMASTER</a> of the above message and time.</p>";
  echo "</body></html>\n";
  die ();
  } // end of MajorProblem

function GetDatabaseName (&$thename)
  {
  global $current_database_name;

  $thename = $current_database_name;
  } // end of GetDatabaseName

//----------------------------------------------------------------------------
// Open database, load control values
//----------------------------------------------------------------------------

function OpenDatabase ($dbserver, $dbuser, $dbname, $dbpassword)
  {
  global $current_database_name, $dblink;

  // save database name in case needed later
  $current_database_name = $dbname;

  $dblink = mysqli_connect($dbserver, $dbuser, $dbpassword, $dbname);

  if (mysqli_connect_errno())
    MajorProblem ("Cannot connect to server $dbserver: " . mysqli_connect_error());

  } // end of OpenDatabase

function OpenMailDatabase ()
  {
  global $DATABASE_SERVER, $MAIL_DATABASE_NAME, $MAIL_DATABASE_USER, $MAIL_DATABASE_PASSWORD;
  global $dblink;

  $dblink = mysqli_connect ($DATABASE_SERVER, $MAIL_DATABASE_USER, $MAIL_DATABASE_PASSWORD, $MAIL_DATABASE_NAME)
      or MajorProblem ("Cannot connect to server $DATABASE_SERVER: " . mysql_error ());

  } // end of OpenMailDatabase

function GetControlItems ()
  {
  global $control, $dblink;
  global $BODY_COLOUR, $HEADING_COLOUR;

  $result = mysqli_query ($dblink, "SELECT * FROM control")   // WTF?
    or MajorProblem ("Select of control table failed: " . mysqli_connect_error ());

  while ($row = dbFetch ($result))
    $control [$row ['item']] = $row ['contents'];

  dbFree ($result);

  $control ['forum_url'] = "//" . $_SERVER ["HTTP_HOST"] . "/forum";
  $HEADING_COLOUR = '#72A2C9';
  $BODY_COLOUR    = '#BBDEEA';

  if (isset ($control ['colour_table_heading']))
    $HEADING_COLOUR = $control ['colour_table_heading'];
  if (isset ($control ['colour_table_body']))
    $BODY_COLOUR = $control ['colour_table_body'];

  // Set the timezone in the current script
  date_default_timezone_set("Australia/Melbourne");

  $dst = strftime ("%z", time());

  // fix time zone
  if (preg_match ("|^([+-][0-9]{2})([0-9]{2})?$|", $dst, $matches))
    dbUpdate ("SET time_zone = '" . $matches [1] . ":" . $matches [2] . "'");  // hopefully OK

  } // end of GetControlItems

/*

I am doing sessions my own way for a number of reasons. The main one is I want to know
what is happening, and I only want session id tags to appear on pages if you have logged
in, otherwise it isn't necessary.

*/

function CheckSessionID ($noHTML = false)
  {
  global $control, $userinfo, $adminaction, $ADMIN_DIRECTORY;

  if (empty ($userinfo))
    return;   // no session for this guy

  if ($adminaction == "logoff")
    {
    LogOff ();
    $userinfo = "";   // don't use unset, it doesn't change the global version
    return;
    }

  $userinfo ["logged_on"] = true;

  if ($noHTML)
    return;

  echo "<p style=\"font-size:x-small; text-align:right;\"> Logged on as <b>"
     . $userinfo ["username"]
     . "</b>&nbsp;&nbsp;";
  hLink ("(Menu)", $ADMIN_DIRECTORY . "logon.php");
  hLink ("(Log off)", $ADMIN_DIRECTORY . "logon.php", "adminaction=logoff");
  echo $control ['admin_links'];    // extra useful links
  echo "</p>\n";

  } // end of CheckSessionID


// for the Yubikey
function crc16 ($data, $len)
 {
  $crc = 0xFFFF;
  for ($pos = 0; $pos < $len; $pos++)
    {
    $crc ^= ord ($data [$pos]);
    for ($i = 0; $i < 8; $i++)
      {
      $j = $crc & 1;
      $crc >>= 1;
      if ($j)
       $crc ^= 0x8408;
      }  // end of for each bit
    } // end of for each byte

  return $crc;
 }  // end of crc16

 function modHexDecode($token)
  {
  $TRANSKEY = "cbdefghijklnrtuv"; // translation key used to ModHex a string

  $tokLen = strlen($token);       // length of the token
  $decoded = "";                  // decoded string to be returned

  // strings must have an even length
  if ( $tokLen % 2 != 0 )
    return FALSE;

  for ($i = 0; $i < $tokLen; $i += 2 )
    {
    $high = strpos ($TRANSKEY, $token [$i]);
    $low  = strpos ($TRANSKEY, $token [$i + 1]);

    // if there's an invalid character in the encoded $token, fail here.
    if ( $high === FALSE || $low === FALSE )
            return FALSE;

    $decoded .= chr(($high << 4) | $low);
  }
  return $decoded;
} // end of modHexDecode

function HandleAuthenticator ($userid, $authenticator_table)
  {
  $authenticator  = trim ($_POST ['authenticator']);

  if (strlen ($authenticator) == 0)
    return "Authenticator required";

// -------------------
// One-time password stuff for when authenticator cannot be used
// -------------------

  $authrow = dbQueryOneParam ("SELECT * FROM one_time_password WHERE passwd = ?",
                              array ('s', &$authenticator));
  if ($authrow)
    {
    // update database so we don't use this password again
    dbUpdateParam ("DELETE FROM one_time_password WHERE passwd = ? ",
                   array ('s', &$authenticator));
    return false;
    }   // end of password found

// -------------------

  if (strlen ($authenticator) != 44)
      return "Authenticator token wrong length";
 //   return "Authenticator token wrong length, should be 44, is actually " . strlen ($authenticator);


  $decodedToken = modHexDecode($authenticator);

  if (!$decodedToken)
    return "Authenticator token incorrect format";

  $publicUID = substr ($decodedToken, 0, 6);
  $encryptedToken = substr ($decodedToken, 6);

  // the public user ID is not encrypted
  $publicUID_converted = bin2hex ($publicUID);

  // see if this authenticator is on file (for the desired user id)
  $authrow = dbQueryOneParam ("SELECT * FROM $authenticator_table WHERE User = ? AND Public_UID = ?",
                              array ('ss', &$userid, &$publicUID_converted));

  if (!$authrow)
    return "That authenticator is not on file";

  $decrypted = mcrypt_decrypt (MCRYPT_RIJNDAEL_128 ,
                                pack('H*',$authrow ['AES_key']),
                                $encryptedToken,
                                MCRYPT_MODE_CBC,
                                str_repeat("\0", 16));

   $crc = crc16 ($decrypted, 16);

   if ($crc != 0xf0b8)
     return "Authentication failed (CRC check)";

   $privateUID_converted = bin2hex (substr ($decrypted, 0, 6));

   if ($privateUID_converted != $authrow ['Secret_UID'])
     return "Authentication failed (Wrong secret user ID)";

  // the session counter is the next 2 bytes (6 to 7)
  $sessionCounter = ord ($decrypted [6]) +
                   (ord ($decrypted [7]) << 8);

//  echo "<br>sessionCounter = $sessionCounter";

  // the timestamp is the next 3 bytes (8 to 10)
  $timeStamp = ord ($decrypted [8]) +
              (ord ($decrypted [9]) <<  8) +
              (ord ($decrypted [10]) << 16);

  // now the use counter (byte 11)
  $useCounter = ord ($decrypted [11]);

//  echo "<br>useCounter = $useCounter";

  // random number is 12 and 13
  // CRC is 14 and 15 (giving a total of 16)

  $totalCount =  ($sessionCounter << 8) + $useCounter;

//  echo "<br>totalCount = $totalCount";

//  echo "<br>authrow ['Counter'] = " . $authrow ['Counter'];

  if ($totalCount <= $authrow ['Counter'])
    return "Authentication failed (token re-used)";

   $Auth_ID = $authrow ['Auth_ID'];

   // update database so we don't use this token again
   dbUpdate ("UPDATE $authenticator_table SET " .   // internally generated
            " Counter = $totalCount, " .
            " Date_Last_Used = NOW() " .
            " WHERE Auth_ID = $Auth_ID");

   return false;  // no problems
  } // end of HandleAuthenticator

// this is for an *adminstrative* logon, eg. to edit SQL tables etc.

function CheckAdminSession ()
  {
  global $userinfo, $userid, $adminaction, $username;
  global $TABLE_AUDIT_LOGON;
  global $log_on_error;

  // do NOT get POST variable or we switch users when editing the user table
  if (isset ($_GET ['session']))
    $adminsession = $_GET ['session'];
  if (empty ($adminsession) && isset ($_COOKIE ['session']))
    $adminsession = $_COOKIE ['session'];

  $userinfo = "";

  // if they are logging on, let them

  $adminaction = trim (getPG ('adminaction'));

  if ($adminaction == "logon")
    {
    $username = getP ('username', 30);
    $password = getP ('password', 50);
    $userinfo = dbQueryOneParam ("SELECT * FROM user WHERE username = ? ",
                                 array ('s', &$username) );

    // if no password on the database, logging in MUST fail
    if (!$userinfo ['password'])
      {
      $userinfo = "";  // no password
      }
    // longer password means bcrypt: method / cost / salt / password
    else if (PasswordCompat\binary\check() &&
        PasswordCompat\binary\_strlen ($userinfo ['password']) > 32)
      {
      if (!password_verify ($password, $userinfo ['password']))
        $userinfo = "";  // wrong password
      }
    else
      {
      $md5_password = md5 ($password . $userinfo ['salt']);  // salt might be empty
      if ($userinfo ['password'] != $md5_password)
        $userinfo = "";  // wrong password
      }

    if ($userinfo)
      {

     // try and work out their IP address
      $remote_ip = getIPaddress ();

      if ($userinfo ['required_ip'])
        if ($userinfo ['required_ip'] != $remote_ip)
          {
          $userinfo = "";
          Problem ("You cannot log on from the IP address $remote_ip");
          }
      $userid = $userinfo ['userid'];

      $authrow = dbQueryOne ("SELECT COUNT(*) AS counter FROM authenticator WHERE User = $userid"); // internally generated

      if ($authrow ['counter'] > 0 )
       {
       $log_on_error = HandleAuthenticator ($userid, 'authenticator');
       if ($log_on_error)
         {
         $userinfo = "";
         return;  // failed authentication
         }
       }

      // generate session
      $session = MakeToken ();

      $query = "UPDATE user SET session = '$session', "
             . "date_logged_on = "
             . "'" . strftime ("%Y-%m-%d %H:%M:%S", utctime()) . "' "
             . "WHERE userid = $userid";

      dbUpdate ($query);   // internally generated

      // convert to bcrypt password if not done already
      if (PasswordCompat\binary\check())
        {
        if (PasswordCompat\binary\_strlen ($userinfo ['password']) <= 32)
          {
          $md5_password = password_hash($password, PASSWORD_BCRYPT, array("cost" => 13));
          $query = "UPDATE user SET salt = NULL, password = '$md5_password' "
                 . "WHERE userid = $userid";
          dbUpdate ($query);   // internally generated
          } // end of generating better password hash and saving it
        } // end of bcrypt available
      else
        {   // bcrypt not available
        if (!$userinfo ['salt'])
          {
          $salt = MakeToken ();
          $md5_password = md5 ($password . $salt);  // now have salted password hash
          $query = "UPDATE user SET salt = '$salt', password = '$md5_password' "
                 . "WHERE userid = $userid";
          dbUpdate ($query);   // internally generated
          }

        }  // end of bcrypt not available

      $userinfo ['session'] = $session;
      $expiry = $userinfo ['cookie_expiry'];
      if (!$expiry)
        $expiry = 60 * 60 * 24 * 7;    // expire in 7 days as default
      if ($userinfo ['use_cookies'])   // only if wanted
        setcookie ('session', $userinfo ['session'], utctime() + $expiry, "/");

      // audit logons
      edittableAudit ($TABLE_AUDIT_LOGON, 'user', $userid);

      } // end of user on file

      return;   // end of logon process

    } // end of logon wanted

  if (empty ($adminsession))    // not logged on yet
    return;   // no session, and not logging in

  $userinfo = dbQueryOneParam ("SELECT * FROM user WHERE session = ?",
                               array ('s', &$adminsession));

  if ($userinfo) // will be empty if no match
    {

      /*
  echo '<p>Here is some debugging info:';
  echo '<pre>';
  print_r($userinfo);
  echo '</pre>';
      */

    // if the user is found, and their session was the same one found in the cookie
    // we don't need to pass sessions on URLs, which makes them look better

    if ($userinfo ['session'] == $_COOKIE ['session'])
      $userinfo ['have_cookie_ok'] = true;   // don't need to pass sessions on links
    } // end of reading that user OK

  } // end of CheckAdminSession

function GetUserColours ()
  {
  global $foruminfo;
  global $colours;

  // customised colours - if they are logged in
  if ($foruminfo)
    {

    // set up custom values from user values, if supplied
    reset ($colours);
    while (list ($colourname, $value) = each ($colours))
      {
      if ($foruminfo [$colourname])   // colour supplied?
        $colours [$colourname] ['current'] = $foruminfo [$colourname];  // use it
      }
    } // end of having $foruminfo

  } // end of GetUserColours

function ForumUserLoginFailure ($username, $password, $remote_ip)
  {
  global $foruminfo, $blocked, $banned_ip, $MAX_LOGIN_FAILURES, $MAX_UNKNOWN_USER_FAILURES;

  $username = strtolower ($username);
  $password = strtolower ($password);

  // generate login failure tracking record
  $query = "INSERT INTO bbuser_login_failure "
       . "(username, password, date_failed, failure_ip) "
       . "VALUES (?, ?, NOW(), ?);";

  dbUpdateParam ($query, array ('sss', &$username, &$password, &$remote_ip));

  $query = "UPDATE bbuser SET "
         . "count_failed_logins = count_failed_logins + 1 "
         . "WHERE username = ? ";

  dbUpdateParam ($query, array ('s', &$username));

  // clear old login failure tracking records (so they can reset by waiting a day)
  $query = "DELETE FROM bbuser_login_failure "
         . "WHERE username = ? AND failure_ip = ? "
         . "AND date_failed < DATE_ADD(NOW(), INTERVAL -1 DAY) ";

  dbUpdateParam ($query, array ('ss', &$username, &$remote_ip));

  // see how many times they failed from this IP address
  $query = "SELECT count(*) AS counter "
          . "FROM bbuser_login_failure "
          . "WHERE failure_ip  = ? "
          . "AND username = ?";

  $failure_row = dbQueryOneParam ($query, array ('ss', &$remote_ip, &$username));

  if ($failure_row ['counter'] > $MAX_LOGIN_FAILURES)
    {
    // now block that IP address
    $query = "INSERT INTO bbbanned_ip (ip_address, date_banned, reason) "
           . "VALUES ( ?, NOW(), CONCAT('Too many forum login failures for: ', ?) )";
    // don't check query, maybe already on file
    dbUpdateParam ($query, array ('ss', &$remote_ip, &$username), false);
    }

  // Extra code to allow for bots trying non-existent usernames:

  // see if user exists
  $row = dbQueryOneParam ("SELECT username FROM bbuser WHERE username = ? ",
                          array ('s', &$username));

  if ($row)
    return;  // username exists, all is OK

  $row = dbQueryOneParam ("SELECT * FROM bbsuspect_ip WHERE ip_address = ? ",
                          array ('s', &$remote_ip));

  if ($row)
    {
    if ($row ['count'] >=  $MAX_UNKNOWN_USER_FAILURES)
      {
      // right! that does it!
      // now block that IP address
      $query = "INSERT INTO bbbanned_ip (ip_address, date_banned, reason) "
             . "VALUES ( ?, NOW(), 'Too many attempts to login to forum with unknown username' )";
      dbUpdateParam ($query, array ('s', &$remote_ip));
      // get rid of from bbuser_login_failure
      dbUpdateParam ("DELETE FROM bbuser_login_failure WHERE failure_ip = ? ",
                     array ('s', &$remote_ip));
      // get rid of from bbsuspect_ip
      dbUpdateParam ("DELETE FROM bbsuspect_ip WHERE ip_address = ?",
                     array ('s', &$remote_ip));
      }
    else
      {
      // increment counter - haven't hit limit yet
      dbUpdateParam ("UPDATE bbsuspect_ip SET count = count + 1 WHERE ip_address = ?",
                     array ('s', &$remote_ip));
      }

    } // if already on file
  else
    {
    dbUpdateParam ("INSERT INTO bbsuspect_ip (ip_address, count) VALUES (?, 1)",
                   array ('s', &$remote_ip));
    }


  }  // end of ForumUserLoginFailure

function getForumInfo ($where, $params)
  {
  global $foruminfo;
  $date_now = strftime ("%Y-%m-%d %H:%M:%S", utctime());

//  echo "\n<!-- Inside getForumInfo, date_now = $date_now -->\n";

  $foruminfo = dbQueryOneParam (
                         "SELECT *, "
                       . "TO_DAYS('$date_now') - TO_DAYS(date_registered) AS days_on, "
                       . "TIMESTAMPDIFF(MINUTE, last_post_date, '$date_now') AS minutes_since_last_post, "
                       . "TIMESTAMPDIFF(MINUTE, date_mail_sent, '$date_now') AS minutes_since_last_mail "
                       . "FROM bbuser "
                       . "WHERE $where", $params);

  } // end of getForumInfo

function completeForumLogon ($bbuser_id)
{
  global $foruminfo, $blocked, $banned_ip, $control;
  global $AUDIT_LOGGED_ON, $AUDIT_LOGGED_OFF;

  // try and work out their IP address
  $remote_ip = getIPaddress ();

  $server_name = $_SERVER["HTTP_HOST"];

  getForumInfo ("bbuser_id = ?", array ('i', &$bbuser_id));

  $username = $foruminfo ['username'];
  // generate token
  $token = MakeToken ();

  $query = "UPDATE bbuser SET "
         . "  token = NULL, "
         . "  date_logged_on = "
         . "  '" . strftime ("%Y-%m-%d %H:%M:%S", utctime()) . "', "
         . "  last_remote_ip = ? "
         . "WHERE bbuser_id = ?";

  dbUpdateParam ($query, array ('ss', &$remote_ip, &$bbuser_id));

  $query = "DELETE FROM bbusertoken WHERE bbuser_id = ? AND date_expires <= NOW()";

  dbUpdateParam ($query, array ('s', &$bbuser_id));

  $expiry = $foruminfo ['cookie_expiry'];
  if (!$expiry)
    $expiry = 60 * 60 * 24 * 7;    // expire in 7 days as default

  $days = ceil ($expiry / (60 * 60 * 24));

  $query = "INSERT INTO bbusertoken "
         .        "(bbuser_id, token, date_logged_on, last_remote_ip, server_name, date_expires) "
         . "VALUES ( ?,           ?,     NOW(),             ?,           ?, "      // see below
         . "DATE_ADD(NOW(), INTERVAL '$days' DAY))";

  dbUpdateParam ($query, array ('ssss', &$bbuser_id, &$token, &$remote_ip, &$server_name ));

  audit ($AUDIT_LOGGED_ON, $bbuser_id);

  $foruminfo ['token'] = $token;
  if ($foruminfo ['use_cookies'])   // only if wanted
    setcookie ('token', $foruminfo ['token'], utctime() + $expiry, "/");

  // clear login failure tracking records (so they don't accumulate)
  $query = "DELETE FROM bbuser_login_failure "
         . "WHERE username = ? AND failure_ip = ?";
  dbUpdateParam ($query, array ('ss', &$username, &$remote_ip));

  // get rid of from bbsuspect_ip - this IP seems OK now
  dbUpdateParam ("DELETE FROM bbsuspect_ip WHERE ip_address = ?", array ('s', &$remote_ip));

  GetUserColours ();

} // end of completeForumLogon


function doForumLogon()
  {
  global $foruminfo, $blocked, $banned_ip, $control;
  global $PHP_SELF;

  // get rid of quotes so they can paste from the email like this: "Nick Gammon"
  $username = getP ('username', 30);
  $username = str_replace ("\"", " ", $username);

  $password = getP ('password', 50);

  $remote_ip = getIPaddress ();

  $server_name = $_SERVER["HTTP_HOST"];

  getForumInfo ("username = ?", array ('s', &$username));

  // if no password on the database, logging in MUST fail
  if (!$foruminfo ['password'])
    {
    $foruminfo = "";  // no password
    }

  // longer password means bcrypt: method / cost / salt / password
  else if (PasswordCompat\binary\check() &&
      PasswordCompat\binary\_strlen ($foruminfo ['password']) > 32)
    {
    if (!password_verify ($password, $foruminfo ['password']))
      $foruminfo = "";  // wrong password
    }
  else
    {
    $md5_password = md5 ($password . $foruminfo ['salt']);  // salt might be empty
    if ($foruminfo ['password'] != $md5_password)
      $foruminfo = "";  // wrong password
    }

  if (!$foruminfo)
    {
    ForumUserLoginFailure ($username, $password, $remote_ip);
    return;
    }   // end of not on file

  if ($foruminfo ['blocked'])
    {
    $blocked = true;    // can't do it
    $foruminfo = "";
    return; // give up
    }

  if ($foruminfo ['required_ip'])
    if ($foruminfo ['required_ip'] != $remote_ip)
      {
      $foruminfo = "";
      return;  // don't generate a cookie
      }

  $banned_row = dbQueryOneParam ("SELECT * FROM bbbanned_ip WHERE ip_address  = ?",
                                array ('s', &$remote_ip));
  if ($banned_row)
    {
    $banned_ip = true;    // can't do it
    $foruminfo = "";
    return; // give up
    } // end of a match

  $bbuser_id = $foruminfo ['bbuser_id'];

  // convert to bcrypt password if not done already

  if (PasswordCompat\binary\check())
    {
    if (PasswordCompat\binary\_strlen ($foruminfo ['password']) <= 32)
      {
      $md5_password = password_hash($password, PASSWORD_BCRYPT, array("cost" => 13));
      $query = "UPDATE bbuser SET salt = NULL, password = ? "
             . "WHERE bbuser_id = ?";
      dbUpdateParam ($query, array ('ss', &$md5_password, &$bbuser_id) );
      } // end of generating better password hash and saving it
    } // end of bcrypt available
  else
    {   // bcrypt not available
    if (!$foruminfo ['salt'])
      {
      $salt = MakeToken ();
      $md5_password = md5 ($password . $salt);  // now have salted password hash
      $query = "UPDATE bbuser SET salt = ?, password = ? WHERE bbuser_id = ?";
      dbUpdateParam ($query, array ('ssi', &$salt, &$md5_password, &$bbuser_id));
      }  // end of generating better password hash and saving it
    }  // end of bcrypt not available

  // generate token
  $token = MakeToken ();

  // see if this guy needs authentication
  $authrow = dbQueryOneParam ("SELECT COUNT(*) AS counter FROM authenticator_forum WHERE User = ?",
                              array ('i', &$bbuser_id));

  // no, so log them in
  if ($authrow ['counter'] == 0 )
    {
    completeForumLogon ($bbuser_id);
    return;
    }

  // security check for when they respond
  dbUpdateParam ("UPDATE authenticator_forum SET Token = ?, Date_Token_Sent = NOW() WHERE User = ?",
                 array ('si', &$token, &$bbuser_id));

  // HTML control items
  GetControlItems ();

  $encoding = $control ['encoding'];

  header("Content-type: text/html; charset=$encoding");
  MessageHead ("Forum authentication", "", "");

  ?>
  <form METHOD="post" ACTION="<?php echo $PHP_SELF;?>">
  <table>
  <tr>
  <th align=right>Authenticator required:</th>
  <td><input type=text name=authenticator size=64 maxlength=64 autofocus></td>
  </tr>
  <tr>
  <td>
  <input type=hidden name=action value="authenticator">
  <?php
  echo "<input type=hidden name=bbuser_id value=$bbuser_id>\n";
  echo "<input type=hidden name=token value=\"$token\">\n";
  ?>
  <p><input Type=submit Value="Confirm"></p>
  </td>
  </tr>
  </table>
  </form>
  </html>
  <?php

  MessageTail ();
  die ();

  } // end of doForumLogon

function checkForumAuthenticator ()
  {
  global $foruminfo, $blocked, $banned_ip, $control;

  $bbuser_id  = getP ('bbuser_id');
  $token  =     getP ('token');

  CheckField ("forum user", $bbuser_id);

  // check user ID and token are OK
  $authrow = dbQueryOneParam ("SELECT COUNT(*) AS counter FROM authenticator_forum " .
                             "WHERE User = ? ".
                             "AND   Token = ? " .
                             "AND   NOW() < DATE_ADD(Date_Token_Sent, INTERVAL 5 MINUTE) ",
                             array ('ss', &$bbuser_id, &$token));

  if ($authrow ['counter'] == 0)
   {
   $foruminfo = "";
   return "Authenticator request out of date or invalid";  // that user id / token is not on file
   }

  $log_on_error = HandleAuthenticator ($bbuser_id, 'authenticator_forum');
  if ($log_on_error)
   {
   $foruminfo = "";
   return $log_on_error;  // failed authentication
   }

  // cancel that token string on the authenticator table
  dbUpdateParam ("UPDATE authenticator_forum SET Token = '' WHERE User = ?", array ('i', &$bbuser_id));
  completeForumLogon ($bbuser_id);

  return false;
  } // end of checkForumAuthenticator

function CheckForumToken ()
  {
  global $foruminfo, $blocked, $banned_ip;
  global $log_on_error;


  $forumtoken = getPGC ('token');

  $foruminfo = "";

  // try and work out their IP address
  $remote_ip = getIPaddress ();

  // if they are logging on, let them

  $action = getP ('action');

  // clear old login IP ban records (so they can reset by waiting a day)
  $query = "DELETE FROM bbbanned_ip "
         . "WHERE ip_address = ? AND "
         . "date_banned < DATE_ADD(NOW(), INTERVAL -1 DAY) AND "
         . "reason LIKE 'Too many forum login failures for%' ";

  dbUpdateParam ($query, array ('s', &$remote_ip));

  $banned_row = dbQueryOneParam ("SELECT * FROM bbbanned_ip WHERE ip_address  = ?",
                                 array ('s', &$remote_ip)) ;

  if ($banned_row)
    {
    $banned_ip = true;    // can't do it
    $foruminfo = "";
    return; // give up
    } // end of a match

  if ($action == "logon")
    {
    doForumLogon ();
    return;   // end of logon process
    } // end of logon wanted
  else if ($action == "authenticator")
    {
    $log_on_error = checkForumAuthenticator ();
    return;   // end of logon process
    } // end of authenticator response

  if (empty ($forumtoken))    // not logged on yet
    return;   // no token, and not logging in

  // first look up token in bbusertoken (this allows for multiple logins)

  $tokeninfo = dbQueryOneParam ("SELECT * FROM bbusertoken WHERE token = ? "  .
                                "AND date_expires >= NOW()",
                                array ('s', &$forumtoken) );

  // if found, use user id in the bbusertoken table to find the forum user id

  if ($tokeninfo) // will be empty if no match
    {
    $id = $tokeninfo ['bbuser_id'];

    getForumInfo ("bbuser_id = ?", array ('i', &$id));

    if ($foruminfo) // will be empty if no match
      {
      // if the user is found, and their token was the same one found in the cookie
      // we don't need to pass tokens on URLs, which makes them look better

      if (isset ($tokeninfo ['token']) && ($tokeninfo ['token'] == $_COOKIE ['token']))
        $foruminfo ['have_cookie_ok'] = true;   // don't need to pass tokens on links
      }

    } // end of reading that user OK

  // check if they carried a good token to a bad IP
  if (isset ($foruminfo ['required_ip']))
    if ($foruminfo ['required_ip'] != $remote_ip)
      $foruminfo = "";

  // check for a problem user logging in
  if (isset ($foruminfo ['blocked']) && $foruminfo ['blocked'])
    {
    $blocked = true;    // can't do it
    $foruminfo = "";
    }
  else
    GetUserColours ();

  } // end of CheckForumToken

// log off by changing the session id
function LogOff ()
  {
  global $userinfo;
  global $TABLE_AUDIT_LOGOFF;

  // generate another random token - they won't know that one!
  $session = MakeToken ();

  $query = "UPDATE user SET session = ? WHERE userid = ?";
  dbUpdateParam ($query, array ('ss', &$session, &$userinfo ['userid']));

  // audit log offs
  edittableAudit ($TABLE_AUDIT_LOGOFF, 'user',  $userinfo ['userid']);

  $userinfo = "";    // user info is no good

  } // end of LogOff

function ShowSource ($filename)
  {

  Permission ('viewsource');

// see: highlight_file ($source_name);

  $fd = @fopen ($filename, "r")
    or Problem ("Cannot open file '$filename'");
  $sourcedata = fread ($fd, filesize ($filename))
    or Problem ("Cannot read file '$filename'");
  fclose ($fd);
  bTable ();
  bRow ("lightblue");
  tHead ("Source of: $filename");
  eRow ();
  bRow ("azure");
  echo "<td><pre><font size=\"3\"><code>\n";
  echo htmlspecialchars ($sourcedata, ENT_SUBSTITUTE | ENT_QUOTES | ENT_HTML5);
  echo "</code></font></pre></td>";
  eRow ();
  eTable ();
  $sourcedata = "";

  } // end of  ShowSource

function Init ($title,
               $keywords = "",
               $mail=false,
               $dbserver = "",
               $dbuser = "",
               $dbname = "",
               $dbpassword = "",
               $otherheaderhtml = "",
               $noContentType = false)
  {
  global $userinfo, $logoff, $control, $PHP_SELF,
         $viewsource, $PATH_TRANSLATED, $pagestarttime, $doingMail;

  // default databases
  global $DATABASE_SERVER, $GENERAL_DATABASE_USER,
         $GENERAL_DATABASE_NAME, $GENERAL_DATABASE_PASSWORD;

  $PHP_SELF = $_SERVER['PHP_SELF'];

  date_default_timezone_set('Australia/ACT');

  // take defaults if necessary
   if ($dbserver == "")
     $dbserver = $DATABASE_SERVER;
   if ($dbuser == "")
     $dbuser = $GENERAL_DATABASE_USER;
   if ($dbname == "")
     $dbname = $GENERAL_DATABASE_NAME;
   if ($dbpassword == "")
     $dbpassword = $GENERAL_DATABASE_PASSWORD;

  // note when we started, for timing purposes
  $pagestarttime = getmicrotime ();

  header("Cache-Control: no-cache, must-revalidate"); // HTTP/1.1
  header("Expires: Mon, 26 Jul 1997 05:00:00 GMT"); // Date in the past

  if ($doingMail = $mail)  // this assignment is intentional
    OpenMailDatabase ();
  else
    {
    OpenDatabase ($dbserver, $dbuser, $dbname, $dbpassword);
    // I am going to use cookies here, so I must do it before I do the header :)
    CheckAdminSession ();
    CheckForumToken ();
    }

  $control ['dateformat'] = "%e %b %Y";  // default date format
  $control ['shortdateformat'] = "%e %b";  // default short date format
  $control ['timeformat'] = "%r";  // default time format
  $control ['datetimeformat'] = "%e %b %Y %r";  // default date/time format
  $control ['shortdatetimeformat'] = "%e %b %r";  // default short date/time format
  $control ['encoding'] = "UTF-8";  // character encoding

  // HTML control items
  GetControlItems ();

  $encoding = $control ['encoding'];

  // for CSV files etc.
  if ($noContentType)
    {
    CheckSessionID (true);
    return;
    }

  header("Content-type: text/html; charset=$encoding");

  // empty title means we are doing a "printable" page
  if ($title)
    {
    MessageHead ($title, $keywords, $otherheaderhtml);

    // we check the session ID here because it outputs HTML which has to come
    // after the header (eg. the fact that you are logged on)

    CheckSessionID ();

    if ($viewsource == "yes")
      ShowSource ($PATH_TRANSLATED);
    }
  else
    CheckSessionID (true);

  } // end of Init

//----------------------------------------------------------------------------
// Start, end of page
//----------------------------------------------------------------------------

function SetFont ()
  {
  global $control;
  echo $control ['font'];
  } // end of SetFont


function MessageHead ($title, $keywords, $otherheaderhtml)
  {
global $control, $foruminfo;
global $bbsubject_id, $bbtopic_id, $bbsection_id;

if ($title == "%FORUM_NAME%")
  {

  // let them use just "id=x" on the URL

  $bbsubject_id = getGP ('id');
  if (!$bbsubject_id || ValidateInt ($bbsubject_id))
    $bbsubject_id = getGP ('bbsubject_id');

  $bbtopic_id = getGP ('bbtopic_id');
  $bbsection_id = getGP ('bbsection_id');

  // get better title (put section/topic/subject into it)

  $title = $control ['forum_name'];
  if ($bbsubject_id && !ValidateInt ($bbsubject_id))
    $title .= " : " .  LookupSubject (true);
  else if ($bbtopic_id && !ValidateInt ($bbtopic_id))
    $title .= " : " . LookupTopic (true);
  else if ($bbsection_id && !ValidateInt ($bbsection_id))
    $title .= " : " . LookupSection (true);

  } // end of forum title

$head = str_replace ("<%TITLE%>", htmlspecialchars ($title, ENT_SUBSTITUTE | ENT_QUOTES | ENT_HTML5), $control ['head']);
$head = str_replace ("<%KEYWORDS%>", htmlspecialchars ($keywords, ENT_SUBSTITUTE | ENT_QUOTES | ENT_HTML5), $head);


if (isset ($foruminfo ['font']))
  $control ['font'] = '<font face="' . $foruminfo ['font'] . '" size="-1">';

// build up CSS styles for user-supplied text and background colours

$font_string = "\n" .
              '<style type="text/css">' . "\n" .
              '  body {color:' ;

// if they specified a colour for their body, don't use the default

if (isset ($foruminfo ['colour_text']))
   $font_string .= $foruminfo ['colour_text'];
else
   $font_string .= $control ['colour_text'];

$font_string .= '; }' . "\n" .
                '  body {background-color: ';

// ditto for background

if (isset ($foruminfo ['colour_body']))
  {
  $font_string .=  $foruminfo ['colour_body'] .  ";\n" ;
  $font_string .= "background-image: none; }\n";
  }
else
  $font_string .=  $control ['colour_body'] . "; }\n" ;

// and take custom font

if (isset ($foruminfo ['font']) && $foruminfo ['font'])
  {
  $font_string .=  '  body { font-family: ';
  $font_string .=  $foruminfo ['font'] .  "; }\n" ;
  }

$font_string .= "</style>\n";

$head = str_replace ("<%BODY%>", $control ['body'], $head);

$head = str_replace ("<%FONT%>", $font_string, $head);


echo $head;
echo $otherheaderhtml;    // eg. refresh
  }   // end of MessageHead

/*

Call this at the end of each page to do a standard page footer

*/

function MessageTail ()
  {
global $control, $pagestarttime, $userinfo, $doingMail, $foruminfo;
global $COLOUR_TIMING_TEXT, $COLOUR_TIMING_BGND;
global $sql_evaluations;

$endtime = getmicrotime ();
$diff = $endtime - $pagestarttime;

if (!empty ($userinfo) || $doingMail ||
    isAdminOrModerator ())
  {
  echo "<p>";
  bTable (0);
  echo "<tr style=\"vertical-align:middle; background-color:$COLOUR_TIMING_BGND; color:$COLOUR_TIMING_TEXT; \">\n";
  echo "<td>\n";
  printf ("<b>Page execution time: %6.3f seconds</b>\n", $diff);
  echo "</td>";
  eRow ();
  eTable ();
  echo "<p></p>\n";
  }

if (isSQLdebugger () && !empty ($sql_evaluations))
  {
  echo "<div style=\"font-size:small;
        background-color:#DCE4F1;
        border-width:3px;
        border-color:#72A2C9;
        border-style:solid;
        padding:1em;
        border-radius: 4px;
        box-shadow: 5px 5px 3px #888888;\">\n";
  echo "<b>SQL analysis</b>\n";
  foreach ($sql_evaluations as $key => $value)
    {
    $sql = $value ['sql'];
    if (strpos ($value ['sql'], "\n"))
      $code = 'pre';
    else
      {
      // a bit of pretty-printing
      $sql = preg_replace ('/\b(FROM|ORDER|LEFT JOIN|RIGHT JOIN|JOIN|WHERE|HAVING|LIMIT|GROUP)\b/i', "\n       \\1", $sql);
      $sql = preg_replace ("/(AS [^,]+,)/", "\\1\n         ", $sql);
      }
    echo ("<hr><p><pre><code style=\"font-size:medium;\">" . nl2br_http (htmlspecialchars ($sql)) . "</code></pre>\n");
    bTable ();
    bRow ("lightblue");
    tHead ('ID');
    tHead ('SELECT type');
    tHead ('Table');
    tHead ('Type');
    tHead ('Possible keys');
    tHead ('Key');
    tHead ('Length');
    tHead ('Ref');
    tHead ('Rows');
    tHead ('Extra');
    eRow ();
    foreach ($value['explanation'] as $k => $v)
      {
      bRow ("azure");
      tData ($v['id']);
      tData ($v['select_type']);
      tData ($v['table']);
      tData ($v['type']);
      tData ($v['possible_keys']);
      tData ($v['key']);
      tData ($v['key_len']);
      tData ($v['ref']);
      tData ($v['rows']);
      tData ($v['Extra']);
      eRow ();

      }
    eTable ();
    }

  echo ("<hr>" . count ($sql_evaluations) . " SELECT statements analyzed.\n");
  echo "</div>\n";
  } // end of admin SQL stuff to show

echo $control ['tail'];
  } // end of MessageTail

function ElapsedTime ($where = "")
  {
global $pagestarttime, $userinfo, $doingMail, $foruminfo;

$endtime = getmicrotime ();
$diff = $endtime - $pagestarttime;

if (isAdminOrModerator ())
  {
  echo "<p><b><font color=\"darkgreen\">\n";
  printf ("Elapsed time $where: %6.3f seconds\n", $diff);
  echo "</font></b></p>\n";
  }

  } // end of ElapsedTime

function DebugSomething ($what)
  {
global $pagestarttime, $userinfo, $doingMail, $foruminfo;

if (!empty ($userinfo) || isAdmin ())
  {
  echo "<br>Debug: " . nl2br_http (htmlspecialchars ($what, ENT_SUBSTITUTE | ENT_QUOTES | ENT_HTML5)) . "<br>\n";
  }
  }     // end of DebugSomething

/*
Return a status name from an ID
*/

function GetStatusName ($statusid, &$statusname)
  {

  $row = dbQueryOne ("SELECT longdescription FROM status WHERE statusid = $statusid");  // internally generated

  if ($row)
    $statusname = $row [0];
  else
    $statusname = "Unknown status";

  } // end of GetstatusName

function Problem ($why)
  {
  echo "<h3>There is a problem ...</h3><p>\n";
  ShowError ($why);
  MessageTail (false);
  die ();
  } // end of Problem

//----------------------------------------------------------------------------
// Debugging
//----------------------------------------------------------------------------

function ShowArray ($name, $thearray, $recurse = false)
  {
  echo "<p><b>$name</b></p><ul>\n";
  if (!is_array ($thearray))
    {
    echo "<li>Not an array\n";
    echo "</ul>\n";
    return;
    }

  reset ($thearray);
  while (list ($cellname, $value) = each ($thearray))
    {

    printf ("<li>[%s] = [%s]\n",
            htmlspecialchars ($cellname, ENT_SUBSTITUTE | ENT_QUOTES | ENT_HTML5),   // name
            htmlspecialchars ($value, ENT_SUBSTITUTE | ENT_QUOTES | ENT_HTML5));  // value
    if ($recurse && is_array ($value))
      ShowArray ($cellname, $value);  // should really be , true but be cautious
    }
  echo "</ul>\n";

  } // end of showarray


function DebugVars ()
  {
  echo "<hr>\n";
  ShowArray ("HTTP_POST_VARS", $_POST, true);
  ShowArray ("HTTP_GET_VARS", $_GET);
  ShowArray ("HTTP_COOKIE_VARS", $_COOKIE);
  ShowArray ("HTTP_SERVER_VARS", $_SERVER);
  ShowArray ("GLOBALS", $GLOBALS);
  echo "<hr>\n";
  } // end of DebugVars

//----------------------------------------------------------------------------
// Table management
//----------------------------------------------------------------------------

// begin table
function bTable ($border=1, $cellpadding=5)
  {
//  echo "<table border=\"$border\" cellpadding=\"$cellpadding\">\n";
  echo "<table style=\"border:$border" . "px solid black;\">\n";
  } // end of bTable

// end table
function eTable ()
  {
  echo "</table>\n";
  } // end of eTable

// begin row
function bRow ($bgcolor="same", $valign="top")  // azure
  {
  if ($bgcolor == 'same')
    echo "<tr style=\"vertical-align:$valign;\">\n";
  else
    echo "<tr style=\"vertical-align:$valign; background-color:$bgcolor\">\n";

  } // end of bRow

// end row
function eRow ()
  {
  echo "</tr>\n";
  } // end of eRow

// table heading
function tHead ($text, $fontsize=-1, $align="left", $colspan=1)
  {
  if ($colspan == 1)
    echo "<th style=\"text-align:$align;\" >"
        . nl2br_http (htmlspecialchars ($text, ENT_SUBSTITUTE | ENT_QUOTES | ENT_HTML5))
        . "</th>\n";
  else
    echo "<th style=\"text-align:$align; \" colspan=\"$colspan\">"
        . nl2br_http (htmlspecialchars ($text, ENT_SUBSTITUTE | ENT_QUOTES | ENT_HTML5))
        . "</th>\n";

  }  // end of tHead

// table heading extra - add extra HTML (eg. class, colspan)
function tHeadx ($text, $extra="")
  {
  echo "<th $extra> " . nl2br_http (htmlspecialchars ($text, ENT_SUBSTITUTE | ENT_QUOTES | ENT_HTML5)) . "</th>\n";
  }  // end of tHeadx

// table heading (HTML) - with class specified
function tHeadHx ($text, $extra="")
  {
  echo "<th $extra>$text</th>\n";
  }  // end of tHeadHx

// table heading - HTML
function tHeadH ($text, $fontsize=-1, $align="left", $colspan=1)
  {
  if ($colspan == 1)
    echo "<th style=\" text-align:$align;\" >$text</th>\n";
  else
    echo "<th style=\" text-align:$align;\" colspan=\"$colspan\" >$text</th>\n";
  }  // end of tHeadH

// table data extra - add extra HTML (eg. class, colspan)
function tDatax ($text, $extra="")
  {
  echo "<td $extra> " . nl2br_http (htmlspecialchars ($text, ENT_SUBSTITUTE | ENT_QUOTES | ENT_HTML5)) . "</td>\n";
  }  // end of tDatax

// table data extra (HTML) - add extra HTML (eg. class, colspan)
function tDataHx ($text, $extra="")
  {
  echo "<td $extra>$text</td>\n";
  } // end of tDataHx

// table data
function tData ($text, $fontsize=-1, $align="left", $colspan=1)
  {

  if ($colspan == 1)
    echo "<td style=\"text-align:$align; \" >"
        . nl2br_http (htmlspecialchars ($text, ENT_SUBSTITUTE | ENT_QUOTES | ENT_HTML5))
        . "</td>\n";
  else
    echo "<td style=\"text-align:$align; \" colspan=\"$colspan\" >"
        . nl2br_http (htmlspecialchars ($text, ENT_SUBSTITUTE | ENT_QUOTES | ENT_HTML5))
        . "</td>\n";

  } // end of tData

// HTML table data
function tDataH ($text, $fontsize=-1, $align="left", $colspan=1)
  {

  if ($colspan == 1)
    echo "<td style=\"text-align:$align; \">$text</td>\n";
  else
    echo "<td style=\"text-align:$align; \" colspan=\"$colspan\">$text</td>\n";

   } // end of tDataH

// start unordered list
function bList ()
  {
  echo "<ul>\n";
  } // end of bList

// end unordered list
function eList ()
  {
  echo "</ul>\n";
  } // end of eList

// start ordered list
function bOList ()
  {
  echo "<ol>\n";
  } // end of bOList

// end ordered list
function eOList ()
  {
  echo "</ol>\n";
  } // end of eOList

// list item
function LI ()
  {
  echo "<li>";
  } // end of LI

// returns an hlink in a string
function shLink (&$result, $description, $destination, $params="", $newwindow=false, $nofollow=false)
  {
  global $userinfo, $viewsource, $foruminfo;
  $token = "";
  $session = "";

  if (!isset ($foruminfo ['have_cookie_ok']) && isset ($foruminfo ['token']))
    $token = $foruminfo ['token'];
  if (!isset ($userinfo ['have_cookie_ok']) && isset ($userinfo ['session']))
    $session = $userinfo ['session'];

  if ($session && $token)
    $session = "?session=$session&amp;token=$token";
  else if ($session)
    $session = "?session=$session";
  else if ($token)
    $session = "?token=$token";
  else
    $session = "";

  $params = htmlspecialchars ($params, ENT_SUBSTITUTE | ENT_QUOTES | ENT_HTML5);   // should be &amp; inside URLs

  if ($viewsource == "yes")
    $session .= "&amp;viewsource=yes";

  if ($newwindow)
    $target = " target=\"_blank\"";
  else
    $target = "";

  if ($nofollow)
    $target .= " rel=\"nofollow\"";

  // only show session ID if we have one, and we are going to a dynamic page
  if (!empty ($session) && stristr ($destination, ".php"))
    if (empty ($params))
      $result =  "<a href=\"$destination$session\"$target>$description</a>\n";
    else
      $result =  "<a href=\"$destination$session&$params\"$target>$description</a>\n";
  else
    if (empty ($params))
      $result =   "<a href=\"$destination\"$target>$description</a>\n";
    else
      $result =   "<a href=\"$destination?$params\"$target>$description</a>\n";

  } // end of shLink

// use this to hyperlink to another file, preserving session id
function hLink ($description, $destination, $params="", $newwindow=false, $nofollow=false)
  {
  shLink ($result, $description, $destination, $params, $newwindow, $nofollow);
  echo $result;
  }   // end of hLink

// use this to send a form, preserving forum session id
function ForumSession ()
  {
  global $foruminfo;
  if (!isset ($foruminfo ['have_cookie_ok']))
    if (!empty ($foruminfo))
      {
      $token = $foruminfo ['token'];
      echo "<input type=\"hidden\" name=\"token\" value=\"$token\"/>\n";
      }
  } // end of ForumSession

// use this to send a form, preserving session id
function FormSession ()
  {
  global $userinfo, $viewsource;

  if (!isset ($userinfo ['have_cookie_ok']))
    if (!empty ($userinfo))
    {
    $session = $userinfo ['session'];
    echo "<input type=\"hidden\" name=\"session\" value=\"$session\"/>\n";
    }
  if ($viewsource == "yes")
    echo "<input type=\"hidden\" name=\"viewsource\" value=\"yes\"/>\n";
  ForumSession ();
  } // end of FormSession


// check we can do something
function Permission ($todo)
  {
  global $userinfo, $ADMIN_DIRECTORY, $PHP_SELF;

  $PHP_SELF = $_SERVER['PHP_SELF'];

  if (!$userinfo || !$userinfo [$todo])
    {
    echo "<p>";
    hLink ("Log on", $ADMIN_DIRECTORY . "logon.php?returnto=" . urlencode ($_SERVER ['REQUEST_URI']));
    echo "</p>\n";
    Problem ("Permission denied");
   }
  }  // end of  Permission

/*

Shows a table, supplied in the $table argument (ie. an array)
Tables consist of a label, and contents. eg.

$table = array
  (
  'Summary' => $row ["shortdescription"],
  'Details' => $row ["longdescription"],
  );  // end of array

You can specify parameters for the table, there are defaults if you omit them:

$COLOUR_TABLE_LEFT_BGND       = GetColour ('colour_lh_table'             );
$COLOUR_TABLE_RIGHT_BGND      = GetColour ('colour_rh_table'             );

$params =  array
  (     // table parameters
  'LH' => 'valign="top" bgcolor="' . $COLOUR_TABLE_LEFT_BGND . '" align="right"',
  'RH' => 'bgcolor="' . $COLOUR_TABLE_RIGHT_BGND . '" align="left"'
  );

You can specify one or more "special processing" for named labels:

$specials = array
  (     // specials
  'Summary'     => array ('heading'),   // want this in bold
  'Details'     => array ('breaks'),    // has line breaks
  'Fixed in version' => array ('html' => true, 'heading' => true) // is in HTML and we want bold
  );

Currently specials are:

  description - description (LH column) - defaults to label
  heading - I want this line in bold (ie. TH rather than TD)
  breaks - I want to see newlines - implies not HTML
  html - The line is already in HTML
  input - field is input, argument is name (eg. input => 'myfield')
  type - type of input (text, multiline, password, combo, bool, filename)
  size - size of input field on screen
  maxlength - max length of input field
  values - values array for a combo box etc.
  rows - number of rows in a multiline field
  cols - number of columns in a multiline field
  error - flag entry with a red asterisk
  comment - explanatory material to be shown in small type in the RH column
  htmlcomment - explanatory material in the RH column - HTML
  readonly - field is read only

*/

function ShowTable ($table, $params, $specials)
  {
  global $WEBMASTER;
  global $control;
  global $MAX_FILE_SIZE;

/*
  echo '<p>Here is some debugging info:';
  echo '<pre>';
  print_r($_FILES);
  print_r($_POST);
  echo '</pre>';
*/

  $COLOUR_FORM_ERROR_TEXT       = GetColour ('colour_form_error');

  if (!is_array ($table))
    {
    echo "<p><b>Not a table</b></p>\n";
    return;
    }

  if (isset ($params ['table']))
    $tableparam = $params ['table'];    // args for table
  else
    $tableparam="border=\"0\" cellpadding=\"5\""; // default

  if (isset ($params ['row']))
    $rowparam = $params ['row'];    // args for each row
  else
    $rowparam="valign=\"top\"";         // default

  if (isset ($params ['LH']))
    $LHcolparam = $params ['LH'];    // args for LH column
  else
    $LHcolparam="valign=\"top\" align=\"right\"";         // default

  if (isset ($params ['RH']))
    $RHcolparam = $params ['RH'];    // args for RH column
  else
    $RHcolparam="valign=\"top\"";         // default

  if (isset ($params ['font']))
    {
    $bfont = $params ['font'];    // font definition
    $efont = "</font>";
    }
  else
    {
    $bfont = "";
    $efont = "";
   }

  // sanity check - we can't have errors for non-input fields

  if (is_array ($specials))
    {
    $implementation_error = false;
    reset ($specials);
    while (list ($label, $contents) = each ($specials))
      {
      if (isset ($contents ['error']))
        {
        $error = $contents ['error'];
        if ($error != '*' && !$contents ['input'])
          {
          ShowError ("Implementation error - error message \"$error\" for field \"$label\""
                   . " however this field is not an input field.");
          $implementation_error = true;
          }
        }
      } // end of checking specials

    if ($implementation_error)
      echo "<p>Please notify the above message(s) to: <a href=\"mailto:$WEBMASTER\">$WEBMASTER</a></p>";
    } // end of specials being an array

  echo "<table $tableparam>\n";

  $contents = ""; // in case no items

  $first_input = true;

  reset ($table);
  while (list ($label, $contents) = each ($table))
    {

    // any special processing for this item?
    if (isset ($specials [$label]))
      $special = $specials [$label];
    else
      $special = "";

    $html = false;
    $heading = false;
    $breaks = false;
    $inputname = "";
    $error = false;
    $type = 'text';
    $comment = "";
    $htmlcomment = "";
    $description = $label;
    $required = false;
    $size = false;
    $maxlength = false;
    $rows = false;
    $cols = false;
    $readonly = false;
    $values = "";

//    $bold = false;

    // if the word is in the array, then it is enabled
    if (is_array ($special))
      {
      if (isset ($special ['html']))
        $html = $special ['html'];                  // HTML encoded

      if (isset ($special ['heading']))
        $heading = $special ['heading'];            // this row is heading

      if (isset ($special ['breaks']))
        $breaks = $special ['breaks'];              // line breaks wanted

      if (isset ($special ['input']))
        $inputname = $special ['input'];            // name of input field

      if (isset ($special ['size']))
        $size = $special ['size'];                  // size of it on screen

      if (isset ($special ['maxlength']))
        $maxlength = $special ['maxlength'];        // max length of it

      if (isset ($special ['type']))
        $type = $special ['type'];                  // type of input (text, password, combo, multiline, bool)

      if (isset ($special ['values']))
        $values = $special ['values'];              // values for combo box

      if (isset ($special ['rows']))
        $rows =   $special ['rows'];                // rows in multiline box

      if (isset ($special ['cols']))
        $cols =   $special ['cols'];                // cols in multiline box

      if (isset ($special ['error']))
        $error = $special ['error'];                // this row is in error

      if (isset ($special ['comment']))
        $comment = $special ['comment'];            // comment pertaining to this row

      if (isset ($special ['required']))
        $required = $special ['required'];          // is field required?

      if (isset ($special ['readonly']))
        $readonly = $special ['readonly'];          // is field read-only?

      if (isset ($special ['htmlcomment']))
        $htmlcomment = $special ['htmlcomment'];    // HTML comment pertaining to this row

//      $bold = $special ['bold'];                  // is description in bold?
      if (isset ($special ['description']))
        $description = $special ['description'];  // description of this row

      if (empty ($type))
        $type = 'text';

      }   // end of having specials

    // don't display NULL rows, provided we are not getting input from it
    if (!isset ($contents) && $readonly)
      continue;

   if (is_array ($contents))
      {
      ShowArray ("error, contents is an array", $contents);
      return;
      }

    // if 'breaks' then they want to keep line breaks
    if ($breaks)
      $contents = nl2br_http (htmlentities ($contents, ENT_SUBSTITUTE | ENT_QUOTES | ENT_HTML5));
    else if (!$html)
      $contents = htmlspecialchars ($contents, ENT_SUBSTITUTE | ENT_QUOTES | ENT_HTML5);

    // this is a heading?
    if ($heading)
      $td = "th";
    else
      $td = "td";

    echo "  <tr $rowparam>\n";
    echo "    <$td $LHcolparam>$bfont<b>" . htmlspecialchars ($description, ENT_SUBSTITUTE | ENT_QUOTES | ENT_HTML5) . "</b>$efont</$td>\n";
    echo "    <$td $RHcolparam>$bfont";

    // do forms processing
    if (!$readonly && !empty ($inputname))
      {
      switch ($type)
        {
        case 'combo':
          echo "<select name=\"$inputname\" size=\"1\">\n";
          if (!$required)
            {
            echo "<option value=\"\" ";
            if (!$contents)
              echo "selected ";
            echo "/>(none)\n";
            } // end if no entry required
          reset ($values);
          while (list ($selectvalue, $selectdescription) = each ($values))
            {
            echo "<option value=\"$selectvalue\" ";
            if ($contents == $selectvalue)
              echo "selected ";
            echo "/>$selectdescription\n";
            } // end of each item
          echo "</select>\n";
          break;    // end of combo box

        case 'list':
          echo "<select name=\"$inputname\" size=\"$rows\">\n";
          if (!$required)
            {
            echo "<option value=\"\" ";
            if (!$contents)
              echo "selected ";
            echo "/>(none)\n";
            } // end if no entry required
          reset ($values);
          while (list ($selectvalue, $selectdescription) = each ($values))
            {
            $selectvalue = htmlspecialchars ($selectvalue);
            echo "<option value=\"$selectvalue\" ";
            if ($contents == $selectvalue)
              echo "selected ";
            echo "/>$selectdescription\n";
            } // end of each item
          echo "</select>\n";
          break;    // end of list box

        case 'multiline':
          echo "<textarea name=\"$inputname\" wrap=\"virtual\" ";
          if (isset ($rows))
            echo "rows=\"$rows\" ";
          if (isset ($cols))
            echo "cols=\"$cols\" ";
          if ($first_input)
            {
            echo "autofocus ";
            $first_input = false;
            } // end of first one
          echo ">";
          echo $contents;
          echo "</textarea>\n";
          break;    // end of multiline input area

        case 'bool':
          echo "<input type=\"checkbox\" name=\"$inputname\" value=\"1\" ";
          if ($contents)
            echo "checked ";
          echo "/>\n";
          break;    // end of boolean

        case 'latitude':
          $name1 = $inputname . "_direction";
          $name2 = $inputname . "_degrees";
          $name3 = $inputname . "_minutes";
          $deg = floor (abs ($contents));
          $min = round ((abs ($contents) - $deg) * 60 * 10) / 10;;

          echo "\n<select name=\"$name1\" size=\"1\">\n";
          echo "<option value=\"1\"";
          if ($contents >= 0)
            echo " selected";
          echo ">North\n";
          echo "<option value=\"-1\"";
          if ($contents < 0)
            echo " selected";
          echo ">South\n";
          echo "</select>\n";
          echo "&nbsp;<input type=\"$type\" name=\"$name2\" value=\"$deg\" "
             . "size=\"3\" maxlength=\"3\"/> degrees\n";
          echo "&nbsp;<input type=\"$type\" name=\"$name3\" value=\"$min\" "
             . "size=\"7\" maxlength=\"7\"/> minutes\n";
          break;    // end of latitude

        case 'longitude':
          $name1 = $inputname . "_direction";
          $name2 = $inputname . "_degrees";
          $name3 = $inputname . "_minutes";
          $deg = floor (abs ($contents));
          $min = round ((abs ($contents) - $deg) * 60 * 10) / 10;;

          echo "\n<select name=\"$name1\" size=\"1\">\n";
          echo "<option value=\"1\"";
          if ($contents >= 0)
            echo " selected";
          echo ">East\n";
          echo "<option value=\"-1\"";
          if ($contents < 0)
            echo " selected";
          echo ">West\n";
          echo "</select>\n";
          echo "&nbsp;<input type=\"$type\" name=\"$name2\" value=\"$deg\" "
             . "size=\"3\" maxlength=\"3\"/> degrees\n";
          echo "&nbsp;<input type=\"$type\" name=\"$name3\" value=\"$min\" "
             . "size=\"7\" maxlength=\"7\"/> minutes\n";
          break;    // end of longitude

        case 'filename':
          echo "<input type=\"hidden\" name=\"MAX_FILE_SIZE\" value=\"$MAX_FILE_SIZE\" >\n";
          echo "Current file name: ";
          if ($contents)
             {
             echo htmlentities ($contents);
             echo " - Remove: ";
             echo "<input name=\"_DELETE_$inputname\" type=\"checkbox\" value=1 >\n";
             echo "<hr>Replace file with: <input name=\"$inputname\" type=\"file\" >\n";
             // original file name in case they don't upload a new one
             echo "<input name=\"$inputname\" type=\"hidden\" value=\"" . htmlentities ($contents) . "\" >\n";
             }
          else
             echo "(None)<br>Upload file: <input name=\"$inputname\" type=\"file\" >";

          break;  // end of filename

        default:
//          echo "<input type=\"$type\" name=\"$inputname\" value=\"" . str_replace ('"', '&quot;', $contents) . "\" ";
          echo "<input type=\"$type\" name=\"$inputname\" value=\"$contents\" ";
          if (isset ($size))
            echo "size=\"$size\" ";
          if (isset ($maxlength))
            echo "maxlength=\"$maxlength\" ";
          if ($first_input)
            {
            echo "autofocus ";
            $first_input = false;
            } // end of first one
         if ($required)
            echo "required ";
          echo "/>\n";
          break;    // end of default input type

        }   // end of switch on input type
      if ($error)
        echo ("<br><b><font color=\"$COLOUR_FORM_ERROR_TEXT\">" .
              htmlspecialchars ($error, ENT_SUBSTITUTE | ENT_QUOTES | ENT_HTML5) .
              "</font></b>");
      } // end of having an input field
    else
      // read-only field
      {
      echo $contents;
      // we have to put the contents into the form so we pick them up when it is sent
      if (!empty ($inputname))
        echo "<input type=\"hidden\" name=\"$inputname\" value=\"" . htmlentities ($contents) . "\">";
      }

    // comment

    if (!empty ($comment))
      {
      echo "<br><font size=\"-2\">";
      echo (nl2br_http (htmlentities($comment)));
      echo ("\n</font>\n");
      }

    // HTML comment

    if (!empty ($htmlcomment))
      {
      echo "<br><font size=\"-2\">";
      echo ($htmlcomment);
      echo ("\n</font>\n");
      }

    echo "$efont</$td>\n";
    echo "  </tr>\n";
    } // end of looping through each item
  echo "</table>\n";

  } // end of ShowTable

function getmicrotime ()
  {
  $mtime = microtime();
  $mtime = explode(" ",$mtime);
  $mtime = $mtime[1] + $mtime[0];
  return ($mtime);
  }  // end of getmicrotime


function ShowList ($results,    // SQL query results
                   $id,         // id of identity row (eq. faqid)
                   $other_args = "",  // other args for link, eg. &productid=0
                   $summary = "summary",
                   $show_count = true,  // show count of matches?
                   $block_preamble = "<UL>",
                   $block_postamble = "</UL>",
                   $line_preamble = "<LI>",
                   $line_postamble = "</LI>",
                   $page = ""
                   )
{
global $PHP_SELF;

$count = count ($results);

if ($count)
  echo $block_preamble . "\n";

if (!$page)
  $page = $PHP_SELF;

foreach ($results as $row)
  {
  echo $line_preamble;
  $summarydata = $row [$summary];
  $iddata = $row [$id];
  hLink (htmlspecialchars ($summarydata, ENT_SUBSTITUTE | ENT_QUOTES | ENT_HTML5), $page, "$id=$iddata$other_args");
  echo $line_postamble . "\n";

  // ------ excerpt -------

  if (isset ($row ["excerpt"]))
    {
    $excerpt = $row ["excerpt"];
    bList (); // indent
    echo "<font size=-2>";
    if ($row ['html'])
      $excerpt = strip_tags ($excerpt);
    echo (htmlentities($excerpt));
    echo ("\n</font><br>\n");
    eList ();   // unindent
    }
  else
    $excerpt = "";

  } // end of reading each row

if ($count)
  echo $block_postamble . "\n";

if ($show_count)
  {
  echo "<p><b>";
  if ($count == 0)
    echo "No matches.";
  else if ($count == 1)
    echo "One match.";
  else
    echo $count . " matches.";
  echo "</b></p>";
  }  // end of searching for something

return $count;
} // end of ShowList

// validate integers
function ValidateInt ($theint)
  {
  $theint = trim ($theint); // ensure no leading spaces etc.

  // look for leading sign
  if (strlen ($theint) > 0 && ($theint [0] == '+' || $theint [0] == '-'))
    $theint = substr ($theint, 1);    // remove sign
  if (!strlen ($theint) || !preg_match ("|^[0-9]+$|", $theint))
    return "Field must be numeric";
  } // end of ValidateInt

// validate booleans
function ValidateBool ($thebool)
  {
  if (!strlen ($thebool) || !preg_match ("|^[0-1]$|", $thebool))
    return "Field must be '0' or '1'";
  } // end of ValidateBool

// validate real numbers
function ValidateReal ($thereal)
  {
  if (!$thereal)
    return "Field cannot be empty";

  $thereal = trim ($thereal); // ensure no leading spaces etc.

  // look for leading $ sign
  if ($thereal [0] == '$')
    $thereal = substr ($thereal, 1);    // remove $

  // look for leading sign
  if ($thereal [0] == '+' || $thereal [0] == '-')
    $thereal = substr ($thereal, 1);    // remove sign

  // get rid of commas (for thousands)
  $thereal = str_replace (",", "", $thereal);

  $items = explode (".", trim ($thereal));  // don't want two decimal points
  if (count ($items) > 2 || !strlen ($thereal) || !preg_match ("|^[0-9.]+$|", $thereal))
    return "Field must be numeric";
  } // end of ValidateReal

// validate colours
function ValidateColour ($thecolour)
  {
  $thecolour = trim ($thecolour); // ensure no leading spaces etc.

  // look for leading #
  if ($thecolour [0] == '#')
    {
    $thecolour = substr ($thecolour, 1);    // remove #
    if (!strlen ($thecolour) || !preg_match ("|^[A-Fa-f0-9]+$|", $thecolour))
      return "Field must colour name or #hex_colour";
    }
  else
    {
    if (!strlen ($thecolour) || !preg_match ("|^[A-Za-z0-9]+$|", $thecolour))
      return "Field must colour name or #hex_colour";
    }

  } // end of ValidateColour

// validate font names
function ValidateFont ($thefont)
  {
  $thecolour = trim ($thefont); // ensure no leading spaces etc.

  if (!strlen ($thefont) || !preg_match ("|^[-A-Za-z0-9 ,_]+$|", $thefont))
    return "Invalid characters in font name";

  } // end of ValidateFont


// validate degrees (eg. latitude/longitude)
function ValidateDegrees ($thedegrees)
  {
  $error = ValidateReal ($thedegrees);
  if ($error)
    return $error;
  if ($thedegrees > 360 || $thedegrees < -360)
    return "Degrees must be in range 0 to 360";
  } // end of ValidateDegrees

// simple date check
function ValidateDate ($thedate)
  {
  global $control;

  $thedate = trim ($thedate); // ensure no leading spaces etc.

  // don't let them slip in alphas or other stuff into the middle of a number
  if (!preg_match ("|^[0-9\-]+$|", $thedate))
     return "Date must consist of YYYY-MM-DD";

  $items = explode ("-", trim ($thedate));

  if (count ($items) != 3)
     return "Date must consist of YYYY-MM-DD";

  if ($items [0] < 1700 || $items [0] > 2100)
     return "Year must be in range 1700 to 2100";

  if ($items [1] < 1 || $items [1] > 12)
     return "Month must be in range 1 to 12";

  if ($items [2] < 1 || $items [2] > 31)
     return "Month must be in range 1 to 31";

  return "";
  } // end of ValidateDate

function ValidateTime ($thetime)
  {
  $thetime = trim ($thetime); // ensure no leading spaces etc.


  // don't let them slip in alphas or other stuff into the middle of a number
  if (!preg_match ("|^[0-9\:]+$|", $thetime))
     return "Time must consist of HH:MM or HH:MM:SS";

  $items = explode (":", trim ($thetime));

  if (count ($items) < 2 || count ($items) > 3)
     return "Time must consist of HH:MM or HH:MM:SS";

  if ($items [0] < 0 || $items [0] > 23)
     return "Hour must be in range 0 to 23";

  if ($items [1] < 0 || $items [1] > 59)
     return "Minute must be in range 0 to 59";

  if ($items [2])
    if ($items [2] < 0 || $items [2] > 59)
       return "Seconds must be in range 0 to 59";

  return "";
  } // end of ValidateTime

function ValidateField ($value, $type)
  {
  $error = "";
  switch ($type)
    {
    case "int":
                $error = ValidateInt ($value);
                 break;

    case "bool":
                $error = ValidateBool ($value);
                 break;

    case "real":
                $error = ValidateReal ($value);
                 break;

    case "decimal":
                $error = ValidateReal ($value);
                 break;

     case "date":
                $error = ValidateDate ($value);
                break;

     case "time":
                $error = ValidateTime ($value);
                break;

     case "latitude":
     case "longitude":
                $error = ValidateDegrees ($value);
                break;

     case "datetime":
                $temp = explode (" ", $value);
                if (count ($temp) < 1 || count ($temp) > 2)
                  $error = "Date/time must consist of YYYY-MM-DD [ HH:MM:SS ]";
                $error = ValidateDate ($temp [0]);
                // date OK? then check time
                if (!$error && $temp [1])
                  $error = ValidateTime ($temp [1]);
                break;

    case "colour":
                $error = ValidateColour ($value);
                 break;

    case "font":
                $error = ValidateFont ($value);
                 break;

    } // end of switch on type

  return $error;

  } // end of ValidateField

function ValidateOneField ($name, $type, $notnull, $maxsize, &$specials)
  {
  global $have_error;

  if (isset ($_POST [$name]))
    {
    // remove leading/trailing spaces
    $_POST [$name] = trim ($_POST [$name]);
    $value = $_POST [$name]; // get value
    }
  else
    $value = "";

  // check for empty on NOT NULL fields
  if (!strlen ($value))
    {
    if ($notnull)
      {
      $have_error = true;
      $specials [$name] ['error'] = "Field cannot be empty";
      }
      return;   // enough validation, field is empty
    } // end of empty field

  // don't validate read-only fields, they can't fix them
  if (isset ($specials [$name] ['readonly']) && $specials [$name] ['readonly'])
    return;

  // validate fields

  $error = ValidateField ($value, $type);

  if (!$error && $type == "email")
    {
    if (strstr ($value, "\""))
      $error = "Email address should not contain a 'quote' character";
    else if (!strstr ($value, "@"))
      $error = "Email address should contain the '@' character";

    } // end of email address

  if (!$error)
    {
    if ($maxsize && strlen ($value) > $maxsize)
      $error = "You have entered too much data - maximum is $maxsize characters";
    } // end of checking size

  if ($error)
    {
    $have_error = true;
    $specials [$name] ['error'] = $error;
    }

  } // end of ValidateOneField

function CheckField ($description, $id, $can_be_blank=true)
  {
  if ($id || !$can_be_blank)
    {
    $error = ValidateInt ($id);
    if ($error)
      Problem ("Error in $description ID - $error");
    } // end of not empty
  } // end of CheckField

function ShowTablesToEdit ()
  {
  global $userinfo, $ADMIN_DIRECTORY, $TABLE_EDITOR;

  echo "<form METHOD=\"post\" ACTION=\"$TABLE_EDITOR\"> \n";
  echo "<p>Edit table: &nbsp; <select name=table size=1>\n";

  // see if this user can edit *all* tables

  $userid = $userinfo ["userid"];
  $row = dbQueryOneParam ("SELECT * FROM access WHERE userid = ? AND tablename = '%'",
                          array ('s', &$userid));

  if ($row)
    {
    // we can edit all tables, so get a list of them
    GetDatabaseName ($databasename);

    $result = dbQuery ("SHOW TABLES FROM " . $databasename) ;  // generated internally

    while ($row = mysqli_fetch_row ($result))
      {
      $table = $row [0];
      echo "<option value=\"$table\">$table\n";
      } // end of doing each row

    dbFree ($result);

    }  // end of being able to edit all tables
  else
    {
    // find the tables he can edit
    $results = dbQueryParam ("SELECT * FROM access WHERE userid = ? AND can_select = 1", array ('s', &$userid));
    foreach ($results as $row)
      {
      $table = $row ['tablename'];
      echo "<option value=\"$table\">$table\n";
      } // end of doing each row

    } // end of being able to edit *some* tables

  echo "</select>\n";

  FormSession ();
  echo "&nbsp; &nbsp; <input Type=submit name=dump Value=\"Edit\"> </p>\n";
  echo "</form>\n";
  } // end of ShowTablesToEdit

function MailAdmins ($subject, $message, $link, $condition, $bbuser_id = 0)
  {
  global $control, $username, $foruminfo, $subjectrow;

  // don't do it if they don't permit it
  if (!$control ['allow_notification'])
    return;

  $forum_name = $control ['forum_name'];
  $forum_url = $control ['forum_url'];

  // put the "http:" part back for emails
  if (substr ($forum_url, 0, 2) == "//")
    $forum_url = "http:" . $forum_url;

  // find all admins (except ourselves - we don't need to notify ourselves
  $query = "SELECT * from bbuser "
          . "WHERE admin <> 0 "
          . "  AND $condition <> 0 "
          . "  AND (bounced IS NULL OR bounced = 0) ";

  if ($bbuser_id)
    $query .= "AND bbuser_id <> " . $bbuser_id;
  else
    if (isset ($foruminfo ['bbuser_id']) && $foruminfo ['bbuser_id'])
      $query .= "AND bbuser_id <> " . $foruminfo ['bbuser_id'];

  $result = dbQuery ($query);   // hopefully OK - need to check each call

  while ($row = dbFetch ($result))
    {
    $notifyname = $row ['username'];
    $notifyemail = $row ['email'];

    $removal = "To edit your notification settings, please click on the link below:\n\n"
             . "  $forum_url/bbuseredit.php?action=amend&bbuser_id=" . $row ['bbuser_id'];

    $removal .= "\n\n";

    // send mail message

    if ($subjectrow ['section_name'] && $subjectrow ['topic_name'])
      $section_note = "This was in the section: " .
                      $subjectrow ['section_name'] .
                      " -> " .
                      $subjectrow ['topic_name'] .
                      "\n\n";
    else
      $section_note = "";

    $notifyemail = $notifyname . " <" . $notifyemail . ">";

    $mailresult =
      SendEmail ($notifyemail,
                 $subject,
                 "Hi $notifyname,\n\n"
               . "$username has $message.\n\n"
               . $section_note
               . "You can view this at:\n\n  $forum_url$link\n\n\n\n"
               . $removal);

    if (!$mailresult)
      Problem ("An error occurred sending an email message");

    } // end of having loop

  dbFree ($result);

  } // end of MailAdmins

function utctime ()
  {
  global $control;
  if ($control ['minuteswest'])
    $minuteswest = $control ['minuteswest'];
  else
    {
    $thetime = gettimeofday ();
    $minuteswest = $thetime ['minuteswest'];
    }
  return time () + ($minuteswest * 60); // add in time-zone correction in minutes
  } // end of utctime

// turns numbers into their ordinal versions (eg. 1 becomes 1st, 23 becomes 23rd)

function ordinal ($number)
  {

  // 12 is 12th not 12nd.

  if ($number >= 10 && $number <= 20)
    $ordinal = "th";
  else
    switch (substr ($number, -1, 1))
      {
      case 1: $ordinal = "st"; break;
      case 2: $ordinal = "nd"; break;
      case 3: $ordinal = "rd"; break;
      default:  $ordinal = "th";
      } // end of switch

  return $number . $ordinal;
  } // end of ordinal

 function checkSQLdate ($thedate, $originalDate)
  {
  $row = dbQueryOneParam ("SELECT DATE_ADD(?, INTERVAL 0 DAY) AS validatedDate",
                          array ('s', &$thedate));

  if (!$row || !$row ['validatedDate'])
    return "Date '$originalDate' ($thedate) is not a valid date.";

  return "";
  } // end of checkSQLdate

// extended date functions
function DoExtendedDate (& $thedate, $defaultEndOfPeriod = false)
  {
  global $MONTHS, $DAYS_IN_MONTHS;

  $originalDate = trim ($thedate);

  // get rid of leading/trailing spaces, make lowercase
  $thedate = trim (strtolower ($thedate));

  // get rid of multiple spaces
  $thedate = str_replace ("  ", " ", $thedate);

  // look for 4 digit year (eg. 1980, 1980s)
  if (preg_match ("|^([0-9]{4})s?$|", $thedate, $matches))
    {
    if ($defaultEndOfPeriod)
      $thedate = $matches [1] . "-12-31";
    else
      $thedate = $matches [1] . "-01-01";
    return "";
    } // end of something like: 1800

  // look for month year (eg. Jan 1980)
  if (preg_match ("|^([A-Za-z]+) ([0-9]{4})$|", $thedate, $matches))
    {
    $month = $matches [1];
    reset ($MONTHS);
    $count = 0;
    while (list ($monthnum, $monthname) = each ($MONTHS))
      {
      // look for partial match - do whole lot in case of ambiguity (eg. ju)
      if ($month == substr ($monthname, 0, strlen ($month)))
        {
        $foundmonth = $monthnum;
        $count++;
        }  // end of found a match
      }  // end of trying each month

    // count of zero means it wasn't amonth, count of > 1 means ambiguous(eg. Ju)
    if ($count == 1)
      {
      // success - convert back and return
      if ($defaultEndOfPeriod)
        $thedate = $matches [2] . "-" . $foundmonth . "-" . $DAYS_IN_MONTHS [$foundmonth];
      else
        $thedate = $matches [2] . "-" . $foundmonth . "-01";
      return "";
      }

    } // end of something like: jan 1800

  // try ISO date, like +1 day, -1 day, next thursday, last monday
  //
  // 1 year
  // 1 year ago
  // 3 years
  // 2 days

  // exclude colons because someone might put a time in a purely date field
  if (strstr ($thedate, ":"))
    return "Date cannot have a colon in it.";

  // we will take a simple number (eg. 23) as a day not a time
  // also exclude straight alphas as it sometimes got "mon" wrong
  if (!preg_match ("|^[0-9]+$|", $thedate) && !preg_match ("|^[A-Za-z]+$|", $thedate))
    {
    // replace slashes with hyphens to force British dates
    $thedate = str_replace ("/", "-", $thedate);
    $converteddate = strtotime ($thedate);

    if ($converteddate)
      {
      // success - convert back and return
      $thedate = strftime ("%Y-%m-%d", $converteddate);
      return "";
      }
    } // end of not simple number

  // if date has hyphens in it, assume already in format 2002-15-02
  if (strstr ($thedate, "-"))
    return "";

  // look for 'today' or 'tomorrow', or some shortened version of either
  if (strlen ($thedate) > 2)
    {

    if ($thedate == substr ('today', 0, strlen ($thedate)) ||
        $thedate == substr ('now', 0, strlen ($thedate))
        )
      {
      $thedate = strftime ("%Y-%m-%d", utctime());
      return "";
      }   // end of today

    if ($thedate == substr ('tomorrow', 0, strlen ($thedate)))
      {
      $thedate = strftime ("%Y-%m-%d", utctime() + (60 * 60 * 24));
      return "";
      }   // end of tomorrow
    }  // end of string length > 2

  if (strstr ($thedate, "/"))
    $items = explode ("/", $thedate);
  else
    $items = explode (" ", $thedate);

  if (count ($items) > 3)
    return "Too many fields in date, maximum of 3 (day/month/year)";

  if (count ($items) < 1)
    return "Date must consist of at least the day (eg. 15)";

  $day = trim($items [0]);

  // look for alpha day name (eg. Monday)
  if (preg_match ("|^[a-z]+$|", $day) && count ($items) < 3)
    {
     $daynames = "";
     $seconds = utctime();
     // find the dates of the next 7 days
     for ($count = 1; $count <= 7; $count++)
       {
       $daynames [strtolower (strftime ("%A", $seconds))] = strftime ("%Y-%m-%d", $seconds);

       // echo ("<p>" . strtolower (strftime ("%A", $seconds)) . " = " . strftime ("%Y-%m-%d", $seconds));

       // let them put in 'Thursday week'
       $daynames_week [strtolower (strftime ("%A", $seconds))]
          = strftime ("%Y-%m-%d", $seconds + (60 * 60 * 24 * 7));
       $seconds += 60 * 60 * 24;  // onwards a day
       }

   // our array now has all 7 days indexed by the day name (eg. Monday)

    reset ($daynames);
    $count = 0;
    while (list ($dayname, $daydate) = each ($daynames))
      {
      // look for partial match - do whole lot in case of ambiguity (eg. t(hursday))
      if ($day == substr ($dayname, 0, strlen ($day)))
        {
        $founddate = $daydate;
        // and pull out a week later
        $founddate_week = $daynames_week [$dayname];
        $count++;
        }  // end of found a match
      }  // end of trying each day

    if ($count == 0)
       return "Day name of \"$day\" not recognised, try 'Monday', 'Tuesday', etc.";
    if ($count > 1)
      return "Day named \"$day\" is ambiguous - please use longer name";

    // found one match - use the corresponding date

    // first see if they followed it by the word 'week'
    if (isset ($items [1]))
      $word = trim($items [1]);
    else
      $word = "";

    if (count ($items) == 2 && $word != "")
      {
      if ($word == substr ('week', 0, strlen ($word)))
        {
        $thedate = $founddate_week;
        return "";
        }   // end of the word week (or an abbreviatio)
      } // end of having a second word

    $thedate = $founddate;
    return "";
    }   // end of alpha day

  // don't let them slip in alphas or other stuff into the middle of a day
  if (!preg_match ("|^[0-9]+$|", $day))
     return "Day must consist of numbers (or 'Monday', 'Tuesday' etc.) - you supplied \"$day\"";

  // get the month
  if (count ($items) > 1)
    $month = trim($items [1]);
  else  // no month? assume current month (or next month if past that date)
        // eg. on 29th March, putting in 2 means 2nd April
    {
    $month = strftime ("%m", utctime());
    $currentday = strftime ("%d", utctime());  // what is today?
    if ($day < $currentday)   // is wanted day earlier? (therefore, next month)
      $month = $month + 1;
    }

  // get the year
  if (count ($items) > 2)
    $year = trim($items [2]);
  else  // no year? assume current year
    {
    $year = strftime ("%Y", utctime());
    // in case we added 1 to current month
    if (preg_match ("|^[0-9]+$|", $month) && $month > 12)
      {
      $year = $year + 1;
      $month = 1;
      }
    }

  // don't let them slip in alphas or other stuff into the middle of a year
  if (!preg_match ("|^[0-9]+$|", $year))
     return "Year must consist of numbers, you supplied \"$year\"";

  // 2-digit year supplied? Assume current century
  if ($year < 100)
    {
    $century = intval (floor (strftime ("%Y", utctime()) / 100)) * 100;
    $year = $year + $century;
    } // end of 2-digit year

  // if non-numeric month, see if we can recognise the month name, either in full or in part
  if (!preg_match ("|^[0-9]+$|", $month))
    {
    reset ($MONTHS);
    $count = 0;
    while (list ($monthnum, $monthname) = each ($MONTHS))
      {
      // look for partial match - do whole lot in case of ambiguity (eg. ju)
      if ($month == substr ($monthname, 0, strlen ($month)))
        {
        $foundmonth = $monthnum;
        $count++;
        }  // end of found a match
      }  // end of trying each month

    if ($count == 0)
      return "Month named \"$month\" not a valid month name, or number";
    if ($count > 1)
      return "Month named \"$month\" is ambiguous - please use longer name";

    $month = $foundmonth;
    } // end of non-numeric month

  $thedate = $year . "-" . $month . "-" . $day;

  // final check - will SQL accept it?
  return checkSQLdate ($thedate, $originalDate);
  } // end of DoExtendedDate

function DoExtendedDateTime (& $thedate)
  {
  $thedate = trim ($thedate);

  // no date? give up
  if ($thedate == "")
    return "";

  // get rid of multiple spaces
  $thedate = str_replace ("  ", " ", $thedate);

  // try ISO date, like +1 day, next thursday, last monday
  //
  // 1 year
  // 1 year ago
  // 3 years
  // 2 days

  // we will take a simple number (eg. 23) as a day not a time
  if (!preg_match ("|^[0-9]+$|", $thedate))
    {
    $converteddate = strtotime ($thedate);
    if ($converteddate)
      {
      // success - convert back and return
      $thedate = strftime ("%Y-%m-%d %H:%M:%S", $converteddate);
      return "";
      }
    } // end of not simple number

  // if no colons let's assume they just typed a date
  if (strstr ($thedate, ":") == 0)
    {
    // extend the date (using my original code)
    return DoExtendedDate ($thedate);
    }

  // see where the last space is
  $i = strrpos ($thedate, " ");
  // see if we have a colon
  $j = strpos  ($thedate, ":");

  $date = "";
  $time = "";

  // if we have a colon we have a time
  if ($j)
    {
    if ($i)
      {
      $date = substr ($thedate, 0, $i); // date is up to last space
      $time = substr ($thedate, $i);    // time is after last space
      }   // end of having a space
    else
      {
      $date = strftime ("%Y-%m-%d", strtotime ("now"));   // assume date today
      $time = $thedate;   // time is whole string
      }   // end of no space
    } // end of date string with a colon in it
  else
    {
    $date = $thedate;   // whole string is date
    } // end of no colon

  // extend the date
  $error = DoExtendedDate ($date);
  if ($error != "")
    return $error;

  // see if we have a time, and if so, process that
  if ($time)
    {

    // extend the date
    $error = DoExtendedTime ($time);
    if ($error != "")
      return $error;
    } // end of having a time too
  else
    $time = "";

  // assemble the fixed date/time
  $thedate = $date . " " . $time;
  return "";  // no error
  } // end of DoExtendedDateTime

function DoExtendedTime(& $thetime)
  {
  // get rid of leading/trailing spaces, make lowercase
  $thetime = trim (strtolower ($thetime));

  // no time? given up
  if ($thetime == "")
    return "";

  // get rid of multiple spaces
  $thetime = str_replace ("  ", " ", $thetime);

  // allow decimal places instead of colons
  $thetime = str_replace (".", ":", $thetime);

  // look for a space
  $items = explode (" ", $thetime);

  // first, let them enter hours only (eg. 11) (convert to 11:00)
  $time = $items [0];
  if (!strstr ($time, ":"))
    $time .= ":00";

  if (count ($items) > 2)
    return "Time must be in format '11', '11:45' or '11:45 am/pm'";

  // look for am/pm
  if (count ($items) == 2)
    $am_pm = trim ($items [1]);
  else
    $am_pm = "";

  // leading zero (eg. 06:30 forces it to be am not pm)
  if (preg_match ("|^0|", $time))
    $am_pm = "am";

  // don't let them slip in alphas or other stuff into the middle of a number
  if (!preg_match ("|^[0-9\:]+$|", $time))
     return "Time must consist of HH:MM or HH:MM:SS";

  // put out hour:minute:second
  $items = explode (":", trim ($time));

  $hour = $items [0];
  if (count ($items) > 1)
    $min = $items [1];
  else
    $min = '00';

  if (count ($items) > 2)
    $sec = $items [2];
  else
    $sec = '00';

  if ($am_pm)
    {
    switch ($am_pm)
      {
      case "am":
      case "a":
        break;    // do nothing

      case "pm":
      case "p":
        if ($hour < 12) // make afternoon
          $hour += 12;
        break;

      default: return "Time must consist of HH:MM am/pm or HH:MM:SS am/pm";
    } // end of switch

  } // end of am/pm
  else
    if ($hour < 8)  // assume a time like 6:30 is 6:30 pm
      $hour += 12;

  if (strlen ($hour) == 1)
    $hour = '0' . $hour;
  $time = $hour . ":" . $min . ":" . $sec;
  $thetime = $time;
  return "";  // no error
  } // end of DoExtendedTime

/*

Audit trail - because some people like abusing the system we will log events
that result in things changing, so we can roll them back or at least see what
they are up to.

eg. user created, posts message, changes his name, changes his email,
deletes a message, adds a thread, deletes a thread, etc.

*/

// audit types

$AUDIT_NEW_USER = 1;
$AUDIT_CHANGED_USER = 2;
$AUDIT_NEW_THREAD = 3;
$AUDIT_NEW_MESSAGE = 4;
$AUDIT_CHANGED_MESSAGE = 5;
$AUDIT_CHANGED_SUBJECT = 6;
$AUDIT_DELETED_MESSAGE = 7;
$AUDIT_DELETED_THREAD = 8;
$AUDIT_SENT_MAIL = 9;
$AUDIT_REQUESTED_PASSWORD = 10;
$AUDIT_CHANGED_PASSWORD = 11;
$AUDIT_VOTED_SPAM = 12;
$AUDIT_RESET_PASSWORD = 13;
$AUDIT_CANCELLED_SPAM_MESSAGE = 14;
$AUDIT_DELETED_USER = 15;
$AUDIT_DEBUGGING_MESSAGE = 16;
$AUDIT_LOGGED_ON = 17;
$AUDIT_LOGGED_OFF = 18;


// audit something they have done
function audit ($bbaudit_type_id,   // what action it is (eg. add, change, delete)
                $bbuser_id,         // who did  it
                $bbpost_id = "",    // which post
                $bbsubject_id = "", // which thread
                $bbtopic_id = "",   // which topic
                $extra = "")        // extras, like the text of the message
  {
  global $dblink;

  $ip = getIPaddress ();

  if (!$bbpost_id)
    $bbpost_id = NULL;
  if (!$bbsubject_id)
    $bbsubject_id = NULL;
  if (!$bbtopic_id)
    $bbtopic_id = NULL;

  $query =  "INSERT INTO bbaudit ("
          . " audit_date, bbaudit_type_id, bbuser_id, bbpost_id, bbsubject_id, bbtopic_id, extra, ip "
          . " ) VALUES ( "
          . "   NOW(),            ?,            ?,        ?,          ?,            ?,       ?,   ? )";

  $count = dbUpdateParam ($query,
    array ('sssssss', &$bbaudit_type_id, &$bbuser_id, &$bbpost_id, &$bbsubject_id, &$bbtopic_id,
                      &$extra, &$ip));
  if ($count == 0)
    Problem ("Could not insert audit record");

  } // end of audit

/* ********************************************************************************
 getIPaddress - find the current user's IP address
 ********************************************************************************  */
function getIPaddress ()
  {
  // try and work out their IP address
  $ip = $_SERVER ['REMOTE_ADDR'];
  if (!$ip)
    $ip = $_ENV ['REMOTE_ADDR'];

  return $ip;
} // end of getIPaddress


// audit types

$TABLE_AUDIT_ADD     = 1;
$TABLE_AUDIT_CHANGE  = 2;
$TABLE_AUDIT_DELETE  = 3;
$TABLE_AUDIT_LOGON   = 4;
$TABLE_AUDIT_LOGOFF  = 5;
$TABLE_AUDIT_ACCESS  = 6;  // access rights change

/* ********************************************************************************
   edittableAudit - saves history database updates (add / change / delete)
   ********************************************************************************  */
function edittableAudit ($audit_type_id, $table, $primary_key, $comment="")
  {
  global $userinfo, $dblink;

  $userid       = $userinfo ['userid'];
  $ip           = getIPaddress ();

  $query =  "INSERT INTO audit ("
          . " audit_date, audit_type_id, audit_table, user_id, ip, primary_key, comment "
          . " ) VALUES ( "
          . "    NOW(),        ?,            ?,          ?,     ?,     ?,          ?  )";

  $count = dbUpdateParam ($query,
    array ('ssssss', &$audit_type_id, &$table, &$userid, &$ip, &$primary_key, &$comment));
  if ($count == 0)
    Problem ("Could not insert audit record");
  } // end of edittableAudit

/* ********************************************************************************
   SaveOneRecord - gets the SQL needed to replace the changed record
   ********************************************************************************  */
function SaveOneRecord ($table, $primary_key_name, $primary_key)
  {
  global $DATABASE_SERVER, $GENERAL_DATABASE_USER, $GENERAL_DATABASE_NAME, $GENERAL_DATABASE_PASSWORD;
  global $control;

  $mysqldump = $control ['mysqldump'];
  $sql = array ();

  exec ("$mysqldump -u'$GENERAL_DATABASE_USER' " .
      " -p'$GENERAL_DATABASE_PASSWORD' " .
      " -h'$DATABASE_SERVER' " .
      " '$GENERAL_DATABASE_NAME' '$table' " .
      " --where=\"$primary_key_name='$primary_key'\" " .
      " --skip-add-drop-table --skip-add-locks --skip-comments " .
      " --skip-disable-keys -t -c ",
      $sql, $returnvar);

  if ($returnvar)
    Problem ("Got error $returnvar executing mysqldump to save undo information");

  // skip comments, blank lines
  for ($i = 0; $i < count ($sql); $i++)
    if (trim ($sql [$i]) && substr (trim ($sql[$i]), 0, 2) != '/*')
      break;

  return $sql [$i];
  } // end of SaveOneRecord

/* ********************************************************************************
   edittableWriteUndo - writes the SQL needed to replace the changed record
   ********************************************************************************  */
function edittableWriteUndo ($audit_type_id, $table, $primary_key, $sql )
  {
  global $userinfo, $dblink;

  $userid       = $userinfo ['userid'];
  $ip           = getIPaddress ();

  $query =  "INSERT INTO undo_data ("
          . " undo_date, audit_type_id, undo_table, user_id, ip, primary_key, saved_sql "
          . " ) VALUES ( "
          . "    NOW(),      ?,              ?,        ?,     ?,      ?,         ?   )";


  $count = dbUpdateParam ($query,
      array ('ssssss', &$audit_type_id, &$table, &$userid, &$ip, &$primary_key, &$sql ));
  if ($count == 0)
    Problem ("Could not insert undo record");
  } // end of edittableWriteUndo

function showBacktrace ($howFarBack = 1)
  {
  echo "<hr><b>Backtrace</b>\n";

  echo "<ol>\n";
  $bt = debug_backtrace ();
  $count = sizeof($bt);
  for ($i = $howFarBack; $i < $count; $i++)
    {
    $item = $bt [$i];
    echo "<li>\n";
    echo "<ul>\n";
    echo ("<li>" . "Function: "     . htmlspecialchars ($item ['function'], ENT_SUBSTITUTE | ENT_QUOTES | ENT_HTML5));
    echo ("<li>" . "Called from: "  . htmlspecialchars ($item ['file'], ENT_SUBSTITUTE | ENT_QUOTES | ENT_HTML5));
    echo ("<li>" . "Line: "         . htmlspecialchars ($item ['line'], ENT_SUBSTITUTE | ENT_QUOTES | ENT_HTML5));
    echo "</ul><p>\n";
    }
  echo "</ol>\n";
  echo "<hr>\n";
  }   // end of showBacktrace

function showSQLerror ($sql)
  {
  global $dblink;
  global $control;

  if ((isset ($control ['show_sql_problems']) && $control ['show_sql_problems'])
      || isAdminOrModerator ())
    {
    echo "<hr>\n";
    echo "<h2><font color=darkred>Problem with SQL</font></h2>\n";
    echo (htmlspecialchars (mysqli_error ($dblink), ENT_SUBSTITUTE | ENT_QUOTES | ENT_HTML5));
    echo "<hr>\n";
    bTable (1);
    bRow ();
    echo "<td><mono>\n";
    echo (htmlspecialchars ($sql, ENT_SUBSTITUTE | ENT_QUOTES | ENT_HTML5). "\n");
    echo "</mono></td>\n";
    eRow ();
    eTable ();
    showBacktrace (2);
    }

  // bail out
  Problem ("SQL statement failed.");
  } // end of showSQLerror

// Do a database query that returns a single row
// return that row, or false (doesn't need freeing)
// (eg. SELECT ... FROM) where you expect a single result
function dbQueryOne ($sql)
  {
  global $dblink;

  $result = mysqli_query ($dblink, $sql);
  // false here means a bad query
  if (!$result)
    showSQLerror ($sql);

  $row = dbFetch ($result);
  dbFree ($result);

  // Debugging of SQL statements

  if (isSQLdebugger () && preg_match ("/^[ ]*SELECT /i", $sql))
    {
    $sql_result = mysqli_query ($dblink, 'EXPLAIN ' . $sql);
    // false here means a bad query
    if (!$sql_result)
      showSQLerror ('EXPLAIN ' . $sql);
    $explain_results = array ();
    while ($sqlRow = dbFetch ($sql_result))
      $explain_results [] = $sqlRow;
    $sql_evaluations [] = array ( 'sql' => $sql, 'explanation' => $explain_results );
    dbFree ($sql_result);
    }  // end of administrator

  return $row;
  }  // end of dbQueryOne

// Do a database query that returns a single row
// return that row, or false (doesn't need freeing)
// (eg. SELECT ... FROM) where you expect a single result

function dbQueryOneParam ($sql, $params)
  {
  $results = dbQueryParam ($sql, $params, 1);
  if (count ($results) > 0)
    return $results [0];
  return false;
  }  // end of dbQueryOneParam

// Do a database query that updates the database.
// eg. UPDATE, INSERT INTO, DELETE FROM etc.
// Doesn't return a result.
function dbUpdate ($sql, $showError = true)
  {
  global $dblink;

  $result = mysqli_query ($dblink, $sql);
  // false here means a bad query
  if (!$result && $showError)
    showSQLerror ($sql);
  }  // end of dbUpdate

// Do a database query that updates the database.
// eg. UPDATE, INSERT INTO, DELETE FROM etc.
// Returns the number of affected rows.
// First array element in $params is a string containing field types (eg. 'ssids')
//   i  corresponding variable has type integer
//   d  corresponding variable has type double
//   s  corresponding variable has type string
// Subsequent elements are the parameters, passed by REFERENCE.
function dbUpdateParam ($sql, $params, $showError = true)
  {
  global $dblink;

  $stmt = mysqli_prepare ($dblink, $sql);
  // false here means a bad query
  if (!$stmt)
    showSQLerror ($sql);

  if (count ($params) > 1)
    if (!call_user_func_array (array($stmt, 'bind_param'), $params))
      showSQLerror ($sql);

  if (!mysqli_stmt_execute ($stmt) && $showError)
    showSQLerror ($sql);

  $count = mysqli_stmt_affected_rows ($stmt);

  mysqli_stmt_close ($stmt);

  return $count;
  }  // end of dbUpdateParam

// Do a database query that returns multiple rows
// return the result variable which must later be freed
function dbQuery ($sql)
  {
  global $dblink;
  global $sql_evaluations;

  $result = mysqli_query ($dblink, $sql);
  // false here means a bad query
  if (!$result)
    showSQLerror ($sql);

  if (isSQLdebugger () && preg_match ("/^[ ]*SELECT /i", $sql))
    {
    $sql_result = mysqli_query ($dblink, 'EXPLAIN ' . $sql);
    // false here means a bad query
    if (!$sql_result)
      showSQLerror ('EXPLAIN ' . $sql);
    $explain_results = array ();
    while ($sqlRow = dbFetch ($sql_result))
      $explain_results [] = $sqlRow;
    $sql_evaluations [] = array ( 'sql' => $sql, 'explanation' => $explain_results );
    dbFree ($sql_result);
    }  // end of administrator

  return $result;
  }  // end of dbQuery

function dbQueryParam_helper ($sql, $params, $max_rows = -1)
  {
  global $dblink;

  $stmt = mysqli_prepare ($dblink, $sql);
  // false here means a bad query
  if (!$stmt)
    showSQLerror ($sql);

  if (count ($params) > 1)
    if (!call_user_func_array (array($stmt, 'bind_param'), $params))
      showSQLerror ($sql);

  if (!mysqli_stmt_execute ($stmt))
    showSQLerror ($sql);

  mysqli_stmt_store_result ($stmt);

  $row = array ();    // array of names/values to return
  $output = array (); // simple array to hold each result

  // get field names, build into zero-based array
  $meta = mysqli_stmt_result_metadata ($stmt);
  while ($field = mysqli_fetch_field($meta))
  {
  $row [$field->name] = 0;
  $output[] = &$row [$field->name];
  }

  // bind the output to the array we built
  if (!call_user_func_array(array($stmt, 'bind_result'), $output))
    showSQLerror ($sql);

  $results = array ();
  $row_count = 0;

  // fetch all the rows
  while (mysqli_stmt_fetch($stmt))
    {
    $item = array ();
    // have to copy the values, otherwise everything ends up being the last one
    foreach ($row as $k => $v)
      $item [$k] = $v;
    $results [] = $item;
    $row_count++;
    // stop inadvertently getting lots of rows when only one is wanted
    if ($max_rows > -1 && $row_count >= $max_rows)
      break;
    } // end of while each row

/*   if ($max_rows > -1 && $row_count > $max_rows)
      {
      ShowWarning ("Too many rows ($row_count) returned for dbQueryOneParam");
      showSQLerror ($sql);
      }
*/

  mysqli_stmt_close ($stmt);
  return $results;

  } // end of dbQueryParam_helper

// Do a database query that returns multiple rows
// Returns an ARRAY of the resulting rows. Nothing needs to be freed later.
// First array element is a string containing field types (eg. 'ssids')
//   i  corresponding variable has type integer
//   d  corresponding variable has type double or decimal
//   s  corresponding variable has type string
// Subsequent elements are the parameters, passed by REFERENCE.
//   eg.  dbQueryOneParam ("SELECT * FROM functions WHERE name = ?", array ('s', &$name));
function dbQueryParam ($sql, $params, $max_rows = -1)
  {
  global $sql_evaluations;

  $results = dbQueryParam_helper ($sql, $params, $max_rows);

  // Debugging of SQL statements

  if (isSQLdebugger () && !preg_match ("/^[ ]*SHOW /i", $sql))
    {
    $explain_results = dbQueryParam_helper ('EXPLAIN ' . $sql, $params);  // no limit on rows
    $sql_evaluations [] = array ( 'sql' => $sql, 'explanation' => $explain_results );
    } // end of isAdmin


  return $results;
  }  // end of dbQueryParam

// fetches one row from the result returned by dbQuery
// glue routine in case we switch to PostGRE or something
function dbFetch ($result)
  {
  if (!($result instanceof mysqli_result))
    {
    showBacktrace (1);
    Problem ("Incorrect 'result' field passed to dbFetch");
    }

  return mysqli_fetch_array ($result);
  } // end of dbFetch

// gets the number of rows in the result returned by dbQuery
// glue routine in case we switch to PostGRE or something
function dbRows ($result)
  {
  if (!($result instanceof mysqli_result))
    {
    showBacktrace (1);
    Problem ("Incorrect 'result' field passed to dbRows");
    }

  return mysqli_num_rows ($result);
  } // end of dbRows

// gets the number of rows affected by dbUpdate
// glue routine in case we switch to PostGRE or something
function dbAffected ()
  {
  global $dblink;
  return mysqli_affected_rows ($dblink);
  } // end of dbAffected

// gets the key of a new row created by INSERT INTO
// glue routine in case we switch to PostGRE or something
function dbInsertId ()
  {
  global $dblink;
  return mysqli_insert_id ($dblink);
  } // end of dbInsertId

// seeks into the result set
// glue routine in case we switch to PostGRE or something
function dbSeek ($result, $position)
  {
  if (!($result instanceof mysqli_result))
    {
    showBacktrace (1);
    Problem ("Incorrect 'result' field passed to dbSeek");
    }

  mysqli_data_seek ($result, $position);
  } // end of dbSeek

// frees the result returned by dbQuery
// glue routine in case we switch to PostGRE or something
function dbFree ($result)
  {
  if (!($result instanceof mysqli_result))
    {
    showBacktrace (1);
    Problem ("Incorrect 'result' field passed to dbFree");
    }

  mysqli_free_result ($result);
  } // end of dbFree

// general function for getting a count of something

function GetSQLcount ($query, $select = "SELECT count(*) FROM ")
  {
  $row = dbQueryOne ($select . $query);  // uncertain - need to check these
  $count = $row [0];
  return ($count);
  } // end of GetSQLcount

function fixsql ($sql)
  {
  global $dblink;

  return mysqli_real_escape_string ($dblink, $sql);
  } // end of fixsql

function validateArgument ($name, $value, $maxLength, $validation)
  {
  $value = trim ($value);
  if ($maxLength > 0 && strlen ($value) > $maxLength)
    Problem ("Parameter '$name' is too long");
  if (strlen ($value) && $validation)
    {
    if (!preg_match ("\xFF" . $validation . "\xFF" . 'i', $value))
      {
//      if (isAdminOrModerator ())
//        showBacktrace (2);
      Problem  ("Parameter '$name' is not in the expected format (unexpected characters).");
      }
    }
  return $value;
  } // end of validateArgument

function getGPC ($name, $maxLength = 0, $validation = "")
  {
  if (isset ($_GET [$name]))
    return validateArgument ($name, $_GET [$name], $maxLength, $validation);
  if (isset ($_POST [$name]))
    return validateArgument ($name, $_POST [$name], $maxLength, $validation);
  if (isset ($_COOKIE [$name]))
    return validateArgument ($name, $_COOKIE [$name], $maxLength, $validation);
  return false;
  }  // getGPC

function getGP ($name, $maxLength = 0, $validation = "")
  {
  if (isset ($_GET [$name]))
    return validateArgument ($name, $_GET [$name], $maxLength, $validation);
  if (isset ($_POST [$name]))
    return validateArgument ($name, $_POST [$name], $maxLength, $validation);
  return false;
  }  // getGP

function getPGC ($name, $maxLength = 0, $validation = "")
  {
  if (isset ($_POST [$name]))
    return validateArgument ($name, $_POST [$name], $maxLength, $validation);
  if (isset ($_GET [$name]))
    return validateArgument ($name, $_GET [$name], $maxLength, $validation);
  if (isset ($_COOKIE [$name]))
    return validateArgument ($name, $_COOKIE [$name], $maxLength, $validation);
  return false;
  }  // getPGC

function getPG ($name, $maxLength = 0, $validation = "")
  {
  if (isset ($_POST [$name]))
    return validateArgument ($name, $_POST [$name], $maxLength, $validation);
  if (isset ($_GET [$name]))
    return validateArgument ($name, $_GET [$name], $maxLength, $validation);

  return false;
  }  // getPG

function getP ($name, $maxLength = 0, $validation = "")
  {
  if (isset ($_POST [$name]))
    return validateArgument ($name, $_POST [$name], $maxLength, $validation);

  return false;
  }  // getP

function getG ($name, $maxLength = 0, $validation = "")
  {
  if (isset ($_GET [$name]))
    return validateArgument ($name, $_GET [$name], $maxLength, $validation);

  return false;
  }  // getG

function isAdmin ()
 {
 global $foruminfo;
 return isset ($foruminfo ['admin']) && $foruminfo ['admin'];
 } // end of isAdmin

function isGlobalModerator ()
 {
 global $foruminfo;
 return isset ($foruminfo ['global_moderator']) && $foruminfo ['global_moderator'];
 } // end of isGlobalModerator

function isAdminOrModerator ($bbsection_id = 0, $bbtopic_id = 0)
{
  global $foruminfo, $headingrow;

  if (!$bbsection_id && isset ($headingrow) && isset ($headingrow ['bbsection_id']) )
    $bbsection_id = $headingrow ['bbsection_id'];

  if (!$bbtopic_id  && isset ($headingrow) && isset ($headingrow ['bbtopic_id']) )
    $bbtopic_id = $headingrow ['bbtopic_id'];

  if (!isset ($foruminfo) || !$foruminfo)
    return false;

  if (isAdmin () || isGlobalModerator ())
    return true;

  if (isset ($foruminfo ['moderator_topic']) && isset ($bbtopic_id))
    if ($bbtopic_id && $foruminfo ['moderator_topic'] == $bbtopic_id)
      return true;

  if (isset ($foruminfo ['moderator_section']) && isset ($bbsection_id))
    if ($bbsection_id && $foruminfo ['moderator_section'] == $bbsection_id)
      return true;

  return false;
} // end of isAdminOrModerator

function hasUnlimitedPostLength ()
  {
  global $foruminfo, $headingrow;

  if (!isset ($foruminfo) || !$foruminfo)
    return false;

  if (isAdminOrModerator ())
    return true;

  if ($foruminfo ['unlimited_post_length'])
    return true;

  return false;

  } // end of hasUnlimitedPostLength

function isSubjectAuthor ()
{
  global $foruminfo, $subjectrow;

  if (!isset ($foruminfo) || !$foruminfo)
    return false;

  if (!isset ($subjectrow) || !$subjectrow)
    return false;

  if (!isset ($foruminfo ['bbuser_id']))
    return false;

  if (!isset ($subjectrow ['author']))
    return false;

  return $foruminfo ['bbuser_id'] == $subjectrow ['author'];
} // end of isAuthor

function isLoggedOn ()
  {
  global $userinfo;

  if (!isset ($userinfo) || !$userinfo || !isset ($userinfo ['logged_on']))
    return false;

  return $userinfo ['logged_on'];
  } // end of isLoggedOn

function isServerAdministrator ()
  {
  global $userinfo;

  if (!isset ($userinfo) || !$userinfo || !isset ($userinfo ['server_administrator']))
    return false;

  return $userinfo ['server_administrator'];
  } // end of isServerAdministrator

function isLoggedOnToForum ()
  {
  global $foruminfo;

  if (!isset ($foruminfo) || !$foruminfo)
    return false;

  return $foruminfo ['bbuser_id'];
  } // end of isLoggedOnToForum

function isSQLdebugger ()
  {
  return isAdmin () || isServerAdministrator ();  // possibly also: isGlobalModerator ()
  } // end of isSQLdebugger

function beingThrottled ($basis = 'minutes_since_last_post', $last_date = 'last_post_date')
  {
  global $foruminfo;
  global $NEW_USER_THROTTLE_MINUTES, $NEW_USER_DAYS_REGISTERED, $NEW_USER_MINIMUM_POST_COUNT;

  $date_now = strftime ("%Y-%m-%d %H:%M:%S", utctime());

//  echo "\n<!-- Inside: beingThrottled, basis = '$basis', date_now = $date_now, last_date = '$last_date' -->\n";

  $bt = debug_backtrace ();
  $item = $bt [0];

//  echo "<!-- Called from: "  . $item ['file'] . ", Line: " . $item ['line'] . " -->\n";

  // not logged on, must not post
  if (!isLoggedOnToForum ())
    {
//    echo "<!-- Not loggged on -->\n";
    return $NEW_USER_THROTTLE_MINUTES;
    }

  // admins and moderators are not throttled
  if (isAdminOrModerator ())
    {
//    echo "<!-- Is moderator -->\n";
    return 0;
    }

  // trusted users won't be throttled
  if ($foruminfo ['trusted'])
    return 0;

  $days_on = $foruminfo ['days_on'];
  $count_posts = $foruminfo ['count_posts'];

//  echo "<!-- days_on = $days_on, count_posts = $count_posts -->\n";

  // if been logged on long enough and made enough posts
  if ($days_on > $NEW_USER_DAYS_REGISTERED &&
      $count_posts > $NEW_USER_MINIMUM_POST_COUNT)
    {
//    echo "<!-- Passed initial tests: days_on > $NEW_USER_DAYS_REGISTERED && count_posts > $NEW_USER_MINIMUM_POST_COUNT -->\n";
    return 0;
    }

  $minutes_basis = $foruminfo [$basis];
  $date_test = $foruminfo [$last_date];

//  echo "<!-- minutes_basis = $minutes_basis -->\n";
//  echo "<!-- date_test = $date_test -->\n";

  // if they have not made any posts, we can't throttle them as there is no known
  // time elapsed since the previous one
  if (!$date_test)
    {
//    echo "<!-- No posts made on test basis. -->\n";
    return 0;
    }

  $throttleTime = $NEW_USER_THROTTLE_MINUTES;

  // calculate proportional throttle time, eg. if you have made 29/30 posts you will be
  // throttled 1/30 of the full time

  // if made not many posts, we will hold that against them
  if ($count_posts <= $NEW_USER_MINIMUM_POST_COUNT)
    $throttleTime1 = $NEW_USER_THROTTLE_MINUTES * (1 - ($count_posts / $NEW_USER_MINIMUM_POST_COUNT));
  else
    $throttleTime1 = 0;

//  echo "<!-- throttleTime1 = $throttleTime1 -->\n";

  // if joined recently, we will hold that against them too
  if ($days_on <= $NEW_USER_DAYS_REGISTERED)
    $throttleTime2 = $NEW_USER_THROTTLE_MINUTES * (1 - ($days_on / $NEW_USER_DAYS_REGISTERED));
  else
    $throttleTime2 = 0;

//  echo "<!-- throttleTime2 = $throttleTime2 -->\n";

  // take the higher one - to make them wait the maximum time
  $throttleTime = max ($throttleTime1, $throttleTime2);

//  echo "<!-- throttleTime = $throttleTime -->\n";

  $time_to_wait = $throttleTime - $minutes_basis;
//  echo "<!-- time_to_wait = $time_to_wait -->\n";

  // if posted recently, cannot post again
  if ($time_to_wait > 0)
    {
//    echo "<!-- they have to $time_to_wait minutes. -->\n";
    return $time_to_wait;
    }

//  echo "<!-- OK to post -->\n";

  // not being throttled
  return 0;

  } // end of beingThrottled

function canUpdate ()
{
 global $access;
 return isset ($access ['can_update']) && $access ['can_update'] && !ServerReadOnly ();
} // end of canUpdate

function canInsert ()
{
 global $access;
 return isset ($access ['can_insert']) && $access ['can_insert'] && !ServerReadOnly ();
} // end of canInsert

function canDelete ()
{
 global $access;
 return isset ($access ['can_delete']) && $access ['can_delete'] && !ServerReadOnly ();
} // end of canDelete

function canEdit ()
{
 global $userinfo;
 return isset ($userinfo ['edittable']) && $userinfo ['edittable'] && !ServerReadOnly ();
} // end of canEdit

function getTz ()
{
  global $foruminfo;

  if (isset ($foruminfo ['time_zone']))
    return $foruminfo ['time_zone'];

  return 0;  // not logged in? Assume UTC
}

function nl2br_http ($text)
  {
  return str_replace ("\n", "<br>", $text);
  } // end of nl2br_http

function ServerReadOnly ()
{
 return (is_file (str_replace ("//", "/",
  $_SERVER['DOCUMENT_ROOT'] . '/ReadOnly.txt')));
} // end of ServerReadOnly

function ServerPublic ()
{
 return (is_file (str_replace ("//", "/",
  $_SERVER['DOCUMENT_ROOT'] . '/PublicServer.txt')));
} // end of ServerPublic

/* ********************************************************************************
 IsReadOnly - shows a message if the server is read-only (the backup server)
 ********************************************************************************  */
function IsReadOnly ($align = 'left')
  {

    /*
  if (ServerPublic ())
    {
    echo ("<p style=\"text-align:$align; color:saddlebrown; font-size:x-small;\">Public server.</p>");
    return true;
    }
  */

  if (ServerReadOnly ())
    {
    echo ("<p style=\"text-align:$align; color:saddlebrown; font-size:x-small;\">This is the stand-by server. It is read-only.</p>");
    return true;
  }
  return false;
} // end of IsReadOnly

/* ********************************************************************************
 ShowBackupDays - shows number of days since the last backup
 ********************************************************************************  */
function ShowBackupDays ()
  {
  global $control;

  /*
    find when last backup
  */

  $last_backup_time = $control ['last_backup'];

  /*
    calculate days since last backup
  */

  $query = "SELECT TO_DAYS(NOW()) - TO_DAYS(?) AS day_count";

  $row = dbQueryOneParam ($query, array ('s', &$last_backup_time));

  $days_since_backup = $row ['day_count'];
  $when = duration ($days_since_backup);

  if ($days_since_backup > 6)
    echo "<p style=\"color:red; \"><b>Last off-site backup $when.</b></p>";
  else
    echo "<p style=\"color:darkgreen; font-size:x-small;\">Last off-site backup $when.</p>";

  } // end of Show_Backup_Days

/* ********************************************************************************
 ShowMessage - shows a message (in HTML) stored in the control file
 ********************************************************************************  */
function ShowMessage ($which)
  {
  global $control;

  $row = dbQueryOneParam ("SELECT * FROM message WHERE Item_Name = ?",
                          array ('s', &$which));

  if ($row)
    {
    $colour = $row ['Box_Colour'];
    if ($colour == 'message')
      $colour = $control ['colour_message'];

    $html = $row ['HTML'];

    // put into a table to make a nice box if wanted
    if ($colour)
      {
      bTable (0);
      echo "<tr style=\"vertical-align:middle; background-color:$colour; \">\n";
      echo "<td>\n";
      }

    echo (str_replace ('<h1></h1>', '', $html . "\n"));

    // close the box
    if ($colour)
      echo "</td></tr></table>\n";
    }
  else
    echo "<p><em>Warning</em>: Message " . htmlspecialchars ($which, ENT_SUBSTITUTE | ENT_QUOTES | ENT_HTML5) . " does  not exist.\n";

  if (isLoggedOn ())
    echo ("<p style=\"text-align:right;\"><span style=\"font-size:smaller; color:gray;\">[$which]</span></p>\n");
  } // end of ShowMessage

/* ********************************************************************************
 SendEmail - sends an email with the appropriate mail headers added
 ********************************************************************************  */
function SendEmail ($recipient, $subject, $message)
{
  global $control;

  $fromEmail = $control ['email_from'];
  $signature = $control ['email_signature'];

  // find email domain
  preg_match ("|@(.*)$|", $fromEmail, $matches);

  // make up a unique message id
  $message_id = '<' .
                time () .
                '-' .
                substr (md5 (rand()), 1, 15) .
                '-' .
                substr (md5($fromEmail . $recipient), 1, 15) .
                '@' . $matches [1] .
                '>';
  return
     mail ($recipient,
           $subject,
           $message . "\r\n\r\n" . $signature . "\r\n",
            // mail header
            "From: $fromEmail\r\n"
          . "Reply-To: $fromEmail\r\n"
          . "Content-Type: text/plain\r\n"
          . "Message-Id: $message_id\r\n"
          . "X-Mailer: PHP/" . phpversion(),
            "-f$fromEmail"   // envelope-sender
            );
}  // end of sendEmail

/* ********************************************************************************
 MakeToken - token generation for security purposes
 ********************************************************************************  */
function MakeToken ()
  {
  // get 128 pseudorandom bits in a string of 16 bytes
  $fp = @fopen ('/dev/urandom', 'rb');
  if ($fp !== FALSE)
    {
    $pr_bits = @fread ($fp, 16);
    fclose ($fp);
    return (bin2hex ($pr_bits));
    }

  // after PHP 5.3.0:
  if (function_exists ('openssl_random_pseudo_bytes'))
     return bin2hex (openssl_random_pseudo_bytes (16));

  // fallback
  return (md5 (uniqid (rand ())));
  } // end of MakeToken

/* ********************************************************************************
 MakeUpdateStatement - makes an update statement for a particular row
 ********************************************************************************  */
function MakeUpdateStatement ($table, $row)
{
 // get the field names
  $names = array ();
  $namesResult = dbQuery ("SHOW COLUMNS FROM " . $table);  // internally generated, hopefully

  while ($nameRow = dbFetch ($namesResult))
      $names [$nameRow ['Field']] = preg_match ('|int|i', $nameRow ['Type']);

  dbFree ($namesResult);

  $result = "UPDATE `$table` SET ";

  reset ($names);
  $count = 0;

  while (list ($fieldName, $isNumber) = each ($names))
    {
    if ($count)
      $result .= ", ";
    $data = $row [$fieldName];

    $result .= "`$fieldName` = ";

    if (is_null ($data))
      $result .=  "NULL";
    else if ($isNumber)
      $result .= $data;
    else
      {
      $data = fixsql ($data);
      $result .= "'$data'";
      }

    $count++;
    } // end of while each field

  return $result;
} // end of MakeUpdateStatement

/* ********************************************************************************
 MakeInsertStatement - makes an insert statement for a particular row
 ********************************************************************************  */
function MakeInsertStatement ($table, $row)
{
 // get the field names
  $names = array ();
  $namesResult = dbQuery ("SHOW COLUMNS FROM " . $table);  // internally generated, hopefully
  while ($nameRow = dbFetch ($namesResult))
      $names [$nameRow ['Field']] = preg_match ('|int|i', $nameRow ['Type']);

  dbFree ($namesResult);

  $result = "INSERT INTO `$table` (";

  reset ($names);
  $count = 0;

  // output the field names
  while (list ($fieldName, $isNull) = each ($names))
    {
    if ($count)
      $result .= ", ";
    $result .= "`$fieldName`";
    $count++;
    } // end of while each field

  $result .= ") VALUES (";

  reset ($names);
  $count = 0;

  // and now the values
  while (list ($fieldName, $isNumber) = each ($names))
    {
    if ($count)
      $result .= ", ";

    $data = $row [$fieldName];

    if (is_null ($data))
      $result .= "NULL";
    else if ($isNumber)
      $result .= $data;
    else
      {
      $data = fixsql ($data);
      $result .= "'$data'";
      }

    $count++;
    } // end of while each field

  $result .= ")";

  return $result;
} // end of MakeInsertStatement

/* ********************************************************************************
  ShowSqlResult - show the results of an SQL query
 ********************************************************************************  */
function ShowSqlResult ($result)
  {
  if (dbRows ($result) > 0)
    {
    bTable ();

    // column names

    bRow ("lightblue");
    $alignments = array ();
    for ($i = 0; $i < mysqli_num_fields ($result); $i++)
    {
      $fieldInfo = mysqli_fetch_field ($result);

      // work out whether to right-align based on field type
      // see: http://www.php.net/manual/en/mysqli.constants.php
      $align = 'left';
      switch ($fieldInfo->type)
        {
        case MYSQLI_TYPE_DECIMAL:
        case MYSQLI_TYPE_NEWDECIMAL:
        case MYSQLI_TYPE_TINY:
        case MYSQLI_TYPE_SHORT:
        case MYSQLI_TYPE_LONG:
        case MYSQLI_TYPE_FLOAT:
        case MYSQLI_TYPE_DOUBLE:
        case MYSQLI_TYPE_LONGLONG:
          $align = 'right';
          break;
        }
      $alignments [] = $align;
      tHead ($fieldInfo->name);
    }
    eRow ();

    while ($row = mysqli_fetch_row ($result))
      {
      // row data
      bRow ("azure");
      for ($i = 0; $i < mysqli_num_fields ($result); $i++)
        {
        $value = $row [$i];
        if (!isset ($value))
          $value = "-";
        tData ($value, -1, $alignments [$i]);
        }
      eRow ();

      }   // end of doing each row

    eTable ();

    } // end of having rows to display

  } // end of ShowSqlResult

function ConvertMarkup ($value, $outputName = 'HTML', $headerLevel = 2, $toc = '')
  {
  global $control;

  // where it is
  $pandocProg = $control ['pandoc'];
  $pandocOptions = $control ['pandoc_options'];
  // check we found it
  if (!is_file ($pandocProg))
    $error = "Cannot find pandoc";
  else

    {
    $cmd = "$pandocProg $pandocOptions " .
           "--from=markdown " .
           "--base-header-level=$headerLevel " .
           "$toc ".
           "--to=html5";

    $descriptorspec = array(
       0 => array("pipe", "r"),  // stdin is a pipe that the child will read from
       1 => array("pipe", "w"),  // stdout is a pipe that the child will write to
       2 => array('pipe', 'w')   // stderr is a pipe that the child will write to
    );

    $process = proc_open($cmd, $descriptorspec, $pipes);

    if (is_resource($process))
      {
      fwrite($pipes[0], $value);
      fclose($pipes[0]);

      $_POST [$outputName] = stream_get_contents($pipes[1]);
      fclose($pipes[1]);

      $error = stream_get_contents($pipes[2]);
      fclose($pipes[2]);

      $return_value = proc_close($process);
      }  // end of process opened OK
    else
      $error = "Cannot invoke process";
    }  // end of found pandoc program

    return $error;
} // end of ConvertMarkup

/*
PROGRESS BAR GENERATOR
----------------------

Arguments:

  width:      Width of window in pixels
  height:     Height of window in pixels (at least 25) - 18 is used for the text (name) area and borders
  name:       Name of bar (eg. Health points)
  colour:     Colour of active bar (HTML colour name, or #hhhhhh colour code)
  backcolour: Colour of bar background (inactive part) - HTML colour name, or #hhhhhh colour code)
  current:    A number representing the current value (eg. 80 percent)
  maximum:    A number representing the maximum value (eg. 100 percent)

At present this gives you:

 *  2 pixels of transparent above the text
 * 14 pixels of text
 *  1 pixel of transparent between the text and the bar
 *  (height - 18) pixels of bar (2 pixels each of black at the top and bottom)
 *  1 pixel of transparent under the bar

Thus the minimal height of 25 gives you a bar with only 3 pixels of colour (plus 2 of black at the top and bottom).

Note that the bar should be long enough to hold the name (the current and maximum are appended to the name).

*/

function ProgressBar ($width, $height, $name, $colour, $backcolour, $current, $maximum)
  {
  $strokeWidth = 2;
  $textTop = 12;
  $barTop = 17;
  $barHeight = $height - $barTop - $strokeWidth - 1;
  $barLeft = 2;
  $barWidth = $width - 4;
  $roundAmount = 4;

  echo "<svg width=\"$width\" height=\"$height\" >\n";

  // entire bar in background colour
  echo "<rect x=\"$barLeft\" y=\"$barTop\" width=\"$barWidth\" height=\"$barHeight\" " .
       "fill=\"$backcolour\" ry=\"$roundAmount\" " .
       "stroke=\"none\" />\n";

  // now draw over with "current" amount
  if ($maximum == 0)
    $currentWidth = 0;
  else
    $currentWidth = ceil ($current / $maximum * $barWidth);
  echo "<rect x=\"$barLeft\" y=\"$barTop\" width=\"$currentWidth\" height=\"$barHeight\" " .
       "fill=\"$colour\" ry=\"$roundAmount\" " .
       "stroke=\"none\" />\n";

  // background rectangle
  echo "<rect x=\"$barLeft\" y=\"$barTop\" width=\"$barWidth\" height=\"$barHeight\" " .
       "fill=\"none\" ry=\"$roundAmount\" " .
       "stroke=\"black\" stroke-width=\"$strokeWidth\" />\n";

  // text on top
  $description = htmlspecialchars ("$name ($current / $maximum)");
  echo "<text style=\"fill:black; font-size:10.5pt; font-family:Arial\" " .
       "x=\"$barLeft\" y=\"$textTop\">$description</text>\n";

  // will be shown if SVG tag not supported
  echo "Sorry, your browser does not support inline SVG.\n";

  echo "</svg>\n";

  } // end of ProgressBar

function openSVGfile ($filename, $labelRow)
{
  $handle = fopen ($filename, "w");

  if (!$handle)
    MajorProblem ("Cannot open file: $filename");

  $width  = $labelRow ['Page_Width'] . 'mm';
  $height = $labelRow ['Page_Height'] . 'mm';

  fwrite ($handle, <<< EOD
    <svg
       xmlns="http://www.w3.org/2000/svg"
       xmlns:xlink="http://www.w3.org/1999/xlink"
       version="1.1"
       viewBox="0 0 $width $height"
       width="$width"
       height="$height" >

  <!-- SVG generated in PHP

    Author:  Nick Gammon
    Written: 23rd April 2016

EOD
);

  // timestamp
  fwrite ($handle, "\n    This file generated on: " . strftime ("%A %d %B %Y at %I:%M:%S %p", time ()));
  fwrite ($handle, "\n\n  -->\n\n");
  return $handle;
}   // end of openSVGfile

function checkHandle ($handle)
  {
  if (gettype ($handle) != 'resource' || get_resource_type ($handle) != 'stream')
    {
    showBacktrace (2);
    MajorProblem ("Handle supplied to SVGrect is not a stream");
    }
  } // end of checkHandle

function SVGcomment ($handle, $comment)
  {
  checkHandle ($handle);
  fwrite ($handle, "<!-- $comment -->\n");
  } // end of SVGcomment

function SVGrect ($handle, $args)
  {
  checkHandle ($handle);

  $defaults = array (
    'x'             => 0,
    'y'             => 0,
    'width'         => 10,
    'height'        => 10,
    'units'         => 'px',
    'strokeColour'  => 'black',
    'strokeWidth'   => 1,
    'fillColour'    => 'none',
    'ry'            => 0,
     );

  $args = array_merge($defaults, array_intersect_key($args, $defaults));

  fwrite ($handle, "<rect " .
               "x=\""             . $args ['x']       . $args ['units'] . "\" " .
               "y=\""             . $args ['y']       . $args ['units'] . "\" " .
               "width=\""         . $args ['width']   . $args ['units'] . "\" " .
               "height=\""        . $args ['height']  . $args ['units'] . "\" " .
               "fill=\""          . $args ['fillColour'] . "\" " .
               "stroke-width=\""  . $args ['strokeWidth'] . "\" " .
               "ry=\""            . $args ['ry'] . "\" " .
               "stroke=\""        . $args ['strokeColour'] . "\" " .
               "/>\n");
  } // end of SVGrect

function SVGline ($handle, $args)
  {
  checkHandle ($handle);

  $defaults = array (
    'x1'            => 0,
    'y1'            => 0,
    'x2'            => 10,
    'y2'            => 10,
    'units'         => 'px',
    'colour'        => 'black',
    'strokeWidth'   => 1,
     );

  $args = array_merge($defaults, array_intersect_key($args, $defaults));

  fwrite ($handle, "<line " .
               "x1=\""            . $args ['x1']      . $args ['units'] . "\" " .
               "y1=\""            . $args ['y1']      . $args ['units'] . "\" " .
               "x2=\""            . $args ['x2']      . $args ['units'] . "\" " .
               "y2=\""            . $args ['y2']      . $args ['units'] . "\" " .
               "stroke-width=\""  . $args ['strokeWidth'] . "\" " .
               "stroke=\""        . $args ['colour']  . "\" " .
               "/>\n");
  } // end of SVGline

// position can be: start / middle / end / inherit
function SVGtext ($handle, $args)
  {
  checkHandle ($handle);

  $defaults = array (
    'x'             => 0,
    'y'             => 0,
    'units'         => 'px',
    'text'          => '',
    'colour'        => 'black',
    'fontSize'      => 9,
    'fontFamily'    => 'Arial',
    'position'      => 'start',   // start / middle / end / inherit
     );

  $args = array_merge($defaults, array_intersect_key($args, $defaults));

  fwrite ($handle, "<text " .
                   "style=\"fill:"    . $args ['colour'] . "; " .
                   "font-size:"       . $args ['fontSize'] . "pt; " .
                   "font-family:"     . $args ['fontFamily'] . "\" " .
                   "x=\""             . $args ['x']       . $args ['units'] . "\" " .
                   "y=\""             . $args ['y']       . $args ['units'] . "\" " .
                   "text-anchor=\""   . $args ['position'] . "\">" .
                   htmlspecialchars ($args ['text']) . "</text>\n");
  } // end of SVGtext

// shows a duration in more human-readable ways
function duration ($days)
  {
  if ($days == 0)
    return "today";
  if ($days == -1)
    return "tomorrow";
  if ($days == 1)
    return "yesterday";

  if ($days > 0)
    $direction = "ago";
  else
    {
    $direction = "in the future";
    $days = -$days;
    }

  if ($days < 14)
    return sprintf ("%d days $direction", $days);

  if ($days < 60)
    return sprintf ("%d weeks $direction", $days / 7);

  if ($days < (365 * 2))
    return sprintf ("%d months $direction", $days / 12);

  return sprintf ("%d years $direction", $days / 362.25);

  } // end of duration

function validateEmail ($email)
  {

// See: http://nikic.github.io/2012/06/15/The-true-power-of-regular-expressions.html

$regexp =
'(?(DEFINE)' .
'  (?<addr_spec> (?&local_part) @ (?&domain) )' .
'  (?<local_part> (?&dot_atom) | (?&quoted_string) | (?&obs_local_part) )' .
'  (?<domain> (?&dot_atom) | (?&domain_literal) | (?&obs_domain) )' .
'  (?<domain_literal> (?&CFWS)? \[ (?: (?&FWS)? (?&dtext) )* (?&FWS)? \] (?&CFWS)? )' .
'  (?<dtext> [\x21-\x5a] | [\x5e-\x7e] | (?&obs_dtext) )' .
'  (?<quoted_pair> \\ (?: (?&VCHAR) | (?&WSP) ) | (?&obs_qp) )' .
'  (?<dot_atom> (?&CFWS)? (?&dot_atom_text) (?&CFWS)? )' .
'  (?<dot_atom_text> (?&atext) (?: \. (?&atext) )* )' .
'  (?<atext> [a-zA-Z0-9!#$%&\'*+/=?^_`{|}~-]+ )' .
'  (?<atom> (?&CFWS)? (?&atext) (?&CFWS)? )' .
'  (?<word> (?&atom) | (?&quoted_string) )' .
'  (?<quoted_string> (?&CFWS)? " (?: (?&FWS)? (?&qcontent) )* (?&FWS)? " (?&CFWS)? )' .
'  (?<qcontent> (?&qtext) | (?&quoted_pair) )' .
'  (?<qtext> \x21 | [\x23-\x5b] | [\x5d-\x7e] | (?&obs_qtext) )' .
'' .
"  # comments and whitespace\n" .
'  (?<FWS> (?: (?&WSP)* \r\n )? (?&WSP)+ | (?&obs_FWS) )' .
'  (?<CFWS> (?: (?&FWS)? (?&comment) )+ (?&FWS)? | (?&FWS) )' .
'  (?<comment> \( (?: (?&FWS)? (?&ccontent) )* (?&FWS)? \) )' .
'  (?<ccontent> (?&ctext) | (?&quoted_pair) | (?&comment) )' .
'  (?<ctext> [\x21-\x27] | [\x2a-\x5b] | [\x5d-\x7e] | (?&obs_ctext) )' .
'' .
"  # obsolete tokens\n" .
'  (?<obs_domain> (?&atom) (?: \. (?&atom) )* )' .
'  (?<obs_local_part> (?&word) (?: \. (?&word) )* )' .
'  (?<obs_dtext> (?&obs_NO_WS_CTL) | (?&quoted_pair) )' .
'  (?<obs_qp> \\ (?: \x00 | (?&obs_NO_WS_CTL) | \n | \r ) )' .
'  (?<obs_FWS> (?&WSP)+ (?: \r\n (?&WSP)+ )* )' .
'  (?<obs_ctext> (?&obs_NO_WS_CTL) )' .
'  (?<obs_qtext> (?&obs_NO_WS_CTL) )' .
'  (?<obs_NO_WS_CTL> [\x01-\x08] | \x0b | \x0c | [\x0e-\x1f] | \x7f )' .
'' .
"  # character class definitions\n" .
'  (?<VCHAR> [\x21-\x7E] )' .
'  (?<WSP> [ \t] )' .
")    # end of DEFINE\n" .
'^(?&addr_spec)$   # the actual validator';


  $delimiter = "\xFF";
  return preg_match ($delimiter . $regexp . $delimiter . 'x', $email);
  }   // end of validateEmail

function getForumURL ()
  {
  global $control;
  $forum_url = $control ['forum_url'];
  // put the "http:" part back for emails
  if (substr ($forum_url, 0, 2) == "//")
    $forum_url = "http:" . $forum_url;
  return $forum_url;
  } // end of getForumURL

// return an interval in days in human-readable form, as a string
//  eg. 1 day ago, 3 weeks ago, 5 months away, 3.2 years ago

function getInterval ($days)
  {
  if ($days == 0)
    return 'today';

  if ($days < 0)
    {
    $ago = ' ago';
    $days = - $days;
    }
  else
    $ago = ' away';  // i.e. in the future

  if ($days == 1)
    return '1 day' . $ago;

  if ($days <= 31)
    return $days . ' days' . $ago;

  $months = floor ($days / 30.42);

  if ($months == 1)
    return '1 month' . $ago;

  if ($months <= 12)
    return $days . ' months' . $ago;

  $years = $days / 365.25;

  return sprintf ("%0.1f", $years) . ' years' . $ago;

  } // end of getInterval

function passwordCheck ($pass, $username = "")
  {
  $MINIMUM_LENGTH = 10;
  $MINIMUM_NUMBERS = 2;
  $MINIMUM_UC_LETTERS = 2;
  $MINIMUM_LC_LETTERS = 2;
  $MINIMUM_PUNCTUATION = 2;
  $MAXIMUM_REPEATED_CHARACTER = 4;
  $MAXIMUM_SEQUENCE = 3;
  $PUNCTUATION = "~!@#$%^&*()_+`-={}|[]\:\";'<>?,./";

  if (strlen ($pass) < $MINIMUM_LENGTH)
    return "Password must be at least $MINIMUM_LENGTH characters";

  // array of counts of occurrences of first 256 characters
  $counts = array ();
  for ($i = 0; $i < 256; $i++)
    $counts [$i] = 0;

  // other counts
  $numberCount = 0;
  $lowerCaseLetterCount = 0;
  $upperCaseLetterCount = 0;
  $punctuationCount = 0;

  // look for too many of the same character anywhere in the password (eg. 1111 or abababababab)
  // also count letters, numbers, punctuation
  for ($i = 0; $i < strlen ($pass); $i++)
    {
    $c = substr ($pass, $i, 1);  // get this character
    if ($c >= '0' && $c <= '9')
      $numberCount++;
    if ($c >= 'a' && $c <= 'z')
      $lowerCaseLetterCount++;
    if ($c >= 'A' && $c <= 'Z')
      $upperCaseLetterCount++;
    if (strspn ($c, $PUNCTUATION) > 0)
      $punctuationCount++;
    $ci = ord ($c);
    if ($ci >= 0 && $ci < 256)
      {
      $counts [$ci] ++;
      if ($counts [$ci] > $MAXIMUM_REPEATED_CHARACTER)
        {
        if ($c == ' ')
          $c = "<space>";
        else if ($ci < 0x20)
          $c = printf ("0x%02x", $ci);
        return "Password has more than $MAXIMUM_REPEATED_CHARACTER of the same character ($c)";
        }
      }
    }

  // generate all sequences (eg. 123, 234, 345, abc, bcd, cde etc.)
  $sequences = array ();
  // letters
  for ($i = ord ('a'); $i <= (ord ('z') - $MAXIMUM_SEQUENCE + 1); $i++)
    {
    $sequence = '';
    for ($j = 0; $j < $MAXIMUM_SEQUENCE; $j++)
      $sequence .= chr ($i + $j);  // going up
    $sequences [] = $sequence ;
    } // end of for each letter

  // numbers
  for ($i = ord ('0'); $i <= (ord ('9') - $MAXIMUM_SEQUENCE + 1); $i++)
    {
    $sequence = '';
    for ($j = 0; $j < $MAXIMUM_SEQUENCE; $j++)
      $sequence .= chr ($i + $j);  // going up
    $sequences [] = $sequence ;
    }

  // check for a sequence, or a reversed sequence
  foreach ($sequences as $sequence)
    {
    if (preg_match ("/$sequence/i", $pass, $matches))
      return "Password contains the ascending sequence: " . $matches [0];
    $sequence = strrev ($sequence);
    if (preg_match ("/$sequence/i", $pass, $matches))
      return "Password contains the descending sequence: " . $matches [0];
    }   // for each sequence we made earlier

  // same thing in a row
  $sequences = array ();
  for ($i = 0x20; $i <= 0x7F; $i++)  // all printable
    {
    $sequence = '';
    for ($j = 0; $j < $MAXIMUM_SEQUENCE; $j++)
      $sequence .= chr ($i);  // all the same
    $sequences [] = $sequence ;
    }

  foreach ($sequences as $sequence)
    {
    // can't use regexp because of characters like "(" that will be generated.
    $match = stristr ($pass, $sequence);
    if ($match !== FALSE)
      return "Password contains the repeated sequence: " . substr ($match, 0, 3);
    }   // for each sequence we made earlier

  // see: https://www.troyhunt.com/only-secure-password-is-one-you-cant/
  // Some not entered here because they would be caught by other rules (eg. "1111111")
  $dictionary = array (
        "pass", "word", "root", "crypt",
        "qwert", "wert", "erty", "tyui", "zxcv", "yuio", "uiop", "asdf", "xcvb", "cvbn",  // keyboard sequences
        "letmein", "dvcfghyt", "r00tk1t", "guru",
        "1qaz2wsx", "zaq1xsw2", // diagonal keyboard sequences

        // and these from: http://www.passwordrandom.com/most-popular-passwords
        "password", "qwerty", "dragon", "pussy", "baseball", "football", "letmein",
        "monkey", "696969", "abc123", "mustang", "michael", "shadow", "master",
        "jennifer", "jordan", "superman", "harley", "1234567", "fuckme", "hunter",
        "fuckyou", "trustno1", "ranger", "buster", "thomas", "tigger", "robert",
        "soccer", "fuck", "batman", "test", "pass", "killer", "hockey", "george",
        "charlie", "andrew", "michelle", "love", "sunshine", "jessica", "asshole",
        "6969", "pepper", "daniel", "access", "123456789", "654321", "joshua",
        "maggie", "starwars", "silver", "william", "dallas", "yankees", "123123",
        "ashley", "hello", "amanda", "orange", "biteme", "freedom", "computer",
        "sexy", "thunder", "nicole", "ginger", "heather", "hammer", "summer",
        "corvette", "taylor", "fucker", "austin", "merlin", "matthew", "121212",
        "golfer", "cheese", "princess", "martin", "chelsea", "patrick", "richard",
        "diamond", "yellow", "bigdog", "secret", "asdfgh", "sparky", "cowboy",
        "correct", "horse", "battery", "staple"   // LOL: https://xkcd.com/936/
        );

  // check to see if dictionary word can be found, forwards or backwards
  foreach ($dictionary as $word)
    {
    if (preg_match ("/$word/i", $pass))
      return "Part of password ($word) is in a dictionary of common passwords";
    $revword = strrev ($word);
    if (preg_match ("/$revword/i", $pass))
      return "Part of password ($word) is in a dictionary of common passwords (reversed)";
    } // for each dictionary word

  // check minimum number of digits
  $s = $MINIMUM_NUMBERS == 1 ? '' : 's';
  if ($numberCount < $MINIMUM_NUMBERS)
    return "Password must contain at least $MINIMUM_NUMBERS number$s (0-9)";

  // check minimum number of lower-case letters
  $s = $MINIMUM_LC_LETTERS == 1 ? '' : 's';
  if ($lowerCaseLetterCount < $MINIMUM_LC_LETTERS)
    return "Password must contain at least $MINIMUM_LC_LETTERS lower-case letter$s (a-z)";

  // check minimum number of upper-case letters
  $s = $MINIMUM_UC_LETTERS == 1 ? '' : 's';
  if ($upperCaseLetterCount < $MINIMUM_UC_LETTERS)
    return "Password must contain at least $MINIMUM_UC_LETTERS upper-case letter$s (A-Z)";

  // check minimum number of punctuation characters
  $s = $MINIMUM_PUNCTUATION == 1 ? '' : 's';
  if ($punctuationCount < $MINIMUM_PUNCTUATION)
    return "Password must contain at least $MINIMUM_PUNCTUATION punctuation character$s out of these: $PUNCTUATION";

  // disallow things like "nickgammon555" - to stop people appending dates etc. after their password
  if (preg_match ("/[0-9]$/", $pass))
    return "Password must not end with a number";

  // check for username hidden inside password
  if ($username)
    {
    for ($i = 0; $i < strlen ($username) - 4; $i++)
      {
      $word = substr ($username, $i, 4);  // get 4 characters of name
      if (stristr ($pass, $word) !== FALSE)
        return "Part of your username ($word) is inside the password";
      $revword = strrev ($word);
      if (stristr ($pass, $revword) !== FALSE)
        return "Part of your username ($word) is inside the password (reversed)";
      } // end of checking each 4 characters
    } // end if have a username

  return "";    // OK
  } // end of passwordCheck
?>
