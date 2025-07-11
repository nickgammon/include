<?php

/*

    message / beforeform
    registration / preamble
    user / postamble

    */

// ========================================================
// preamble
// ========================================================



// --------------------------------------------------------
// metatable_registration_preamble - (table: registration)
//     Executed before attempting to validate fields.
// --------------------------------------------------------

function metatable_registration_preamble ()
{
global $import, $importdata, $key, $value, $action;

// import stuff from the registration program
  if (!empty ($import))
    {
    if (empty ($importdata))
      Problem ("No data to import");
    $lines = explode ("\r\n", $importdata);

    while (list ($key, $value) = each ($lines))
      {
      if (substr ($value, 0, 2) != '##')
        continue;

      $token = explode (":", $value);

      switch ($token [0])
        {
        case "## Name":
            $_POST ['username'] = trim ($token [1]); break;
        case "## Registration":
            $_POST ['regcode'] = trim ($token [1]); break;
        case "## Email":
             $_POST ['email'] = trim ($token [1]); break;
        case "## Product":
             $_POST ['productid'] = trim ($token [1]); break;

        } // end of switch on token

      }  // end of processing each line

    $action = "add";
    } // import stuff

}  // end of metatable_registration_preamble




// ========================================================
// postamble
// ========================================================




// --------------------------------------------------------
// metatable_user_postamble - (table: user)
//     Executed after the record is shown, and after Add/Change/Delete buttons.
// --------------------------------------------------------

function metatable_user_postamble ()
{
global $field_data, $returnto, $primary_key;

if ($field_data ['userid'] && $returnto)
    {
     echo ('<p><a href="' . $returnto .
           $primary_key .
           '">View this item (' .
           $field_data ['userid'] .
           ') in database</a>');
    }

  echo '<p><a href="/hhs/">Heidelberg Historical Society main page</a>';

}  // end of metatable_user_postamble


// ========================================================
// beforelist
// ========================================================



// ========================================================
// beforeform
// ========================================================



// --------------------------------------------------------
// metatable_message_beforeform - (table: message)
//     Executed before showing a form.
// --------------------------------------------------------

function metatable_message_beforeform ()
{

echo '<p><a href="/hhs/message.php?name=markup" target="_blank">Notes about markdown</a>';

}  // end of metatable_message_beforeform



// ========================================================
// afterform
// ========================================================


// ========================================================
// after_add
// ========================================================






?>
