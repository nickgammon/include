<?php

/*

    registration_preamble
    citation_book_postamble
    citation_item_postamble
    citation_project_postamble
    notes_postamble
    user_postamble
    citation_item_beforeform
    message_beforeform

      
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
global $import, $importdata, $key, $value, $HTTP_POST_VARS;

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
            $HTTP_POST_VARS ['username'] = trim ($token [1]); break;
        case "## Registration":  
            $HTTP_POST_VARS ['regcode'] = trim ($token [1]); break;
        case "## Email":         
             $HTTP_POST_VARS ['email'] = trim ($token [1]); break;
        case "## Product":       
             $HTTP_POST_VARS ['productid'] = trim ($token [1]); break;
        
        } // end of switch on token
       
      }  // end of processing each line
    
    $action = "add";
    } // import stuff

}  // end of metatable_registration_preamble




// ========================================================
// postamble
// ========================================================


// --------------------------------------------------------
// metatable_citation_book_postamble - (table: citation_book)
//     Executed after the record is shown, and after Add/Change/Delete buttons.
// --------------------------------------------------------

function metatable_citation_book_postamble ()
{

hLink ("Show citation projects", "/hms/citations.php");

}  // end of metatable_citation_book_postamble


// --------------------------------------------------------
// metatable_citation_item_postamble - (table: citation_item)
//     Executed after the record is shown, and after Add/Change/Delete buttons.
// --------------------------------------------------------

function metatable_citation_item_postamble ()
{

if (isset ($_GET ['Citation_Project_ID']))
    $Citation_Project_ID = $_GET ['Citation_Project_ID'];
  else if (isset ($_POST ['Citation_Project_ID']))
    $Citation_Project_ID = $_POST ['Citation_Project_ID'];
  else
    $Citation_Project_ID = 0;
  
  if ($Citation_Project_ID)
      hLink ("Show citations in current project", "/hms/citations.php?id=$Citation_Project_ID");
  else
      hLink ("Show citations", "/hms/citations.php");

}  // end of metatable_citation_item_postamble


// --------------------------------------------------------
// metatable_citation_project_postamble - (table: citation_project)
//     Executed after the record is shown, and after Add/Change/Delete buttons.
// --------------------------------------------------------

function metatable_citation_project_postamble ()
{

hLink ("Show citation projects", "/hms/citations.php");

}  // end of metatable_citation_project_postamble



// --------------------------------------------------------
// metatable_notes_postamble - (table: notes)
//     Executed after the record is shown, and after Add/Change/Delete buttons.
// --------------------------------------------------------

function metatable_notes_postamble ()
{
global $primary_key;

if ($primary_key)
    echo "<p><a href=\"/hms/notes.php?id=$primary_key\">Show this note</a>";

}  // end of metatable_notes_postamble





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
// metatable_citation_item_beforeform - (table: citation_item)
//     Executed before showing a form.
// --------------------------------------------------------

function metatable_citation_item_beforeform ()
{
global $ADMIN_DIRECTORY;

global $ADMIN_DIRECTORY;
  echo "<p>";
  
  hLink ("Add&nbsp;new&nbsp;book",
         $ADMIN_DIRECTORY . "edittable.php",
         "table=citation_book&new=1&simple=1&desc=Add%20book");
  echo "</p>";

}  // end of metatable_citation_item_beforeform




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
