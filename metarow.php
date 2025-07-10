<?php

/*

Meta row entries

  authenticator / AES_key
  authenticator / Public_UID
  authenticator / Secret_UID
  metarow / displaytype
  metarow / fkcolumn
  metarow / fkdescription
  metarow / fktable
  sso_authenticators / AES_key
  sso_authenticators / Public_UID
  sso_authenticators / Secret_UID
    
*/
    
// ========================================================
// validation
// ========================================================
// --------------------------------------------------------
// metarow_authenticator_column_AES_key_validation - (table: authenticator / AES_key) 
//      Executed before attempting to validate fields.
//      Field value is in $value, set $error if there are errors
// --------------------------------------------------------

function metarow_authenticator_column_AES_key_validation (&$value, &$error)
{

if (strlen ($value) != 32)
    $error = "AES key length must be 32 hex characters";
  else
    {
    if (!preg_match ("/^[0-9A-Fa-f]+$/", $value))
      $error = "AES key must be in hex";
    }

}  // end of metarow_authenticator_column_AES_key_validation


// --------------------------------------------------------
// metarow_authenticator_column_Public_UID_validation - (table: authenticator / Public_UID) 
//      Executed before attempting to validate fields.
//      Field value is in $value, set $error if there are errors
// --------------------------------------------------------

function metarow_authenticator_column_Public_UID_validation (&$value, &$error)
{

if (strlen ($value) != 12)
    $error = "Public UID length must be 12 hex characters";
  else
    {
    if (!preg_match ("/^[0-9A-Fa-f]+$/", $value))
      $error = "Public UID must be in hex";
    }

}  // end of metarow_authenticator_column_Public_UID_validation


// --------------------------------------------------------
// metarow_authenticator_column_Secret_UID_validation - (table: authenticator / Secret_UID) 
//      Executed before attempting to validate fields.
//      Field value is in $value, set $error if there are errors
// --------------------------------------------------------

function metarow_authenticator_column_Secret_UID_validation (&$value, &$error)
{

if (strlen ($value) != 12)
    $error = "Secret UID length must be 12 hex characters";
  else
    {
    if (!preg_match ("/^[0-9A-Fa-f]+$/", $value))
      $error = "Secret UID must be in hex";
    }

}  // end of metarow_authenticator_column_Secret_UID_validation




// --------------------------------------------------------
// metarow_metarow_column_displaytype_validation - (table: metarow / displaytype) 
//      Executed before attempting to validate fields.
//      Field value is in $value, set $error if there are errors
// --------------------------------------------------------

function metarow_metarow_column_displaytype_validation (&$value, &$error)
{

if ($value == 11 && !$_POST ['directory']) 
    $error = "Filename types must have an associated directory";

}  // end of metarow_metarow_column_displaytype_validation


// --------------------------------------------------------
// metarow_metarow_column_fkcolumn_validation - (table: metarow / fkcolumn) 
//      Executed before attempting to validate fields.
//      Field value is in $value, set $error if there are errors
// --------------------------------------------------------

function metarow_metarow_column_fkcolumn_validation (&$value, &$error)
{

// must have fktable if we have fkcolumn
  if (empty ($_POST ['fktable'])) 
  $error = "Cannot have a fkcolumn without a fktable";
  // must have fkdescription if we have fkcolumn
  else if (empty ($_POST ['fkdescription'])) 
  $error = "fkdescription must be supplied if you have a foreign key";

}  // end of metarow_metarow_column_fkcolumn_validation


// --------------------------------------------------------
// metarow_metarow_column_fkdescription_validation - (table: metarow / fkdescription) 
//      Executed before attempting to validate fields.
//      Field value is in $value, set $error if there are errors
// --------------------------------------------------------

function metarow_metarow_column_fkdescription_validation (&$value, &$error)
{

// must have fktable if we have fkdescription
  if (empty ($_POST ['fktable'])) 
  $error = "Cannot have a fkdescription without an fktable";
  // must have fkcolumn if we have fkdescription
  else if (empty ($_POST ['fkcolumn'] )) 
  $error = "fkcolumn must be supplied if you have a foreign key";

}  // end of metarow_metarow_column_fkdescription_validation


// --------------------------------------------------------
// metarow_metarow_column_fktable_validation - (table: metarow / fktable) 
//      Executed before attempting to validate fields.
//      Field value is in $value, set $error if there are errors
// --------------------------------------------------------

function metarow_metarow_column_fktable_validation (&$value, &$error)
{

// must have fktable if we have fkcolumn
  if (empty ($_POST ['fkcolumn'])) 
  $error = "Cannot have a fktable without an fkcolumn ";
  // must have fkdescription if we have fkcolumn
  else if (empty ($_POST ['fkdescription'])) 
  $error = "fkdescription must be supplied if you have a foreign key";

}  // end of metarow_metarow_column_fktable_validation




// --------------------------------------------------------
// metarow_sso_authenticators_column_AES_key_validation - (table: sso_authenticators / AES_key) 
//      Executed before attempting to validate fields.
//      Field value is in $value, set $error if there are errors
// --------------------------------------------------------

function metarow_sso_authenticators_column_AES_key_validation (&$value, &$error)
{

if (strlen ($value) != 32)
    $error = "AES key length must be 32 hex characters";
  else
    {
    if (!preg_match ("/^[0-9A-Fa-f]+$/", $value))
      $error = "AES key must be in hex";
    }

}  // end of metarow_sso_authenticators_column_AES_key_validation


// --------------------------------------------------------
// metarow_sso_authenticators_column_Public_UID_validation - (table: sso_authenticators / Public_UID) 
//      Executed before attempting to validate fields.
//      Field value is in $value, set $error if there are errors
// --------------------------------------------------------

function metarow_sso_authenticators_column_Public_UID_validation (&$value, &$error)
{

if (strlen ($value) != 12)
    $error = "Public UID length must be 12 hex characters";
  else
    {
    if (!preg_match ("/^[0-9A-Fa-f]+$/", $value))
      $error = "Public UID must be in hex";
    }

}  // end of metarow_sso_authenticators_column_Public_UID_validation


// --------------------------------------------------------
// metarow_sso_authenticators_column_Secret_UID_validation - (table: sso_authenticators / Secret_UID) 
//      Executed before attempting to validate fields.
//      Field value is in $value, set $error if there are errors
// --------------------------------------------------------

function metarow_sso_authenticators_column_Secret_UID_validation (&$value, &$error)
{

if (strlen ($value) != 12)
    $error = "Secret UID length must be 12 hex characters";
  else
    {
    if (!preg_match ("/^[0-9A-Fa-f]+$/", $value))
      $error = "Secret UID must be in hex";
    }

}  // end of metarow_sso_authenticators_column_Secret_UID_validation



?>
