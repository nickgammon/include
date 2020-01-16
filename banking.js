<script type="text/javascript">

/*

Banking reconciliation support

Author: Nick Gammon
Date: 16th January 2020

This supplies some helper stuff for fiddling with the CSV file that is downloaded from
the CBA site for bank accounts. It is included in "Beforeform" for the metatable for "bank",
like this:

    global $INCLUDE_DIRECTORY;
    echo (file_get_contents ($INCLUDE_DIRECTORY . "banking.js"));

A button is added to the bank form in the "Postamble" for the metatable for "bank", with a
handler like this:

  onclick="doReconciliation()"

Basically it tries to split up the data from the bank which is amount / date / description separated by
tabs, and put them into the three relevant fields on the form (amount / date_paid / description) as well
as setting "reconciled" to 1 and checked.

*/

function doReconciliation ()
  {
  descriptions = document.getElementsByName ("description");
  description = descriptions [1];  // descriptions [0] is in the document header
  amounts = document.getElementsByName ("amount");
  amount = amounts [0];
  dates_paid = document.getElementsByName ("date_paid");
  date_paid = dates_paid [0];
  reconcileds = document.getElementsByName ("reconciled");
  reconciled = reconcileds [0];

  // find the description contents
  content = description.value;
  fields = content.split ('\t');  // from the bank file they are split at tabs

  // if not 3 separate fields, doesn't look right (amount / date / description)
  if (fields.length != 3)
    {
    alert ("This does not appear to be a tab-delimited description from the bank transactions download");
    return;
    } // end of not 3 fields

  amount.value = fields [0];
  date_paid.value = fields [1];
  description.value = fields [2];
  reconciled.value = 1; // mark reconciled
  reconciled.checked = true;
  description.focus ();   // put focus back on description so we can edit it
  description.select ();  // and select all of it
  } // end of function doReconciliation

</script>
