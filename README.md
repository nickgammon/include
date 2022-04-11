include
=======

This repository contains one file: common.php

These are the "common" functions which are used by various parts of the system (eg. to upload an image) and are included into each relevant file, like this:


````php
require ("config.php");  // this has the location of the config file (ie. $CONFIG_PATH)
require ($CONFIG_PATH . "general_config.php"); // This has the path variables: $INCLUDE_DIRECTORY and $HHS_INCLUDE_DIRECTORY 
require ($INCLUDE_DIRECTORY . "common.php");   // General common functions
````
