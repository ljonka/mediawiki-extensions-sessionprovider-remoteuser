<?php

$wgAuthRemoteuserName = isset( $_SERVER["HTTP_AD_DISPLAYNAME"] )
    ? $_SERVER["HTTP_AD_DISPLAYNAME"]
    : '';

/* User's Mail */
$wgAuthRemoteuserMail = isset( $_SERVER["HTTP_AD_MAIL"] )
    ? $_SERVER["HTTP_AD_MAIL"]
    : '';

