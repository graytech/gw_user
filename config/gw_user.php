<?php  if ( ! defined('BASEPATH')) exit('No direct script access allowed');

// Table Names
$config['gw_user_table'] = 'users';
$config['gw_user_rolls_table'] = 'user_rolls';

// Session Key Names
$config['gw_guid_session_key'] = 'guid';
$config['gw_userinfo_session_key'] = 'userinfo';
$config['gw_rolls_session_key'] = 'userrolls';

// Rolls Configuration
$config['gw_user_rolls'] = array(
	'user',
	'administrator',
	'superuser'
);
$config['gw_user_default_roll'] = 'user';