<?php  if ( ! defined('BASEPATH')) exit('No direct script access allowed');
/**
 * GW Tools
 *
 * A set of general use and debugging tools by Grayworld Media, LLC
 *
 * @package		Grayworld
 * @author		Grayworld Media Dev Team
 * @copyright	Copyright (c) 2008 - 2012, Grayworld Media, LLC.
 * @link		http://grayworld.com
 * @since		Version 1.0
 * @filesource
 */

/**
 * Data structure exposer
 * 
 * Displays the data structure for any supplied value
 * 
 * @param 	mixed $var
 * @access	public
 * @return	string
 */
if ( ! function_exists('print_pre')) {
	function print_pre($var, $return=false) {
		$retval = '<pre>'.print_r($var, true).'</pre>';
		if ($return) {
			return $retval;
		} else {
			echo $retval;
		}
	}
}

/**
 * Data cleaner
 * 
 * Cleans data by stripping out unneeded keys 
 * and tells if all required fields where supplied
 */
if ( ! function_exists('clean_data')) {
	function clean_data(&$datain, $allowed_fields=null, $required_fields=null) {
		// remove unused fields
		if (is_array($allowed_fields)) {
			foreach($datain as $key => $values) {
				if (!in_array($key, $allowed_fields)) {
					unset($datain[$key]);
				}
			}
		}
		// check for required fields
		if (is_array($required_fields)) {
			$missing_fields = '';
			foreach ($required_fields as $field) {
				if (!key_exists($field, $datain)) {
					$missing_fields .= ($missing_fields == '') ? $field : ",{$field}";
				}
			}
		}
		if ($missing_fields != '') {
			return $missing_fields;
		} else {
			return true;
		}
	}
}

/**
 * Check for Serialization
 * 
 * Check to see if a string is serialized
 * Returns true if a string is serialized
 */
if ( ! function_exists('is_serialized')) {
	function is_serialized($var=null) {
		if (is_string($var)) {
			return (@unserialize($var) !== false);
		} else {
			return false;
		}	
	}	
}

/**
 * Validate an email address.
 * 
 * Provide email address (raw input)
 * Returns true if the email address has the email 
 * address format and the domain exists.
 */
if ( function_exists('is_vslid_email')) {
	function validEmail($email) {
		$isValid = true;
		$atIndex = strrpos($email, "@");
		if (is_bool($atIndex) && !$atIndex) {
			$isValid = false;
		} else {
			$domain = substr($email, $atIndex+1);
			$local = substr($email, 0, $atIndex);
			$localLen = strlen($local);
			$domainLen = strlen($domain);
			if ($localLen < 1 || $localLen > 64) {
				// local part length exceeded
				$isValid = false;
			} else if ($domainLen < 1 || $domainLen > 255) {
				// domain part length exceeded
				$isValid = false;
			} else if ($local[0] == '.' || $local[$localLen-1] == '.') {
				// local part starts or ends with '.'
				$isValid = false;
			} else if (preg_match('/\\.\\./', $local)) {
				// local part has two consecutive dots
				$isValid = false;
			} else if (!preg_match('/^[A-Za-z0-9\\-\\.]+$/', $domain)) {
				// character not valid in domain part
				$isValid = false;
			} else if (preg_match('/\\.\\./', $domain)) {
				// domain part has two consecutive dots
				$isValid = false;
			} else if (!preg_match('/^(\\\\.|[A-Za-z0-9!#%&`_=\\/$\'*+?^{}|~.-])+$/', str_replace("\\\\","",$local))) {
				// character not valid in local part unless 
				// local part is quoted
				if (!preg_match('/^"(\\\\"|[^"])+"$/',
					str_replace("\\\\","",$local)))
				{
					$isValid = false;
				}
			}
			if ($isValid && !(checkdnsrr($domain,"MX") || checkdnsrr($domain,"A"))) {
				// domain not found in DNS
				$isValid = false;
			}
		}
		return $isValid;
	}	
}

/**
 * Get the clients REAL IP address
 * 
 * This function attempts to determing the clients real ip address
 * it will resolve ips behind proxies and shared connections.
 */
if ( function_exists('get_ip_address')) {
	function get_ip_address() {
		if (!empty($_SERVER['HTTP_CLIENT_IP'])) {  //check ip from share internet
			$ip=$_SERVER['HTTP_CLIENT_IP'];
		} elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR']))  { //to check ip is pass from proxy
			$ip=$_SERVER['HTTP_X_FORWARDED_FOR'];
		} else {
			$ip=$_SERVER['REMOTE_ADDR'];
		}
		return $ip;
	}		
}

