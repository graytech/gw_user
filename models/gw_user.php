<?php if ( ! defined('BASEPATH')) exit('No direct script access allowed');
/**
 * User Access System
 * @copyright 2012, Grayworld Media, LLC. All rights reserved.
 */
 
/**
 * User Object Access Model Class
 * 
 * Handles all access control and user management.
 * 
 * @author gkales
 *
 */
class Gw_user extends CI_Model {

	protected $user_table;
	protected $rolls_table;
	protected $secret;
	protected $sess_login_key;
	protected $sess_userinfo_key;
	protected $sess_rolls_key;
	protected $userinfo;
	protected $rolls = false;
	
	/**
	 * Constructor
	 */
	public function __construct() {
		parent::__construct();
		$this->ci = get_instance();
		$this->ci->load->config('config');
		$this->ci->load->config('gw_user');
		$this->load->library('session');
		$this->load->database();
		$this->user_table = $this->db->dbprefix('users');
		$this->rolls_table = $this->db->dbprefix('user_rolls');
		$this->secret = $this->ci->config->item('encryption_key');
		$this->sess_login_key = $this->ci->config->item('gw_guid_session_key');
		$this->sess_rolls_key = $this->ci->config->item('gw_rolls_session_key');
		$this->secret = $this->ci->config->item('encryption_key');
		$this->upgrade();
	}
	
	// Login Controls
	
	/**
	 * Login Method
	 * 
	 * Logs in the current user session.
	 * 
	 * @param string $username
	 * @param string $password
	 */
	public function login($username=null, $password=null) {
		$this->logout();
		if (!$user_id = $this->getuid($username)) {
			return false;
		}
		$users = $this->search(array(
			'user_id'	=> $user_id,
			'password'	=> $password
		));
		if (count($users) > 0) {
			$user = $users[0];
			
			$this->get_rolls($user->user_id);
			// get auth id
			$this->update(array(
				'username'		=> $user->username,
				'last_access'	=> date('Y-m-d H:i:s'),
				'last_ip'		=> $this->get_ip_address()
			));	
			$session_value = $this->mk_session_value(array(
				$user->user_id,
				$user->username,
				$user->email
			));
			// set session entry
			$this->session->set_userdata($this->sess_login_key, $session_value);
			return true;
		} else {
			$this->logout();
			return false;
		}
	}
	
	/**
	 * Logout Method
	 * 
	 * Logs out the current user session.
	 */
	public function logout() {
		// remove session entry
		$this->session->unset_userdata($this->sess_login_key);
		$this->rolls = false;
	}
	
	// Access Queries
	
	/**
	 * Login Check
	 * 
	 * Checks to see if the current user is logged in
	 * 
	 * @return logical - true is logged in, false if not
	 */
	public function loggedin() {
		// check if user is logged in
		$session_value = $this->session->userdata($this->sess_login_key);
		if (is_array($this->decode_session_value($session_value))) {
			return true;
		} else {
			$this->logout();
			return false;
		}
	}
	
	/**
	 * Is Member of a Role
	 * 
	 * checks to see if the current user session is a member of a role.
	 * 
	 * @param string $roll
	 * @return logical - true if member, false if not member
	 */
	public function ismember($roll=null) {
		if (!is_null($roll)) {
			if (!$user_id = $this->getuid()) {
				return false;
			}
			$rolls_count = $this->db
				->where('roll', $roll)
				->where('user_id', $user_id)
				->get($this->rolls_table)
				->num_rows();
			if ($rolls_count == 0) {
				return false;
			} else {
				return true;
			}
		}
	}
	
	// Rolls Controls
	
	/**
	 * Add a user to a role
	 * 
	 * Adds a user to a role. If no role exists, it is created.
	 * If no role is supplied, the user is added to the global user role.
	 * If a username is not supplied then the current user session
	 * is used.
	 * 
	 * @param string $roll
	 * @param string $username
	 */
	public function add_roll($roll='user', $username=null) {
		if (!$user_id = $this->getuid($username)) {
			return false;
		}
		$rolls_count = $this->db
			->where('roll', $roll)
			->where('user_id', $user_id)
			->get($this->rolls_table)
			->num_rows();
		if ($rolls_count == 0) {
			$this->db->insert($this->rolls_table, array(
				'created' 	=> date('Y-m-d H:i:s'),
				'user_id' 	=> $user_id,
				'roll'		=> $roll
			));
			return true;
		} else {
			return false;
		}
	}
	
	/**
	 * Remove a user form a role
	 * 
	 * Removes a user from a role.
	 * If no role is supplied, the user is removed to the global user role.
	 * If a username is not supplied then the current user session
	 * is used.
	 * 
	 * @param string $roll
	 * @param string $username
	 */
	public function remove_user_roll($roll='user', $username=null) {
		if (!$user_id = $this->getuid($username)) {
			return false;
		}
		$rolls_count = $this->db
			->where('roll', $roll)
			->where('user_id', $user_id)
			->delete($this->rolls_table);		
		return true;
	}
	
	/**
	 * Get roles for a user
	 * 
	 * Get an array of roles a user belongs to.
	 * If no user is supplied, the current user session is used.
	 * 
	 * @param string $username
	 */
	public function get_rolls($username=null) {
		if (!$user_id = $this->getuid($username)) {
			return array();
		}
		$result = $this->db
			->where('user_id', $user_id)
			->get($this->rolls_table)
			->result();
		$rolls = array();
		foreach ($results as $entry) {
			$rolls[] = $entry->roll;
		}
		if (is_null($username)) {
			$this->session->set_userdata($this->sess_rolls_key, $rolls);
		}
		return $rolls;
	}
	
	/**
	 * Get a list of available roles
	 * 
	 * Returns an array of all available roles in the system
	 */
	public function get_available_rolls() {
		$result = $this->db
			->distinct()
			->get($this->rolls_table)
			->result();
		if ($result) {
			$rolls = array();
			foreach ($result as $entry) {
				$rolls[] = $entry->roll;
			}
			return $rolls;
		} else {
			return false;
		}
	}
	
	/**
	 * Remove a role
	 * 
	 * Remove a role from the system.
	 * 
	 * @param string $roll
	 * @return logical - true on success. false on on fail.
	 */
	public function remove_roll($roll=null) {
		if (!is_null($roll)) {
			$rolls_count = $this->db
				->where('roll', $roll)
				->delete($this->rolls_table);		
			return true;
		} else {
			return false;
		}
	}
	
	/**
	 * Remove all roles
	 * 
	 * Removes all roles form the system.
	 */
	public function remove_all_rolls() {
		$rolls_count = $this->db
			->delete($this->rolls_table);
	}
	
	// User Table Controls
	
	/**
	 * General Search
	 * 
	 * Performs a general search on the user database.
	 * The query is formatted as an array where key/value pairs
	 * reparesent field/query syntax as defined in the CI active recored
	 * deffinition.
	 * 
	 * @param array $query
	 */
	public function search($query=array()) {
		if (isset($query['password'])) {
			$query['password'] = md5($query['password']);
		}
		return $this->db
			->where($query)
			->get($this->user_table)
			->result();
	}
	
	/**
	 * Add a user
	 * 
	 * Adds a user to the system.
	 * @param unknown_type $params
	 */
	public function add($userdata=array()) {
		//print_pre($params);
		// data validation
		$valid_params = array(
			'username',
			'password',
			'email',
			'first_name',
			'last_name'
		);
		$required_params = array(
			'username',
			'password',
			'email',
			'first_name',
			'last_name'
		);
		$clean_status = clean_data($userdata, $valid_params, $required_params);
		$userdata['created'] = date('Y-m-d H:i:s');
		if ($clean_status !== true) {
			return "Missing fields in user add ({$clean_status})";
		}
		// check if user exists
		if (!$this->userexists($userdata['username'])){
			if (isset($userdata['password'])) {
				$userdata['password'] = md5($userdata['password']);
			}
			$this->db->insert($this->user_table, $userdata);
			$this->db->cache_delete();
			return true;
		} else {
			return "User exists ({$userdata['username']})";
		}
	}
	
	/**
	 * Update a user record
	 * 
	 * Updates the record in the user database
	 * 
	 * @param array $userdata
	 */
	public function update($userdata=array()) {
		// data validation
		$valid_params = array(
			'username',
			'password',
			'email',
			'first_name',
			'last_name',
			'last_ip',
			'last_access'
		);
		$required_params = array(
			'username'
		);
		$clean_status = clean_data($userdata, $valid_params, $required_params);
		if ($this->userexists($userdata['username'])){
			if (isset($userdata['password'])) {
				$userdata['password'] = md5($userdata['password']);
			}
			$this->db
				->where('username', $userdata['username'])
				->update($this->user_table, $userdata);
		} else {
			return "User Update Failed! User does not exist ({$userdata['username']})";
		}	
	}
	
	/**
	 * Delete a user
	 * 
	 * Deletes a user record form the user table.
	 * The query is formatted as an array where key/value pairs
	 * reparesent field/query syntax as defined in the CI active recored
	 * deffinition.
	 * 
	 * @param unknown_type $query
	 */
	public function delete($query=null) {
		// data validation
		$valid_params = array(
			'username',
			'password',
			'email',
			'first_name',
			'last_name'
		);
		clean_data($query, $valid_params);
		if (!is_null($query)) {
			$this->db
				->where($query)
				->delete();
		}
	}
	
	/**
	 * Validate a User
	 * 
	 * Verifies that a User/Password pair exists. 
	 * NOTE: This method does not log the session in.
	 * To log a user in, use $this->login()
	 * 
	 * @param string $username
	 * @param string $password
	 * @return logical - true if valid. false if invalid
	 */
	public function validate($username=null, $password=null) {
		$users = $this->db
			->where('username', $username)
			->where('password', md5($password))
			->get($this->user_table)
			->num_rows();
		if ($users > 0) {
			return true;
		} else {
			return false;
		}
	}	
	
	/**
	 * Check if a user exists
	 * 
	 * Checks to see if a user exists in the user table.
	 * 
	 * @param string $username
	 */
	public function userexists($username='') {
		$users = $this->db
			->where('username', $username)
			->get($this->user_table)
			->num_rows();
		if ($users > 0) {
			return true;
		} else {
			return false;
		}
	}
	
	/**
	 * Get a user's information
	 * 
	 * 
	 * 
	 * @param string $username
	 */
	public function userinfo($username=null) {
		if (!is_null($username)) {
			$field = ($this->validEmail($idin)) ? 'email' : 'username';
			$user = $this->db
				->where($field, $username)
				->get($this->user_table)
				->row();
			return $user;
		}
	}
	
	/**
	 * Build Session Value
	 * 
	 * Builds and encodes session value that is used 
	 * to track a user's authentication status.
	 * 
	 * @param array $params
	 * @return string - session value
	 */
	public function mk_session_value($params=null) {
		$value = implode(':', $params);
		$value .= ':'.time();
		$value .= ':'.md5("{$value}:{$this->secret}");
		$value = str_rot13($value);
		return $value;
	}
	
	/**
	 * Decode a Session Value
	 * 
	 * Decodes a session value that is used to 
	 * track a user's authentication status.
	 * 
	 * @param string $session_value
	 * @return array - session elements
	 */
	public function decode_session_value($session_value=null) {
		if (!is_null($session_value)) {
			$session_value = str_rot13($session_value);
			$parts = explode(':', $session_value);
			$hash = array_pop($parts);
			if ($hash == md5(implode(':', $parts).":{$this->secret}")) {
				return $parts;
			} else {
				return false;
			}
		} else {
			return false;
		}
	}
	
	/**
	 * Get a User ID
	 * 
	 * Gets a User's ID based on the supplied username or email address
	 * 
	 * @param string $idin - email or username
	 * @return logical/int - returns an ID on success or false on failure
	 */
	public function getuid($idin=null) {
		if (!is_null($idin)) {
			if (is_string($idin)) {
				$field = ($this->validEmail($idin)) ? 'email' : 'username';
				$user = $this->db
					->select('user_id')
					->where($field, $idin)
					->get($this->user_table)
					->row();
				return (isset($user->user_id)) ? $user->user_id : false;
			} elseif (is_int($idin)) {
				return $idin;
			} else {
				return false;
			}
		} else {
			$user_info = $this->decode_session_value(
				$this->session->userdata($this->sess_login_key)
			);
			if (is_array($user_info)) {
				return ($user_info[0]);
			} else {
				return false;
			}
		}
	}
	
	/**
	 * Get a client's Real IP Address
	 * 
	 * Attempts to determine a cleints REAL IP address
	 * will look for addresses that are behind proxies and shared 
	 * ip envieonments.
	 * 
	 * @return string - ip address
	 */
	protected function get_ip_address() {
		if (!empty($_SERVER['HTTP_CLIENT_IP'])) {  //check ip from share internet
			$ip=$_SERVER['HTTP_CLIENT_IP'];
		} elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR']))  { //to check ip is pass from proxy
			$ip=$_SERVER['HTTP_X_FORWARDED_FOR'];
		} else {
			$ip=$_SERVER['REMOTE_ADDR'];
		}
		return $ip;
	}
	
	/**
	 * Validate an email address
	 * 
	 * Does a comprehensive check on supplied string to determine 
	 * if it is a valid email address.
	 * If $dnscheck is set to true, the method will also verify 
	 * that an MX record exists on the internet for the domain 
	 * portion of the email address.
	 * 
	 * @param string $email
	 * @param logical $dnscheck
	 * @return logical - true if string is an email address else false
	 */
	protected function validEmail($email, $dnscheck = false) {
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
			if ($isValid && $dnscheck && !(checkdnsrr($domain,"MX") || checkdnsrr($domain,"A"))) {
				// domain not found in DNS
				$isValid = false;
			}
		}
		return $isValid;
	}	

	/**
	 * Setup Environment
	 * 
	 * Method used to setup tables and other elements in the environment
	 * so this class will function.
     * 
     * @todo convert table creation to CI SQL-less code
	 */
	protected function setup() {
		if (!$this->db->table_exists($this->user_table)) {
			if (!isset($this->dbforge)) $this->load->dbforge();
			$fields = array(
				'user_id'	=> array(
					'type'	=> 'BIGINT',
					'contraint' => 20,
					'auto_increment' => TRUE
				),
				'created'	=> array(
					'type'	=> 'DATETIME'
				),
				'last_access'	=> array(
					'type'	=> 'DATETIME'
				),
				
			);
			
		}
		if (!$this->db->table_exists($this->rolls_table)) {
			
		}
		if (!$this->db->table_exists($this->rolls_table)) {
			
		}
		$session_table = $this->db->dbprefix(
			$this->ci->config->item('sess_table_name')
		);
		if (!$this->db->table_exists($session_table)) {
			
		}
		
		$this->db->query("
			CREATE TABLE IF NOT EXISTS  {$this->user_table} (
			  user_id bigint(20) NOT NULL AUTO_INCREMENT,
			  created datetime DEFAULT NULL,
			  last_access datetime DEFAULT NULL,
			  last_ip varchar(20) DEFAULT NULL,
			  email varchar(100) DEFAULT NULL,
			  username varchar(100) DEFAULT NULL,
			  password varchar(100) DEFAULT NULL,
			  first_name varchar(50) DEFAULT NULL,
			  last_name varchar(50) DEFAULT NULL,
			  PRIMARY KEY (user_id)
			) ENGINE=InnoDB DEFAULT CHARSET=latin1;
		");
		$this->db->query("
			CREATE TABLE IF NOT EXISTS  {$this->rolls_table} (
			  roll_id bigint(20) NOT NULL AUTO_INCREMENT,
			  created datetime DEFAULT NULL,
			  roll varchar(100) DEFAULT NULL,
			  user_id varchar(100) DEFAULT NULL,
			  PRIMARY KEY (roll_id)
			) ENGINE=InnoDB DEFAULT CHARSET=latin1;
		");
		$this->add(array(
			'username'		=> 'gray',
			'password'		=> 'letmein',
			'email'			=> 'gray@grayworld.com',
			'first_name'	=> 'Gray',
			'last_name'		=> 'Kales'
		));
		$session_table = $this->db->dbprefix(
			$this->ci->config->item('sess_table_name')
		);
		$this->ci->db->query("
			CREATE TABLE IF NOT EXISTS  `{$session_table}` (
				session_id varchar(40) DEFAULT '0' NOT NULL,
				ip_address varchar(45) DEFAULT '0' NOT NULL,
				user_agent varchar(120) NOT NULL,
				last_activity int(10) unsigned DEFAULT 0 NOT NULL,
				user_data text NOT NULL,
				PRIMARY KEY (session_id),
				KEY `last_activity_idx` (`last_activity`)
			);
		");			
		$this->ci->options->set('gw_users_version', '1.0.000');
	}
	
	/**
	 * Update Environment
	 * 
	 * Version based update function used to make sure the environment
	 * is properly setup for the version of this class.
	 */
	protected function upgrade() {
		if (!$version = $this->ci->options->get('gw_users_version', false)) {
			$this->setup();
		}
	}
}