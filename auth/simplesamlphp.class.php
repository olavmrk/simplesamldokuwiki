<?php
/**
 * simpleSAMLphp authentication plugin
 *
 * @author     Andreas Aakre Solberg, UNINETT, http://www.uninett.no
 */

define('DOKU_AUTH', dirname(__FILE__));
require_once(DOKU_AUTH.'/basic.class.php');

class auth_simplesamlphp extends auth_basic {

    var $users = null;
    var $_pattern = array();


    function auth_simplesamlphp() {
    	$this->cando['external'] = true;

    }

	private static function encodeIllegalChars($input) {
		return preg_replace("/[^a-zA-Z0-9_@=.]/", "_", $input);
	}

	private static function getRealmPart($userid) {

		$decomposedID = explode("@", $userid);
		if (isset($decomposedID[1])) {
			return self::encodeIllegalChars($decomposedID[1]);
		}
		return null;
	}


	function trustExternal($user,$pass,$sticky=false){

		global $USERINFO;
		global $conf;
		$sticky ? $sticky = true : $sticky = false; //sanity check
		
		
		/*
		 * Check for inclusion of libraries etc.
		 */
		if (!array_key_exists('simplesamlphp_path', $conf))
			throw new Exception('Configuration parameter [simplesamlphp_path] was not set. Edit your configuration and check the installation guide.');
		
		$includefile = $conf['simplesamlphp_path'] . '/www/_include.php';
	
		if (!file_exists($includefile)) 
			throw new Exception('Could not read simpleSAMlphp include file: ' . $includefile);
			
		global $SIMPLESAML_INCPREFIX;			
		require_once($includefile);
		require_once((isset($SIMPLESAML_INCPREFIX)?$SIMPLESAML_INCPREFIX:'') . 'SimpleSAML/Utilities.php');
		require_once((isset($SIMPLESAML_INCPREFIX)?$SIMPLESAML_INCPREFIX:'') . 'SimpleSAML/Configuration.php');
		require_once((isset($SIMPLESAML_INCPREFIX)?$SIMPLESAML_INCPREFIX:'') . 'SimpleSAML/Session.php');
		// - - - - - - - - - - - - - - - 
		
		
		/* Load simpleSAMLphp, configuration and metadata */
		$config = SimpleSAML_Configuration::getInstance();
		$session = SimpleSAML_Session::getInstance();
		
		
		
		$authority = 'saml2';
		if (array_key_exists('simplesamlphp_authority', $conf))
			$authority = $conf['simplesamlphp_authority'];
		
		$initsso = 'saml2/sp/initSSO.php';
		if (array_key_exists('simplesamlphp_initsso', $conf))
			$initsso = $conf['simplesamlphp_initsso'];

		$initslo = 'saml2/sp/initSLO.php';
		if (array_key_exists('simplesamlphp_initslo', $conf))
			$initsso = $conf['simplesamlphp_initslo'];
		
		/* Check if valid local session exists.. */
		if (!isset($session) || !$session->isValid($authority) ) {
		
			unset($USERINFO['name']);
			unset($USERINFO['mail']);
			unset($USERINFO['grps']);
			unset($_SERVER['REMOTE_USER']);
			unset($_SESSION[DOKU_COOKIE]['auth']['user']);
			unset($_SESSION[DOKU_COOKIE]['auth']['pass']);
			unset($_SESSION[DOKU_COOKIE]['auth']['info']);
	
			if ($_REQUEST['do'] != 'login' && $conf['requirelogin'] == 'false') {	
				return false;
			}
			
			// Redirect to initialize SSO.
			SimpleSAML_Utilities::redirect(
				'/' . $config->getBaseURL() . $initsso,
				array('RelayState' => SimpleSAML_Utilities::selfURL())
			);
			
		}
		
		global $ACT;
		if ($_REQUEST['do'] == 'logout' || $ACT == 'logout') {
			
			// Initialize Single Sign-Out
			SimpleSAML_Utilities::redirect(
				'/' . $config->getBaseURL() . $initslo, array(
					'RelayState' => SimpleSAML_Utilities::selfURL(),
					'do'         => 'show',
					'nologin'    => 1,
				)
			);
		}
		
		
		$idattr = 'eduPersonPrincipalName';
		if (array_key_exists('simplesamlphp_attr_id', $conf))
			$idattr = $conf['simplesamlphp_attr_id'];
			
		$mailattr = 'mail';
		if (array_key_exists('simplesamlphp_attr_mail', $conf))
			$mailattr = $conf['simplesamlphp_attr_mail'];
	
		$groupattr = 'groups';
		if (array_key_exists('simplesamlphp_attr_groups', $conf))
			$groupattr = $conf['simplesamlphp_attr_groups'];
	
		/* Retrieve attributes from the session. */
		$attributes = $session->getAttributes();
	
		/*
		 * Get the user ID of the logged in user.
		 */
		if (!array_key_exists($idattr, $attributes))
			throw new Exception('The dokuWiki simpleSAMLphp authentication module requires the user attribute [' . $idattr . '] to identify the user');
		$baseuser = $attributes[$idattr][0];

		/*
		 * Get the user mail of the logged in user.
		 */
		if (!array_key_exists($mailattr, $attributes))
			throw new Exception('The dokuWiki simpleSAMLphp authentication module requires the user attribute [' . $idattr . '] to identify the users mail address');
		$basemail = $attributes[$mailattr][0];

		// Add groups
		$groups = array();
		if (array_key_exists($groupattr, $attributes))
			$groups = $attributes[$groupattr];
			
		
		if (isset($USERINFO['name']) &&
			($USERINFO['name'] != $baseuser)) {
			
			unset($USERINFO['name']);
			unset($USERINFO['mail']);
			unset($USERINFO['grps']);
			unset($_SERVER['REMOTE_USER']);
			unset($_SESSION[DOKU_COOKIE]['auth']['user']);
			unset($_SESSION[DOKU_COOKIE]['auth']['pass']);
			unset($_SESSION[DOKU_COOKIE]['auth']['info']);
		}
		
		/*
		 * Define the user, mail and group variables. Groups will be filled in later.
		 */
		$user =  self::encodeIllegalChars($baseuser);
		$mail = self::encodeIllegalChars($basemail);
		$groups[] = 'users';
		

	
	
		// set the globals if authed
		$USERINFO['name'] = $user;
		$USERINFO['mail'] = $mail;
		$USERINFO['grps'] = $groups;
		$_SERVER['REMOTE_USER'] = $user;
		$_SESSION[DOKU_COOKIE]['auth']['user'] = $user;
		$_SESSION[DOKU_COOKIE]['auth']['pass'] = $pass;
		$_SESSION[DOKU_COOKIE]['auth']['info'] = $USERINFO;
		return true;
	}


}
