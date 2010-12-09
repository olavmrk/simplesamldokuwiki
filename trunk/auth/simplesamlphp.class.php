<?php
/**
 * simpleSAMLphp authentication plugin
 *
 * @author     Andreas Aakre Solberg, UNINETT, http://www.uninett.no
 * @author     François Kooman
 * @author     Thijs Kinkhorst, Universiteit van Tilburg
 */

class auth_simplesamlphp extends auth_basic {
  
  var $as;
  
  function auth_simplesamlphp()
  {
    $this->cando['external'] = true;
    $this->cando['logoff']   = true;
    $this->success = true;
  }
  
  function trustExternal($user,$pass,$sticky=false)
  {
    global $USERINFO;
    global $conf;
    
    $sticky ? $sticky = true : $sticky = false;
    //sanity check
    
    $path = '/var/simplesamlphp';
    if (array_key_exists('simplesamlphp_path', $conf)) {
      $path = $conf['simplesamlphp_path'];
    }
    require_once($path . '/lib/_autoload.php');
    
    $sp_auth = 'default-sp';
    if (array_key_exists('simplesamlphp_sp_auth', $conf)) {
      $sp_auth = $conf['simplesamlphp_sp_auth'];
    }
    
    $this->as = new SimpleSAML_Auth_Simple($sp_auth);
    $this->as->requireAuth();
    
    $attributes = $this->as->getAttributes();
    
    $attr_user = 'eduPersonPrincipalName';
    if (array_key_exists('simplesamlphp_attr_user', $conf)) {
      $attr_user = $conf['simplesamlphp_attr_user'];
    }
    
    $attr_name = 'cn';
    if (array_key_exists('simplesamlphp_attr_name', $conf)) {
      $attr_name = $conf['simplesamlphp_attr_name'];
    }
    
    $attr_mail = 'mail';
    if (array_key_exists('simplesamlphp_attr_mail', $conf)) {
      $attr_mail = $conf['simplesamlphp_attr_mail'];
    }
    
    $attr_grps = 'eduPersonAffiliation';
    if (array_key_exists('simplesamlphp_attr_grps', $conf)) {
      $attr_grps = $conf['simplesamlphp_attr_grps'];
    }
    
    if (!array_key_exists($attr_user, $attributes)) {
      die("no attribute \"" . $attr_user . "\" provided by IDP");
    }
    $user = $attributes[$attr_user][0];
    
    if (!array_key_exists($attr_name, $attributes)) {
      die("no attribute \"" . $attr_name . "\" provided by IDP");
    }
    $USERINFO['name'] = $attributes[$attr_name][0];
    
    if (!array_key_exists($attr_mail, $attributes)) {
      $USERINFO['mail'] = "";
    } else {
      $USERINFO['mail'] = $attributes[$attr_mail][0];
    }
    
    if (!array_key_exists($attr_grps, $attributes)) {
      $USERINFO['grps'] = array($conf['defaultgroup']);
    } else {
      $USERINFO['grps'] = $attributes[$attr_grps];
    }
    
    $_SERVER['REMOTE_USER'] = $user;
    $_SESSION[DOKU_COOKIE]['auth']['user'] = $user;
    $_SESSION[DOKU_COOKIE]['auth']['pass'] = $pass;
    $_SESSION[DOKU_COOKIE]['auth']['info'] = $USERINFO;
    
    return true;
  }
  
  function logoff()
  {
    $this->as->logout();
  }
}
