<html>
<head>
 <title> SSSO IdP </title>
</head>
<body>
<h2> IdP (Identity Provider) </h2>
<?php

define('DOMAIN', 'idpdomain.test');
define('CONFIG', '/etc/ssso.json');

if(
!in_array('imap', get_loaded_extensions()) ||
!in_array('sodium', get_loaded_extensions())
) { echo 'imap or sodium module not loaded!'; exit(); }

sleep(.5);
session_start();

if(file_exists(CONFIG))
{
//TODO file lock?!
	$config = json_decode(file_get_contents(CONFIG), TRUE);
}
else
{
	echo 'IdP not configured yet!';
	exit();
}

if(isset($_GET['logout']))
{
	$_SESSION = [];
	header('Location: ?');
}

// log user in
if(isset($_POST['username']) && isset($_POST['password']))
{
	if(isset($config[DOMAIN]['users'][$_POST['username']]) && password_verify($_POST['password'], $config[DOMAIN]['users'][$_POST['username']]['password']))
	{
		$_SESSION = $config[DOMAIN]['users'][$_POST['username']];
		$_SESSION['username'] = $_POST['username'];
	}
	else
	{
		echo 'Unknown username / password';
	}
}

// SP request to confirm an email address but logged in under another login
if(isset($_GET['email']) && isset($_GET['signed']) && isset($_GET['redirect']) && isset($_SESSION['username']) && (($_SESSION['username'].'@'.DOMAIN) != $_GET['email']))
{
	header('Location: '.$_GET['redirect'].'?email='.$_GET['email'].'&loginfailed=You appear to be logged in under a different account at your IdP!');
	exit();
}

if(isset($_GET['email']) && isset($_GET['signed']) && isset($_GET['redirect']) && isset($_SESSION['username']) && (($_SESSION['username'].'@'.DOMAIN) == $_GET['email'])) // || in_array($_SESSION['alias'], $_GET['email'])
{
	// get the domain of the SP from the redirect and pull the _ssoPublicKey to confirm the signed email request came from them.
	$providerHostname = parse_url($_GET['redirect'])['host'];
	$domain = parse_url($_GET['redirect'])['host'];
	$sk = base64_decode($config[DOMAIN]['sk']);

	if($domain)
	{
		$url = 'https://'.$domain.'/.well-known/_ssoPublicKey';

		$status = get_headers($url);
		if(strstr($status[0], '200')!==FALSE)
		{
			$pk = file_get_contents($url);
			$pk = base64_decode($pk);
		}
		else
		{
			if($entries = dns_get_record('_ssoPublicKey.'.$domain, DNS_TXT))
			{		
				$pk = base64_decode($entries[0]['entries'][0]);
			}
			else
			{
				echo 'Failed to retrieve SP _ssoPublicKey from domain TXT record or .well-known, have you configured the SP with setup.php?';
				exit();
			}
		}

		$message = sodium_crypto_sign_open(base64_decode($_GET['signed']), $pk);
		if(!$message)
		{
			echo 'Failed to verify message came from the SP, have you configured the SP with setup.php?';
			exit();
		}
		else
		{
			if($_GET['email'] != $message)
			{
				echo 'Failed to confirm email!';
				exit();
			}
		}
	}
	else
	{
		echo 'Failed to derive domain from IdP email response.';
		exit();
	}

	if(isset($_SESSION['username']))
	{
		if(!in_array($providerHostname, $_SESSION['authorisedHosts']) && !isset($_GET['yes']))
		{
// TODO: do something with a no answer.
			echo 'Allow '.$providerHostname.' to confirm your identity (email address)? <a href="?'.$_SERVER['QUERY_STRING'].'&yes">Yes</a> | <a href="">No</a>';
		}
		else if(in_array($providerHostname, $_SESSION['authorisedHosts']) || isset($_GET['yes']))
		{
			if(!in_array($providerHostname, $_SESSION['authorisedHosts']))
			{
				$_SESSION['authorisedHosts'][] = $providerHostname;
			}

			$signed = sodium_crypto_sign($_GET['email'], $sk);
			header('Location: '.$_GET['redirect'].'?email='.urlencode($_SESSION['username'].'@'.DOMAIN).'&signed='.urlencode(base64_encode($signed)));
			exit();
		}
	}
}
else if(!isset($_SESSION['username']))
{
	echo '<form method="post">Username: <input type="text" name="username" /> Password: <input type="password" name="password" /><input type="submit" /></form><hr />';
}

if(isset($_SESSION['username']))
{
	echo '<hr />';
	echo 'Logged in as: '.$_SESSION['username'].'<br />';
	echo 'Authorised SPs:<pre>';
	print_r($_SESSION['authorisedHosts']);
	echo '</pre>';
	echo '<a href="?logout">Logout</a>';
}
?>
</body>
</html>
