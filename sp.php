<html>
<head>
 <title> SSSO SP </title>
</head>
<body>
<h2> SP (Service Provider) </h2>
<h4> Use this page to test an email address managed by your IdP implementation. </h4>
<?php

define('DOMAIN', 'spdomain.test');
define('CONFIG', '/etc/ssso.json');
$redirect = 'https://'.$_SERVER['SERVER_NAME'].$_SERVER['PHP_SELF'];

if(
!in_array('imap', get_loaded_extensions()) ||
!in_array('sodium', get_loaded_extensions())
) { echo 'imap or sodium module not loaded!'; exit(); }

if(file_exists(CONFIG))
{
	$config = json_decode(file_get_contents(CONFIG), TRUE);
}
else
{
	echo 'SP not configured yet!';
	exit();
}

if(!isset($config[DOMAIN]['sk']))
{
	echo 'Secret key not configured!';
	exit();
}

$sk = base64_decode($config[DOMAIN]['sk']);

session_start();

if(isset($_GET['logout']))
{
	$_SESSION = [];
	header('Location: ?');
}

// user not logged in
if(!isset($_SESSION['email']))
{
	// attempt to login with suppled email from user.
	if(isset($_POST['email']) && !empty($_POST['email']))
	{
		// remember supplied email for when the IdP directs the user back.
		$_SESSION['ssoEmail'] = $_POST['email'];

		$domain = imap_rfc822_parse_adrlist($_POST['email'], false)[0]->host;
		if($domain)
		{
	                $url = 'https://'.$domain.'/.well-known/_ssoEndpoint';

	                $status = get_headers($url);
        	        if(strstr($status[0], '200')!==FALSE)
			{
				$endpoint = file_get_contents($url);
			}
			else
			{
				if($entries = dns_get_record('_ssoEndpoint.'.$domain, DNS_TXT))
				{
					$endpoint = $entries[0]['entries'][0];
				}
				else
				{
					echo 'Failed to reach out to endpoint for this email address.';
					exit();
				}
			}


			$signed = sodium_crypto_sign($_POST['email'], $sk);

			if($endpoint)
			{
				header('Location: https://'.$domain.'/'.$endpoint.'?email='.$_POST['email'].'&signed='.urlencode(base64_encode($signed)).'&redirect='.$redirect);
				exit();
			}
		}
		else
		{
			echo 'Failed to derive domain from email address.';
		}
	}

	// response from IdP
	else if(isset($_GET['signed']) && isset($_GET['email']))
	{
		$domain = imap_rfc822_parse_adrlist($_GET['email'], false)[0]->host;
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
					echo 'Failed to retrieve IdP _ssoPublicKey from domain TXT record or .well-known, have you configured the IdP with setup.php?';
					exit();
				}
			}

			$message = sodium_crypto_sign_open(base64_decode($_GET['signed']), $pk);
			if(!$message)
			{
				echo 'Failed to verify message came from the IdP, have you configured the IdP with setup.php?';
			}
			else
			{
				if($_SESSION['ssoEmail'] == $message)
				{
					$_SESSION['email'] = $message;
					unset($_SESSION['ssoEmail']);
					header('Location: ?');
				}
				else
				{
					echo 'Failed to confirm email!';
				}
			}	
		}
		else
		{
			echo 'Failed to derive domain from IdP email response.';
		}
	}
	else
	{
		echo 'Please enter your email address to login: <form method="post">Email: <input type="text" name="email"> <input type="submit"/> </form>';
	}
}

if(isset($_GET['loginfailed']))
{
	echo 'Failed to login to SP: '.htmlentities($_GET['loginfailed']).'<br />';
}


if(isset($_SESSION['email']))
{
	echo 'Logged in with email:'. $_SESSION['email']."<br />";
}

echo "Current session data: \n";
print_r($_SESSION);

echo '<hr><a href="?logout"> Logout / Clear session</a>';

?>
</body>
</html>
