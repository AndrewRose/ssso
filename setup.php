#!/usr/bin/php
<?php

define('CONFIG', '/etc/ssso.json');

if(php_sapi_name() != 'cli')
{
	echo 'This is a CLI tool';
	exit();
}

if(
!in_array('imap', get_loaded_extensions()) ||
!in_array('sodium', get_loaded_extensions())
) { echo 'imap or sodium module not loaded!'; exit(); }

if(! ((($argc == 4 || $argc == 5) && $argv[2] == 'init') || ($argc == 4 && $argv[2] == 'adduser')))
{
	echo "Usage (IdP):\n";
	echo 'php '.$argv[0]." test.com init /src/http/test.com endpoint.php \n";
	echo 'php '.$argv[0]." test.com adduser user\n\n";
	echo "Usage (SP):\n";
	echo 'php '.$argv[0]." test.com init /src/http/test.com \n";
	exit();
}

if($argv[2] == 'init')
{
	if($argc == 5)
	{
		if(!file_exists($argv[3].'/'.$argv[4]))
		{
			echo "Endpoint does not exist!\n";
			exit();
		}
	}

	$pair = sodium_crypto_sign_keypair();
	$sk = sodium_crypto_sign_secretkey($pair);
	$pk = sodium_crypto_sign_publickey($pair);

	if(!is_dir($argv[3]))
	{
		echo 'Unknown directory: '.$argv[3]."\n";
		exit();
	}

	$wellknown = $argv[3].'/.well-known';
	if(!is_dir($wellknown))
	{
		if(!mkdir($wellknown))
		{
			echo "Failed to create .well-known, permission issue?\n";
			exit();
		}
	}

	$pk = base64_encode($pk);
	file_put_contents($wellknown.'/_ssoPublicKey', $pk);

	if($argc == 5)
	{
		file_put_contents($wellknown.'/_ssoEndpoint', $argv[4]);
	}

	$sk = base64_encode($sk);
	if(file_exists(CONFIG))
	{
		$config = json_decode(file_get_contents(CONFIG), TRUE);
		file_put_contents(CONFIG.'-bk', file_get_contents(CONFIG));
	}
	else
	{
		$config = [];
	}

	$config[$argv[1]] = ['sk' => $sk, 'root' => $argv[3], 'users' => []];
	file_put_contents(CONFIG, json_encode($config, JSON_PRETTY_PRINT)); 
	exit();
}
else if($argv[2] == 'adduser')
{
	$config = json_decode(file_get_contents(CONFIG), TRUE);

	if(!isset($config[$argv[1]]))
	{
		echo $argv[1]." not configured, use init first?\n";
		exit();
	}

	//$password = readline('Enter password for user '.$argv[2].': ');
	// https://stackoverflow.com/questions/187736/command-line-password-prompt-in-php
	echo 'Enter password for user '.$argv[3].': ';
	system('stty -echo');
	$password = trim(fgets(STDIN));
	system('stty echo');

	if(isset($config[$argv[1]]['users'][$argv[3]]))
	{
		$config[$argv[1]]['users'][$argv[3]]['password'] = password_hash($password, PASSWORD_BCRYPT);
	}
	else
	{
		$config[$argv[1]]['users'][$argv[3]] = ['password' => password_hash($password, PASSWORD_BCRYPT), 'authorisedHosts' => []];
	}
	file_put_contents('/etc/ssso.json-bk', file_get_contents(CONFIG));
	file_put_contents(CONFIG, json_encode($config, JSON_PRETTY_PRINT)); 
}
