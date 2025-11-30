session_unset();
session_destroy();
header("Location: login.php");
exit();
?>
<?php
require_once __DIR__ . '/db_config.php';

// Unset all session variables
$_SESSION = [];

// If there's a session cookie, expire it
if (ini_get('session.use_cookies')) {
	$params = session_get_cookie_params();
	setcookie(session_name(), '', time() - 42000,
		$params['path'], $params['domain'], $params['secure'] ?? false, $params['httponly'] ?? true
	);
}

// Destroy session server-side
session_unset();
session_destroy();

header('Location: login.php');
exit();
?>