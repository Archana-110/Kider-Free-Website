<?php
// logout.php — secure, production-ready logout handler

// MUST run before any output
ini_set('session.cookie_httponly', 1);
if (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') {
    ini_set('session.cookie_secure', 1);
}
// Prefer Strict or Lax depending on app flow; Strict is safest.
ini_set('session.cookie_samesite', 'Lax'); // or 'Strict' if compatible

session_start();

// Only accept POST for logout to reduce CSRF surface
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    // Optionally show a small form to POST (prevents accidental GET logouts)
    http_response_code(405);
    echo "Method not allowed. To logout, submit the logout form.";
    exit();
}

// Verify CSRF token - use your existing helper
if (!function_exists('csrf_verify') || !csrf_verify($_POST['_csrf'] ?? '')) {
    error_log('Logout failed: invalid CSRF from ' . ($_SERVER['REMOTE_ADDR'] ?? 'unknown'));
    http_response_code(400);
    echo "Invalid request.";
    exit();
}

// Optional: log who is logging out (user id/email if present)
$uid = $_SESSION['user_id'] ?? null;
error_log('User logout: ' . ($uid !== null ? "user_id={$uid}" : 'anonymous') . ' ip=' . ($_SERVER['REMOTE_ADDR'] ?? 'unknown'));

// Clear all session variables
$_SESSION = [];

// If you use a custom session storage, also explicitly destroy the session data
// session_destroy() will remove the server-side data for the current session id
if (session_status() === PHP_SESSION_ACTIVE) {
    // Delete session cookie by setting it with past expiry and secure flags
    $params = session_get_cookie_params();
    // Use PHP >= 7.3 cookie options array for SameSite support
    setcookie(session_name(), '', [
        'expires' => time() - 42000,
        'path' => $params['path'] ?? '/',
        'domain' => $params['domain'] ?? '',
        'secure' => $params['secure'] ?? (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off'),
        'httponly' => true,
        'samesite' => 'Lax' // match your session.cookie_samesite value
    ]);

    // Finally destroy session data on server
    session_unset();
    session_destroy();
}

// Redirect to login (use absolute or relative path as needed)
header('Location: login.php');
exit();
