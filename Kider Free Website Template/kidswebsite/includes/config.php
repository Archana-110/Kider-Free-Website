<?php
// Database credentials: replace with real values or use environment variables.
$servername = getenv('DB_HOST') ?: 'localhost';
$username = getenv('DB_USER') ?: 'your_db_user';
$password = getenv('DB_PASS') ?: 'your_db_password';
$dbname = getenv('DB_NAME') ?: 'your_db_name';

// Create connection (mysqli)
mysqli_report(MYSQLI_REPORT_OFF);
try {
    $conn = new mysqli($servername, $username, $password, $dbname);
    // Set recommended charset
    if (!$conn->set_charset('utf8mb4')) {
        error_log('Error loading character set utf8mb4: ' . $conn->error);
    }
} catch (Exception $e) {
    // Log error for operator and show a generic message to client
    error_log('Database connection error: ' . $e->getMessage());
    // In production avoid leaking DB details to the user
    die('Database connection failed. Please try again later.');
}
?>