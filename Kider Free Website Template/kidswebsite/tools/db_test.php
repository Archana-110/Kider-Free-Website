<?php
// Simple DB test helper - usage: open in browser with ?email=you@example.com
require_once __DIR__ . '/../db_config.php';

header('Content-Type: text/plain; charset=utf-8');

$email = $_GET['email'] ?? '';
if ($email === '') {
    echo "Usage: db_test.php?email=you@example.com\n";
    exit();
}

$email = filter_var($email, FILTER_SANITIZE_EMAIL);
if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    echo "Invalid email format\n";
    exit();
}

$stmt = $conn->prepare('SELECT id, first_name, last_name, email, created_at FROM users WHERE email = ? LIMIT 1');
if (!$stmt) {
    echo "DB prepare failed: " . $conn->error . "\n";
    exit();
}

$stmt->bind_param('s', $email);
$stmt->execute();
$res = $stmt->get_result();
if ($res && $res->num_rows === 1) {
    $user = $res->fetch_assoc();
    echo "User found:\n";
    echo "ID: " . $user['id'] . "\n";
    echo "Name: " . $user['first_name'] . " " . $user['last_name'] . "\n";
    echo "Email: " . $user['email'] . "\n";
    if (isset($user['created_at'])) echo "Created: " . $user['created_at'] . "\n";
} else {
    echo "No user with email $email found\n";
}

$stmt->close();
$conn->close();

?>
