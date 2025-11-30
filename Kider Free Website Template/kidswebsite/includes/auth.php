<?php
// Use central db/session bootstrap
require_once __DIR__ . '/../db_config.php';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!csrf_verify($_POST['_csrf'] ?? '')) {
        $_SESSION['error'] = 'Invalid request.';
        header('Location: register.php');
        exit();
    }
    // Trim and basic sanitize inputs
    $firstName = trim((string)($_POST['firstName'] ?? ''));
    $lastName = trim((string)($_POST['lastName'] ?? ''));
    $email = filter_var(trim((string)($_POST['email'] ?? '')), FILTER_SANITIZE_EMAIL);
    $password = $_POST['password'] ?? '';
    $gender = trim((string)($_POST['gender'] ?? ''));
    $terms = isset($_POST['terms']) ? 1 : 0;

    // Validation
    $errors = [];
    if ($firstName === '') $errors[] = 'First name is required.';
    if ($lastName === '') $errors[] = 'Last name is required.';
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) $errors[] = 'Invalid email address.';
    if (!is_string($password) || strlen($password) < 8) $errors[] = 'Password must be at least 8 characters.';
    if ($gender === '') $errors[] = 'Gender is required.';
    if (!$terms) $errors[] = 'You must agree to the terms.';

    // Check if email already exists
    if (empty($errors)) {
        $stmt = $conn->prepare('SELECT id FROM users WHERE email = ?');
        if ($stmt) {
            $stmt->bind_param('s', $email);
            $stmt->execute();
            $stmt->store_result();
            if ($stmt->num_rows > 0) {
                $errors[] = 'Email already registered.';
            }
            $stmt->close();
        } else {
            error_log('DB prepare failed: ' . $conn->error);
            $errors[] = 'Registration temporarily unavailable.';
        }
    }

    if (empty($errors)) {
        // Hash password securely
        $hashedPassword = password_hash($password, PASSWORD_DEFAULT);

        $stmt = $conn->prepare('INSERT INTO users (first_name, last_name, email, password, gender) VALUES (?, ?, ?, ?, ?)');
        if ($stmt) {
            $stmt->bind_param('sssss', $firstName, $lastName, $email, $hashedPassword, $gender);
            if ($stmt->execute()) {
                // Prefer not to leak implementation details to user; success message only
                $_SESSION['success'] = 'Registration successful. Please login.';
                // Redirect to login
                header('Location: login.php');
                exit();
            } else {
                error_log('DB insert failed: ' . $stmt->error);
                $_SESSION['error'] = 'Registration failed. Please try again later.';
            }
            $stmt->close();
        } else {
            error_log('DB prepare failed: ' . $conn->error);
            $_SESSION['error'] = 'Registration failed. Please try again later.';
        }
    } else {
        // Set validation errors to display on the form
        $_SESSION['error'] = implode('<br>', $errors);
    }

    header('Location: register.php');
    exit();
}
?>