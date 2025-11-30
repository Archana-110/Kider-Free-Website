<?php
session_start();
require_once 'db_config.php';

// Initialize messages
$_SESSION['error'] = '';
$_SESSION['success'] = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Sanitize inputs
    $firstName = filter_var($_POST['firstName'], FILTER_SANITIZE_STRING);
    $lastName = filter_var($_POST['lastName'], FILTER_SANITIZE_STRING);
    $email = filter_var($_POST['email'], FILTER_SANITIZE_EMAIL);
    $password = $_POST['password'];
    $gender = $_POST['gender'] ?? '';
    $terms = isset($_POST['terms']) ? 1 : 0;

    // Validation
    $errors = [];

    if (empty($firstName)) $errors[] = "First name is required";
    if (empty($lastName)) $errors[] = "Last name is required";
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) $errors[] = "Invalid email format";
    if (strlen($password) < 8) $errors[] = "Password must be at least 8 characters";
    if (empty($gender)) $errors[] = "Gender is required";
    if (!$terms) $errors[] = "You must agree to the terms";

    // Check if email exists
    $stmt = $conn->prepare("SELECT id FROM users WHERE email = ?");
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $stmt->store_result();

    if ($stmt->num_rows > 0) $errors[] = "Email already registered";
    $stmt->close();

    if (empty($errors)) {
        // Hash password
        $hashedPassword = password_hash($password, PASSWORD_DEFAULT);

        // Insert user
        $stmt = $conn->prepare("INSERT INTO users (first_name, last_name, email, password, gender) VALUES (?, ?, ?, ?, ?)");
        $stmt->bind_param("sssss", $firstName, $lastName, $email, $hashedPassword, $gender);

        if ($stmt->execute()) {
            $_SESSION['success'] = "Registration successful! Please login.";
            header("Location: login.php");
            exit();
        } else {
            $_SESSION['error'] = "Registration failed: " . $stmt->error;
        }
        $stmt->close();
    } else {
        $_SESSION['error'] = implode("<br>", $errors);
    }

    header("Location: register.php");
    exit();
}
?>