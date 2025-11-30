<?php
session_start();

// Database configuration
$servername = "localhost";
$username = "your_db_username";
$password = "your_db_password";
$dbname = "your_database_name";

// Create connection
$conn = new mysqli($servername, $username, $password, $dbname);

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Initialize error messages
$_SESSION['error'] = '';
$_SESSION['success'] = '';

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Sanitize and validate input
    $firstName = $conn->real_escape_string(trim($_POST['firstName']));
    $lastName = $conn->real_escape_string(trim($_POST['lastName']));
    $email = $conn->real_escape_string(trim($_POST['email']));
    $password = trim($_POST['password']);
    $gender = isset($_POST['gender']) ? $conn->real_escape_string($_POST['gender']) : '';
    $terms = isset($_POST['terms']) ? 1 : 0;

    // Validation checks
    $errors = [];

    if (empty($firstName)) {
        $errors[] = "First name is required";
    }

    if (empty($lastName)) {
        $errors[] = "Last name is required";
    }

    if (empty($email) || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $errors[] = "Valid email is required";
    }

    if (empty($password) || strlen($password) < 8) {
        $errors[] = "Password must be at least 8 characters";
    }

    if (empty($gender)) {
        $errors[] = "Gender is required";
    }

    if (!$terms) {
        $errors[] = "You must agree to the terms and conditions";
    }

    // Check if email already exists
    $stmt = $conn->prepare("SELECT id FROM users WHERE email = ?");
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $stmt->store_result();

    if ($stmt->num_rows > 0) {
        $errors[] = "Email already registered";
    }
    $stmt->close();

    if (empty($errors)) {
        // Hash password
        $hashedPassword = password_hash($password, PASSWORD_DEFAULT);

        // Insert into database
        $stmt = $conn->prepare("INSERT INTO users (first_name, last_name, email, password, gender) 
                               VALUES (?, ?, ?, ?, ?)");
        $stmt->bind_param("sssss", $firstName, $lastName, $email, $hashedPassword, $gender);

        if ($stmt->execute()) {
            $_SESSION['success'] = "Registration successful! You can now login.";
            header("Location: register.html");
            exit();
        } else {
            $_SESSION['error'] = "Error: " . $stmt->error;
        }
        $stmt->close();
    } else {
        $_SESSION['error'] = implode("<br>", $errors);
    }

    // Redirect back to form with errors
    header("Location: register.html");
    exit();
}

$conn->close();
?>