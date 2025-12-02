<?php
// Combined register form (GET) + processor (POST)
require_once __DIR__ . '/db_config.php';

// If POST -> process registration
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
                $_SESSION['success'] = 'Registration successful. Please login.';
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
        $_SESSION['error'] = implode('<br>', $errors);
    }

    header('Location: register.php');
    exit();
}

// If GET -> show form
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Registration Page</title>
    <!-- Bootstrap CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <!-- Font Awesome -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <!-- Custom CSS -->
    <style>
        .registration-container {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        .registration-card {
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
        }
        .password-toggle {
            cursor: pointer;
            position: absolute;
            right: 15px;
            top: 50%;
            transform: translateY(-50%);
        }
    </style>
</head>
<body>
    
    <div class="registration-container">
        <div class="container">
            <div class="row justify-content-center">
                <div class="col-md-8 col-lg-6">
                    <div class="registration-card card">
                        <div class="card-header bg-primary text-white">
                            <h3 class="text-center mb-0">Create Account</h3>
                        </div>
                        <div class="card-body p-4">
<?php if(!empty($_SESSION['error'])): ?>
<div class="alert alert-danger"><?= htmlspecialchars($_SESSION['error']); unset($_SESSION['error']); ?></div>
<?php endif; ?>
<?php if(!empty($_SESSION['success'])): ?>
<div class="alert alert-success"><?= htmlspecialchars($_SESSION['success']); unset($_SESSION['success']); ?></div>
<?php endif; ?>
<form id="registrationForm" action="register.php" method="POST" novalidate>
                                <input type="hidden" name="_csrf" value="<?= htmlspecialchars(csrf_token()); ?>">
                                <div class="row">
                                    <div class="col-md-6 mb-3">
                                        <label for="firstName" class="form-label">First Name <span class="text-danger">*</span></label>
                                        <input type="text" class="form-control" id="firstName" name="firstName" required>
                                        <div class="invalid-feedback">Please enter your first name</div>
                                    </div>
                                    <div class="col-md-6 mb-3">
                                        <label for="lastName" class="form-label">Last Name <span class="text-danger">*</span></label>
                                        <input type="text" class="form-control" id="lastName" name="lastName" required>
                                        <div class="invalid-feedback">Please enter your last name</div>
                                    </div>
                                </div>

                                <div class="mb-3">
                                    <label for="email" class="form-label">Email Address <span class="text-danger">*</span></label>
                                    <div class="input-group">
                                        <span class="input-group-text"><i class="fas fa-envelope"></i></span>
                                        <input type="email" class="form-control" id="email" name="email" required>
                                        <div class="invalid-feedback">Please enter a valid email address</div>
                                    </div>
                                </div>

                                <div class="mb-3 position-relative">
                                    <label for="password" class="form-label">Password <span class="text-danger">*</span></label>
                                    <div class="input-group">
                                        <span class="input-group-text"><i class="fas fa-lock"></i></span>
                                        <input type="password" class="form-control" id="password" name="password" required>
                                        <i class="password-toggle fas fa-eye-slash" onclick="togglePassword()"></i>
                                    </div>
                                    <div class="invalid-feedback">Please enter a password</div>
                                </div>

                                <div class="mb-3">
                                    <label class="form-label">Gender</label>
                                    <div class="d-flex gap-3">
                                        <div class="form-check">
                                            <input class="form-check-input" type="radio" name="gender" id="male" value="Male">
                                            <label class="form-check-label" for="male">Male</label>
                                        </div>
                                        <div class="form-check">
                                            <input class="form-check-input" type="radio" name="gender" id="female" value="Female">
                                            <label class="form-check-label" for="female">Female</label>
                                        </div>
                                        <div class="form-check">
                                            <input class="form-check-input" type="radio" name="gender" id="other" value="Other">
                                            <label class="form-check-label" for="other">Other</label>
                                        </div>
                                    </div>
                                </div>

                                <div class="form-check mb-4">
                                    <input class="form-check-input" type="checkbox" id="terms" name="terms" required>
                                    <label class="form-check-label" for="terms">
                                        I agree to the <a href="#">Terms and Conditions</a>
                                    </label>
                                    <div class="invalid-feedback">You must agree before submitting</div>
                                </div>

                                <button type="submit" class="btn btn-primary w-100 py-2">Register Now</button>
                            </form>

                            <div class="text-center mt-3">
                                <p>Already have an account? <a href="login.php">Login here</a></p>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Bootstrap JS and dependencies -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <!-- Custom JS -->
    <script>
        function togglePassword() {
            const passwordInput = document.getElementById('password');
            const toggleIcon = document.querySelector('.password-toggle');
            
            if (passwordInput.type === 'password') {
                passwordInput.type = 'text';
                toggleIcon.classList.replace('fa-eye-slash', 'fa-eye');
            } else {
                passwordInput.type = 'password';
                toggleIcon.classList.replace('fa-eye', 'fa-eye-slash');
            }
        }

        // Form validation
        (() => {
            'use strict'

            const form = document.getElementById('registrationForm');

            form.addEventListener('submit', event => {
                if (!form.checkValidity()) {
                    event.preventDefault()
                    event.stopPropagation()
                }

                form.classList.add('was-validated')
            }, false)
        })()
    </script>
</body>
</html>