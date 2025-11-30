<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login Page</title>
    <!-- Bootstrap CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <!-- Font Awesome -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <!-- Custom CSS -->
    <style>
        .login-container {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }

        .login-card {
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
            max-width: 500px;
            margin: 0 auto;
        }

        .btn-gradient {
            background: linear-gradient(45deg, #667eea, #764ba2);
            color: white;
            border: none;
        }

        .btn-gradient:hover {
            opacity: 0.9;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="container">
            <div class="row justify-content-center">
                <div class="col-md-8 col-lg-6">
                    <div class="login-card card">
                        <div class="card-header bg-primary text-white">
                            <h3 class="text-center mb-0">Welcome Back!</h3>
                        </div>
                        <div class="card-body p-4">
                            <p class="text-center text-muted mb-4">Login to continue your journey</p>
                            
                            <!-- Error Message -->
                            <?php if(isset($_SESSION['error'])): ?>
                            <div class="alert alert-danger"><?= $_SESSION['error']; unset($_SESSION['error']); ?></div>
                            <?php endif; ?>

                            <form id="loginForm" action="login.php" method="POST">
                                <div class="mb-3">
                                    <label class="form-label">Email</label>
                                    <div class="input-group">
                                        <span class="input-group-text"><i class="fas fa-envelope"></i></span>
                                        <input type="email" class="form-control" name="email" placeholder="Enter your email" required>
                                    </div>
                                </div>

                                <div class="mb-3">
                                    <label class="form-label">Password</label>
                                    <div class="input-group">
                                        <span class="input-group-text"><i class="fas fa-lock"></i></span>
                                        <input type="password" class="form-control" name="password" placeholder="Enter your password" required>
                                    </div>
                                </div>

                                <button type="submit" class="btn btn-gradient w-100 py-2">Login</button>
                            </form>

                            <div class="text-center mt-4">
                                <a href="#" class="text-muted text-decoration-none">Forgot Password?</a>
                                <span class="mx-2">|</span>
                                <a href="register.php" class="text-primary text-decoration-none">Sign Up</a>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Bootstrap JS -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
<?php
session_start();
require 'db_config.php';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email = filter_var($_POST['email'], FILTER_SANITIZE_EMAIL);
    $password = $_POST['password'];

    // Validate credentials
    $stmt = $conn->prepare("SELECT id, password, first_name FROM users WHERE email = ?");
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows === 1) {
        $user = $result->fetch_assoc();
        
        if (password_verify($password, $user['password'])) {
            // Set session variables
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['email'] = $email;
            $_SESSION['first_name'] = $user['first_name'];
            $_SESSION['logged_in'] = true;

            // Redirect to dashboard
            header("Location: dashboard.php");
            exit();
        }
    }

    // Invalid credentials
    $_SESSION['error'] = "Invalid email or password";
    header("Location: login.php");
    exit();
}
?>