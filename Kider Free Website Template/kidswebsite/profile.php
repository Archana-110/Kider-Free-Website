<?php
// Central session/DB bootstrap
require_once __DIR__ . '/db_config.php';

if (!isset($_SESSION['logged_in']) || empty($_SESSION['user_id'])) {
    header('Location: login.php');
    exit();
}

$userId = $_SESSION['user_id'];
$success = '';
$error = '';

// Handle profile update
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!csrf_verify($_POST['_csrf'] ?? '')) {
        $error = 'Invalid request.';
    } else {
        $firstName = trim($_POST['firstName'] ?? '');
        $lastName = trim($_POST['lastName'] ?? '');
        $gender = $_POST['gender'] ?? '';
        $newPassword = $_POST['new_password'] ?? '';

    $errors = [];
    if ($firstName === '') $errors[] = 'First name is required.';
    if ($lastName === '') $errors[] = 'Last name is required.';
    if ($gender === '') $errors[] = 'Gender is required.';

    if (empty($errors)) {
        // Update core fields
        $stmt = $conn->prepare("UPDATE users SET first_name = ?, last_name = ?, gender = ? WHERE id = ?");
        $stmt->bind_param('sssi', $firstName, $lastName, $gender, $userId);
        if ($stmt->execute()) {
            $success = 'Profile updated successfully.';
            $_SESSION['first_name'] = $firstName; // keep session display in sync
        } else {
            $errors[] = 'Failed to update profile: ' . $stmt->error;
        }
        $stmt->close();

        // Update password if provided
        if ($newPassword !== '') {
            if (strlen($newPassword) < 8) {
                $errors[] = 'New password must be at least 8 characters.';
            } else {
                $hashed = password_hash($newPassword, PASSWORD_DEFAULT);
                $stmt = $conn->prepare("UPDATE users SET password = ? WHERE id = ?");
                $stmt->bind_param('si', $hashed, $userId);
                if ($stmt->execute()) {
                    $success .= ' Password updated.';
                } else {
                    $errors[] = 'Failed to update password: ' . $stmt->error;
                }
                $stmt->close();
            }
        }
    }

        if (!empty($errors)) {
            $error = implode('<br>', $errors);
        }
    }
}

// Fetch current user data
$stmt = $conn->prepare('SELECT first_name, last_name, email, gender FROM users WHERE id = ?');
$stmt->bind_param('i', $userId);
$stmt->execute();
$result = $stmt->get_result();
if ($result && $result->num_rows === 1) {
    $user = $result->fetch_assoc();
} else {
    // user not found; force logout
    header('Location: logout.php');
    exit();
}
$stmt->close();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Your Profile</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-primary">
        <div class="container">
            <a class="navbar-brand" href="dashboard.php">Dashboard</a>
            <div class="navbar-nav ms-auto">
                <span class="navbar-text me-3">Welcome, <?= htmlspecialchars(
                    
                    $_SESSION['first_name']
                ) ?>!</span>
                <a class="nav-link" href="logout.php">Logout</a>
            </div>
        </div>
    </nav>

    <div class="container mt-4">
        <h2>Your Profile</h2>

        <?php if ($success): ?>
            <div class="alert alert-success"><?= htmlspecialchars($success) ?></div>
        <?php endif; ?>
        <?php if ($error): ?>
            <div class="alert alert-danger"><?= htmlspecialchars($error) ?></div>
        <?php endif; ?>

        <form method="POST" class="mt-3 needs-validation" novalidate id="profileForm">
            <input type="hidden" name="_csrf" value="<?= htmlspecialchars(csrf_token()); ?>">
            <div class="mb-3">
                <label class="form-label">First name</label>
                <input type="text" name="firstName" class="form-control" value="<?= htmlspecialchars($user['first_name']) ?>" required>
            </div>
            <div class="mb-3">
                <label class="form-label">Last name</label>
                <input type="text" name="lastName" class="form-control" value="<?= htmlspecialchars($user['last_name']) ?>" required>
            </div>
            <div class="mb-3">
                <label class="form-label">Email (cannot change)</label>
                <input type="email" class="form-control" value="<?= htmlspecialchars($user['email']) ?>" readonly>
            </div>
            <div class="mb-3">
                <label class="form-label">Gender</label>
                <select name="gender" class="form-select" required>
                    <option value="">Select</option>
                    <option value="Male" <?= ($user['gender'] === 'Male') ? 'selected' : '' ?>>Male</option>
                    <option value="Female" <?= ($user['gender'] === 'Female') ? 'selected' : '' ?>>Female</option>
                    <option value="Other" <?= ($user['gender'] === 'Other') ? 'selected' : '' ?>>Other</option>
                </select>
            </div>

            <div class="mb-3">
                <label class="form-label">New password (leave blank to keep current)</label>
                <input type="password" name="new_password" class="form-control" placeholder="New password" id="newPassword">
                <div class="form-text">Leave empty to keep your current password. Minimum 8 characters if changing.</div>
            </div>

            <button class="btn btn-primary" type="submit">Save Changes</button>
        </form>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
    // Client-side validation for profile form
    (function() {
        'use strict'
        const form = document.getElementById('profileForm');
        form.addEventListener('submit', function(event) {
            // Reset native validation
            if (!form.checkValidity()) {
                event.preventDefault();
                event.stopPropagation();
            }

            // Custom password length check only when non-empty
            const pwd = document.getElementById('newPassword').value;
            if (pwd && pwd.length > 0 && pwd.length < 8) {
                event.preventDefault();
                event.stopPropagation();
                document.getElementById('newPassword').classList.add('is-invalid');
                if (!document.getElementById('newPassword').nextElementSibling || !document.getElementById('newPassword').nextElementSibling.classList.contains('invalid-feedback')) {
                    const feedback = document.createElement('div');
                    feedback.className = 'invalid-feedback';
                    feedback.textContent = 'Password must be at least 8 characters.';
                    document.getElementById('newPassword').parentNode.appendChild(feedback);
                }
            }

            form.classList.add('was-validated');
        }, false);
    })();
    </script>
</body>
</html>
