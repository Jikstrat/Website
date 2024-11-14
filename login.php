<?php
require_once 'config.php';
session_start();

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $email = trim($_POST['email']);
    $password = $_POST['password'];

    if (empty($email) || empty($password)) {
        die("Please fill all fields");
    }

    try {
        $stmt = $pdo->prepare("SELECT * FROM users WHERE email = ?");
        $stmt->execute([$email]);

        if ($stmt->rowCount() == 1) {
            $user = $stmt->fetch();

            if (password_verify($password, $user['password'])) {
                $_SESSION['user_id'] = $user['id'];
                $_SESSION['username'] = $user['username'];

                if (isset($_POST['remember'])) {
                    setcookie('remember_me', $user['id'], time() + (30 * 24 * 60 * 60), '/');
                }

                header("Location: welcome.html");
                exit();
            } else {
                die("Invalid password");
            }
        } else {
            die("User not found");
        }
    } catch (PDOException $e) {
        die("Login failed: " . $e->getMessage());
    }
}
?>
