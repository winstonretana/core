<?php
// index.php - Redirección automática al login o dashboard
session_start();

// Si el usuario ya está autenticado, ir al dashboard
if (isset($_SESSION['sgsbot_partner'])) {
    header('Location: dashboard.php');
} else {
    // Si no, ir al login
    header('Location: login.php');
}
exit;
?>