<?php
// /app/logout.php
session_start();

require_once __DIR__ . '/ChannelConnection.php';
require_once __DIR__ . '/ChannelAuth.php';
require_once __DIR__ . '/includes/SecurityLayer.php';

// Aplica headers de seguridad lo antes posible
SecurityLayer::applyHeaders();

/**
 * Fallback local para limpiar sesión y cookies
 * (se usa si no podemos contactar BD, para no dejar sesiones colgando)
 */
$localLogout = function () {
    // Borrar cookie de access_token con mismos atributos que en el login
    if (isset($_COOKIE['access_token'])) {
        setcookie('access_token', '', [
            'expires'  => time() - 3600,
            'path'     => '/',
            'secure'   => !empty($_SERVER['HTTPS']),
            'httponly' => true,
            'samesite' => 'Lax'
        ]);
    }

    // Limpiar sesión PHP
    $_SESSION = [];
    if (isset($_COOKIE[session_name()])) {
        setcookie(session_name(), '', time() - 42000, '/');
    }
    session_destroy();
};

try {
    $config = parse_ini_file('/home/suppcenter/channel.conf');
    if ($config) {
        // Intenta revocar token en BD y cerrar sesión usando ChannelAuth
        $db   = ChannelConnection::getInstance($config);
        $auth = new ChannelAuth($db);
        $auth->logout(); // Revoca token (si existe), loguea LOGOUT y destruye sesión
    } else {
        // Sin config -> fallback local
        error_log('Logout: Cannot read configuration, using local fallback');
        $localLogout();
    }
} catch (Throwable $e) {
    // Cualquier error en BD/IO -> fallback local
    error_log('Logout error: ' . $e->getMessage());
    $localLogout();
}

// Redirige siempre al login con mensaje de cierre
header('Location: /app/login.php?logout=1');
exit;
