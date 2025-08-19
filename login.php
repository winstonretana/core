<?php
// /app/login.php
session_start();

require_once __DIR__ . '/ChannelConnection.php';
require_once __DIR__ . '/ChannelAuth.php';
require_once __DIR__ . '/includes/SecurityLayer.php';

// Aplica headers de seguridad de inmediato
SecurityLayer::applyHeaders();

// Carga configuración
$config = parse_ini_file('/home/suppcenter/channel.conf');
if (!$config) {
    http_response_code(500);
    error_log('Login: Cannot read configuration');
    exit('Sistema temporalmente no disponible');
}

// Conexión
try {
    $db   = ChannelConnection::getInstance($config);
    $auth = new ChannelAuth($db);
} catch (Exception $e) {
    http_response_code(500);
    error_log('Login: Database connection failed: ' . $e->getMessage());
    exit('Sistema temporalmente no disponible');
}

// Si ya hay sesión, redirige
if ($auth->isLoggedIn()) {
    header('Location: /app/dashboard.php');
    exit;
}

$error         = '';
$logoutMessage = isset($_GET['logout']) ? 'Sesión cerrada correctamente' : '';

// Manejo de POST (login)
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    try {
        // CSRF
        SecurityLayer::validateCSRF();

        $email    = trim($_POST['email'] ?? '');
        $password = $_POST['password'] ?? '';

        if ($email === '' || $password === '') {
            $error = 'Por favor ingrese email y contraseña';
        } else {
            $result = $auth->login($email, $password);
            if (!empty($result['success'])) {
                header('Location: /app/dashboard.php');
                exit;
            }
            $error = $result['message'] ?? 'Credenciales inválidas';
        }
    } catch (Exception $e) {
        error_log('Login POST error: ' . $e->getMessage());
        $error = 'Error de seguridad. Intente nuevamente.';
    }
}

// Token CSRF para el formulario
$csrfToken = SecurityLayer::generateCSRF();

// Si tu SecurityLayer expone nonce para CSP, lo usamos en el <script>; si no, queda vacío.
$cspNonce = method_exists('SecurityLayer','cspNonce') ? (SecurityLayer::cspNonce() ?? '') : '';
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Channel Management - SuppCenter Global</title>
    <meta name="description" content="Sistema de gestión de canales y partners">
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdn.jsdelivr.net/npm/boxicons@2.1.4/css/boxicons.min.css" rel="stylesheet">
</head>
<body class="bg-gradient-to-br from-blue-600 via-purple-600 to-indigo-800 min-h-screen flex items-center justify-center">
    <div class="bg-white/10 backdrop-blur-lg rounded-2xl p-8 w-full max-w-md shadow-2xl border border-white/20">
        <!-- Logo -->
        <div class="text-center mb-8">
            <div class="w-20 h-20 mx-auto mb-4 bg-gradient-to-br from-orange-400 to-pink-500 rounded-2xl flex items-center justify-center shadow-lg">
                <i class='bx bx-network-chart text-white text-3xl'></i>
            </div>
            <h1 class="text-3xl font-bold text-white mb-2">Channel Management</h1>
            <p class="text-blue-100">SuppCenter Global Services</p>
        </div>

        <!-- Mensajes -->
        <?php if ($logoutMessage): ?>
            <div class="mb-6 p-4 bg-green-500/20 border border-green-400/50 rounded-lg backdrop-blur-sm">
                <div class="flex items-center gap-2 text-green-100">
                    <i class='bx bx-check-circle'></i>
                    <?= htmlspecialchars($logoutMessage) ?>
                </div>
            </div>
        <?php endif; ?>

        <?php if ($error): ?>
            <div class="mb-6 p-4 bg-red-500/20 border border-red-400/50 rounded-lg backdrop-blur-sm">
                <div class="flex items-center gap-2 text-red-100">
                    <i class='bx bx-error-circle'></i>
                    <?= htmlspecialchars($error) ?>
                </div>
            </div>
        <?php endif; ?>

        <!-- Formulario -->
        <form method="POST" action="/app/login.php" id="loginForm" class="space-y-6" autocomplete="on">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken) ?>">

            <div>
                <label for="email" class="block text-sm font-medium text-blue-100 mb-2">Email</label>
                <div class="relative">
                    <div class="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                        <i class='bx bx-envelope text-blue-300'></i>
                    </div>
                    <input type="email"
                           id="email"
                           name="email"
                           required
                           autofocus
                           autocomplete="email"
                           placeholder="tu@email.com"
                           value="<?= htmlspecialchars($_POST['email'] ?? '') ?>"
                           class="block w-full pl-10 pr-3 py-3 bg-white/10 border border-white/20 rounded-lg text-white placeholder-blue-200 focus:outline-none focus:ring-2 focus:ring-orange-400 focus:border-transparent backdrop-blur-sm">
                </div>
            </div>

            <div>
                <label for="password" class="block text-sm font-medium text-blue-100 mb-2">Contraseña</label>
                <div class="relative">
                    <div class="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                        <i class='bx bx-lock-alt text-blue-300'></i>
                    </div>
                    <input type="password"
                           id="password"
                           name="password"
                           required
                           autocomplete="current-password"
                           placeholder="••••••••"
                           class="block w-full pl-10 pr-3 py-3 bg-white/10 border border-white/20 rounded-lg text-white placeholder-blue-200 focus:outline-none focus:ring-2 focus:ring-orange-400 focus:border-transparent backdrop-blur-sm">
                </div>
            </div>

            <button type="submit"
                    id="btnLogin"
                    class="w-full bg-gradient-to-r from-orange-500 to-pink-500 text-white font-semibold py-3 px-4 rounded-lg hover:from-orange-600 hover:to-pink-600 focus:outline-none focus:ring-2 focus:ring-orange-400 transform transition-all duration-200 hover:scale-105 shadow-lg">
                <span class="btn-text">Iniciar Sesión</span>
                <span class="btn-loading hidden">
                    <i class='bx bx-loader-alt animate-spin mr-2'></i>
                    Verificando...
                </span>
            </button>
        </form>

        <!-- Seguridad -->
        <div class="mt-6 p-3 bg-white/5 rounded-lg">
            <p class="text-xs text-blue-200 text-center">
                <i class='bx bx-shield-quarter mr-1'></i>
                Conexión segura • Token 8 horas • Rate limiting activo
            </p>
        </div>

        <!-- Footer -->
        <div class="mt-8 text-center">
            <p class="text-blue-200 text-sm">© <?= date('Y') ?> SuppCenter Global Services</p>
            <p class="text-blue-300 text-xs mt-1">Channel Management System</p>
        </div>
    </div>

    <!-- JS externo (no inline). Si hay nonce en CSP, se agrega. -->
    <script src="/app/assets/js/login.js" <?= $cspNonce ? 'nonce="'.htmlspecialchars($cspNonce).'"' : '' ?> defer></script>
</body>
</html>
