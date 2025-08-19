<?php
// ChannelAuth.php - Con SecurityLayer integrado y SQL parametrizado
require_once __DIR__ . '/includes/SecurityLayer.php';

class ChannelAuth {
    private $db;
    private $tokenTTL = 480; // minutos
    
    public function __construct($db) {
        $this->db = $db;
    }
    
    public function login($email, $password) {
        try {
            // Rate limiting
            if (!SecurityLayer::checkRateLimit($_SERVER['REMOTE_ADDR'] ?? 'Unknown', 'login')) {
                SecurityLayer::logAttempt($email, false);
                return [
                    'success' => false, 
                    'message' => 'Demasiados intentos fallidos. Intente en 15 minutos.'
                ];
            }
            
            $user = $this->db->getUserForLogin($email);
            if (!$user || (int)$user['IsActive'] !== 1) {
                SecurityLayer::logAttempt($email, false);
                $this->logActivity('LOGIN_FAILED', 0, null, $email);
                return ['success' => false, 'message' => 'Credenciales inválidas'];
            }
            
            if (!password_verify($password, $user['PasswordHash'])) {
                SecurityLayer::logAttempt($email, false);
                $this->logActivity('LOGIN_FAILED', (int)$user['UserId'], null, $email);
                return ['success' => false, 'message' => 'Credenciales inválidas'];
            }
            
            // Éxito
            SecurityLayer::logAttempt($email, true);

            // Update LastLogin
            $this->db->execute(
                "UPDATE Users SET LastLogin = SYSUTCDATETIME() WHERE UserId = ?",
                [ (int)$user['UserId'] ]
            );
            
            // Session segura
            $_SESSION['channel_user'] = [
                'UserId'      => (int)$user['UserId'],
                'Email'       => $user['Email'],
                'FullName'    => $user['FullName'],
                'UserRole'    => $user['UserRole'],
                'CompanyId'   => (int)$user['CompanyId'],
                'CompanyType' => $user['CompanyType'],
                'CompanyName' => $user['CompanyName'],
                'IsPartner'   => ((int)$user['IsPartner']) === 1,
                'IsSGS'       => ((int)$user['IsSGS']) === 1
            ];
            $_SESSION['user_fingerprint'] = SecurityLayer::generateFingerprint();
            $_SESSION['last_activity']    = time();
            $_SESSION['login_time']       = time();
            $_SESSION['ip_address']       = $_SERVER['REMOTE_ADDR'] ?? 'Unknown';
            session_regenerate_id(true);
            
            // Token API
            $this->createApiToken((int)$user['UserId']);
            
            // Log
            $this->logActivity('LOGIN_SUCCESS', (int)$user['UserId'], $user['FullName']);
            
            // Limpieza ocasional
            if (rand(1, 100) === 1) {
                SecurityLayer::cleanupOldAttempts();
            }
            
            return ['success' => true, 'message' => 'Login exitoso'];
            
        } catch (Exception $e) {
            error_log("ChannelAuth::login error: " . $e->getMessage());
            return ['success' => false, 'message' => 'Error del sistema. Intente más tarde.'];
        }
    }
    
    private function createApiToken($userId) {
        try {
            // Revocar existentes
            $this->db->execute(
                "UPDATE ApiTokens SET RevokedAt = SYSUTCDATETIME() WHERE UserId = ? AND RevokedAt IS NULL",
                [ $userId ]
            );
            
            $token = bin2hex(random_bytes(32));
            $hash  = hash('sha256', $token);
            $ip    = $_SERVER['REMOTE_ADDR'] ?? '';
            $ua    = substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 255);

            $this->db->execute(
                "INSERT INTO ApiTokens (UserId, TokenHashHex, ExpiresAt, IPAddress, UserAgent, CreatedAt)
                 VALUES (?, ?, DATEADD(MINUTE, ?, SYSUTCDATETIME()), ?, ?, SYSUTCDATETIME())",
                [ $userId, $hash, $this->tokenTTL, $ip, $ua ]
            );
            
            // Cookie segura
            setcookie('access_token', $token, [
                'expires'  => time() + ($this->tokenTTL * 60),
                'path'     => '/',
                'secure'   => !empty($_SERVER['HTTPS']),
                'httponly' => true,
                'samesite' => 'Lax'
            ]);
            
        } catch (Exception $e) {
            error_log("Token creation failed: " . $e->getMessage());
            // no crítico
        }
    }
    
    public function logout() {
        $userId = $_SESSION['channel_user']['UserId'] ?? null;
        
        // Revocar token
        if (isset($_COOKIE['access_token'])) {
            try {
                $hash = hash('sha256', $_COOKIE['access_token']);
                $this->db->execute(
                    "UPDATE ApiTokens SET RevokedAt = SYSUTCDATETIME() WHERE TokenHashHex = ? AND RevokedAt IS NULL",
                    [ $hash ]
                );
            } catch (Exception $e) {
                error_log("Token revocation failed: " . $e->getMessage());
            }
            // borrar cookie con mismos atributos
            setcookie('access_token', '', [
                'expires'  => time() - 3600,
                'path'     => '/',
                'secure'   => !empty($_SERVER['HTTPS']),
                'httponly' => true,
                'samesite' => 'Lax'
            ]);
        }
        
        // Log
        if ($userId) {
            $this->logActivity('LOGOUT', (int)$userId);
        }
        
        // Limpiar sesión
        $_SESSION = [];
        if (isset($_COOKIE[session_name()])) {
            setcookie(session_name(), '', time() - 42000, '/');
        }
        session_destroy();
        
        return true;
    }
    
    private function logActivity($type, $userId, $userName = null, $details = null) {
        try {
            $ip = $_SERVER['REMOTE_ADDR'] ?? '';
            $ua = substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 500);
            $this->db->execute(
                "INSERT INTO ActivityLog
                 (EntityType, EntityId, ActivityType, ActivityDescription,
                  UserId, UserName, IPAddress, UserAgent, NewValue, CreatedAt)
                 VALUES ('Authentication', 0, ?, ?, ?, ?, ?, ?, ?, SYSUTCDATETIME())",
                [
                    $type,
                    $type,
                    ($userId > 0 ? $userId : null),
                    ($userName ?: null),
                    $ip,
                    $ua,
                    ($details ?: null)
                ]
            );
        } catch (Exception $e) {
            error_log("Activity logging failed: " . $e->getMessage());
        }
    }
    
    public function hasPermission($module, $action = 'CanView') {
        if (!$this->isLoggedIn()) return false;
        $user = $_SESSION['channel_user'];

        // Bypass Admin / SGS
        if (($user['UserRole'] ?? '') === 'Admin' || !empty($user['IsSGS'])) {
            return true;
        }

        // Whitelist de columnas permitidas para evitar inyección en el nombre de columna
        $allowed = ['CanView','CanEdit','CanApprove','CanDelete','CanCreate','CanManage'];
        if (!in_array($action, $allowed, true)) {
            $action = 'CanView';
        }

        try {
            $val = $this->db->scalar(
                "SELECT {$action} FROM RolePermissions WHERE UserRole = ? AND Module = ?",
                [ $user['UserRole'], $module ]
            );
            return ((int)$val) === 1;
        } catch (Exception $e) {
            error_log("Permission check failed: " . $e->getMessage());
            return false;
        }
    }
    
    public function isLoggedIn() {
        return isset($_SESSION['channel_user']) && SecurityLayer::validateSession();
    }
    
    public function getCurrentUser() {
        if (!$this->isLoggedIn()) return null;
        return $_SESSION['channel_user'];
    }
    
    public function requirePermission($module, $action = 'CanView', $redirect = '/app/dashboard.php') {
        if (!$this->hasPermission($module, $action)) {
            header('Location: ' . $redirect);
            exit;
        }
    }
    
    public function isPartner() {
        return (bool)($_SESSION['channel_user']['IsPartner'] ?? false);
    }
    
    public function isSGS() {
        return (bool)($_SESSION['channel_user']['IsSGS'] ?? false);
    }
}
