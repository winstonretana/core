<?php
// includes/SecurityLayer.php - Versión corregida para usar ChannelConnection existente
// VERSIÓN FINAL - Compatible con los métodos de ChannelConnection

class SecurityLayer {
    private static $db = null;
    private static $initialized = false;
    
    private static function init() {
        if (self::$initialized) return;
        
        $config = parse_ini_file('/home/suppcenter/channel.conf');
        if (!$config) {
            error_log('SecurityLayer: Cannot read config');
            die('System error');
        }
        
        require_once dirname(__DIR__) . '/ChannelConnection.php';
        self::$db = ChannelConnection::getInstance($config);
        self::$initialized = true;
    }
    
    public static function applyHeaders() {
        header('X-Frame-Options: DENY');
        header('X-Content-Type-Options: nosniff');
        header('X-XSS-Protection: 1; mode=block');
        header('Referrer-Policy: strict-origin-when-cross-origin');
        header('Permissions-Policy: geolocation=(), microphone=(), camera=()');
        
        // Content Security Policy relajado para desarrollo
        header('Content-Security-Policy-Report-Only: default-src * \'unsafe-inline\' \'unsafe-eval\';');
        
        if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') {
            header('Strict-Transport-Security: max-age=31536000; includeSubDomains; preload');
        }
        
        // Cache control
        header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
        header('Pragma: no-cache');
        header('Expires: 0');
    }
    
    public static function validateCSRF() {
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') return true;
        
        // NO validar CSRF en el login inicial
        if (strpos($_SERVER['REQUEST_URI'], '/login.php') !== false && !isset($_SESSION['channel_user'])) {
            return true;
        }
        
        $sessionToken = $_SESSION['csrf_token'] ?? '';
        $postToken = $_POST['csrf_token'] ?? $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
        
        if (empty($sessionToken) || empty($postToken)) {
            http_response_code(403);
            self::logSecurityEvent('CSRF_MISSING', 'Missing CSRF token on ' . $_SERVER['REQUEST_URI'], 'WARNING');
            die('Security error: Missing CSRF token');
        }
        
        if (!hash_equals($sessionToken, $postToken)) {
            http_response_code(403);
            self::logSecurityEvent('CSRF_MISMATCH', 'Invalid CSRF token on ' . $_SERVER['REQUEST_URI'], 'CRITICAL');
            die('Security error: Invalid CSRF token');
        }
        
        return true;
    }
    
    public static function generateCSRF() {
        if (empty($_SESSION['csrf_token'])) {
            $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        }
        return $_SESSION['csrf_token'];
    }
    
    public static function checkRateLimit($identifier, $type = 'login') {
        self::init();
        
        $limits = [
            'login' => ['attempts' => 5, 'window' => 15],
            'api' => ['attempts' => 100, 'window' => 60],
            'password_reset' => ['attempts' => 3, 'window' => 60],
            'file_upload' => ['attempts' => 10, 'window' => 60],
            'export' => ['attempts' => 5, 'window' => 60],
            'qa_analysis' => ['attempts' => 10, 'window' => 60]
        ];
        
        if (!isset($limits[$type])) {
            error_log("SecurityLayer: Unknown rate limit type: $type");
            return false;
        }
        
        $limit = $limits[$type];
        
        try {
            // Usar el SP sp_CheckRateLimit con la sintaxis correcta de ChannelConnection
            $sql = "EXEC sp_CheckRateLimit ?, ?, ?, ?";
            
            $result = self::$db->getFirst($sql, [
                $identifier,
                $type,
                $limit['window'],
                $limit['attempts']
            ]);
            
            if (!$result) {
                // Si el SP no devuelve nada, permitir por defecto
                return true;
            }
            
            // Convertir el resultado a booleano
            $isAllowed = intval($result['IsAllowed'] ?? 0) === 1;
            
            if (!$isAllowed) {
                self::logSecurityEvent('RATE_LIMIT_EXCEEDED', 
                    "Type: $type, Identifier: $identifier, Attempts: " . ($result['CurrentAttempts'] ?? 'unknown'),
                    'WARNING'
                );
            }
            
            return $isAllowed;
            
        } catch (Exception $e) {
            error_log("SecurityLayer rate limit check failed: " . $e->getMessage());
            // En caso de error, ser permisivo para no bloquear el sistema
            return true;
        }
    }
    
    public static function logAttempt($email, $success, $type = 'LOGIN') {
        self::init();
        
        $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown';
        $ipAddress = $_SERVER['REMOTE_ADDR'] ?? 'Unknown';
        
        try {
            // Usar el SP sp_LogSecurityAttempt con parámetros
            $sql = "EXEC sp_LogSecurityAttempt ?, ?, ?, ?, ?";
            
            self::$db->execute($sql, [
                $email,
                $ipAddress,
                substr($userAgent, 0, 1000), // Limitar a 1000 chars
                $success ? 1 : 0,
                $type
            ]);
            
            // Si falla el login, verificar si está bloqueado
            if (!$success && $type === 'LOGIN') {
                $sql = "EXEC sp_RecordFailedLogin ?, ?, ?";
                $result = self::$db->getFirst($sql, [$email, $ipAddress, $userAgent]);
                
                if ($result && intval($result['IsBlocked'] ?? 0) === 1) {
                    // Cuenta bloqueada temporalmente
                    throw new Exception($result['Message'] ?? 'Account temporarily locked');
                }
            }
            
        } catch (Exception $e) {
            error_log("SecurityLayer log attempt failed: " . $e->getMessage());
            throw $e; // Re-throw para que login.php pueda manejar el mensaje
        }
    }
    
    public static function generateFingerprint() {
        $components = [
            $_SERVER['HTTP_USER_AGENT'] ?? '',
            $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? '',
            $_SERVER['HTTP_ACCEPT_ENCODING'] ?? '',
            $_SERVER['HTTP_ACCEPT'] ?? ''
        ];
        return hash('sha256', implode('|', $components));
    }
    
    public static function validateSession() {
        if (!isset($_SESSION['channel_user'])) {
            return false;
        }
        
        // Check fingerprint
        if (isset($_SESSION['user_fingerprint'])) {
            $current = self::generateFingerprint();
            if (!hash_equals($_SESSION['user_fingerprint'], $current)) {
                self::logSecurityEvent('SESSION_FINGERPRINT_MISMATCH', 
                    'User: ' . $_SESSION['channel_user']['UserId'],
                    'CRITICAL'
                );
                session_destroy();
                return false;
            }
        } else {
            // Crear fingerprint si no existe
            $_SESSION['user_fingerprint'] = self::generateFingerprint();
        }
        
        // Check session timeout (8 hours)
        if (isset($_SESSION['last_activity'])) {
            $inactive = time() - $_SESSION['last_activity'];
            if ($inactive > 28800) { // 8 hours
                self::logSecurityEvent('SESSION_TIMEOUT', 
                    'User: ' . $_SESSION['channel_user']['UserId'] . ', Inactive: ' . round($inactive/3600, 1) . ' hours',
                    'INFO'
                );
                session_destroy();
                return false;
            }
        }
        
        // Session regeneration cada 30 minutos
        if (!isset($_SESSION['session_created'])) {
            $_SESSION['session_created'] = time();
        } else if (time() - $_SESSION['session_created'] > 1800) {
            session_regenerate_id(true);
            $_SESSION['session_created'] = time();
        }
        
        $_SESSION['last_activity'] = time();
        
        // Validar en BD usando SP
        if (isset($_SESSION['channel_user']['UserId'])) {
            try {
                self::init();
                $sql = "EXEC sp_ValidateUserSession ?";
                $result = self::$db->getFirst($sql, [$_SESSION['channel_user']['UserId']]);
                
                if (!$result || intval($result['IsValid'] ?? 0) !== 1) {
                    session_destroy();
                    return false;
                }
            } catch (Exception $e) {
                error_log("Session validation failed: " . $e->getMessage());
                // En caso de error con el SP, permitir continuar
            }
        }
        
        return true;
    }
    
    public static function cleanupOldAttempts() {
        self::init();
        
        try {
            // Usar el SP sp_CleanupSecurityLogs
            $sql = "EXEC sp_CleanupSecurityLogs ?";
            $result = self::$db->getFirst($sql, [7]); // 7 días por defecto
            
            if ($result) {
                error_log("SecurityLayer cleanup: " . ($result['LoginAttemptsDeleted'] ?? 0) . 
                         " login attempts, " . ($result['ActivityLogsDeleted'] ?? 0) . " logs deleted");
            }
        } catch (Exception $e) {
            error_log("Cleanup failed: " . $e->getMessage());
        }
    }
    
    /**
     * Sanitiza entrada de usuario
     */
    public static function sanitizeInput($input, $type = 'string') {
        if (is_array($input)) {
            return array_map(function($item) use ($type) {
                return self::sanitizeInput($item, $type);
            }, $input);
        }
        
        if ($input === null) {
            return null;
        }
        
        switch ($type) {
            case 'int':
                return filter_var($input, FILTER_SANITIZE_NUMBER_INT);
                
            case 'float':
                return filter_var($input, FILTER_SANITIZE_NUMBER_FLOAT, FILTER_FLAG_ALLOW_FRACTION);
                
            case 'email':
                $email = filter_var($input, FILTER_SANITIZE_EMAIL);
                return substr($email, 0, 510); // Limitar a 510 chars (tamaño en BD)
                
            case 'url':
                return filter_var($input, FILTER_SANITIZE_URL);
                
            case 'html':
                return htmlspecialchars($input, ENT_QUOTES | ENT_HTML5, 'UTF-8');
                
            case 'sql':
                self::init();
                return self::$db->escape($input);
                
            case 'filename':
                return preg_replace('/[^a-zA-Z0-9._-]/', '', $input);
                
            case 'alpha':
                return preg_replace('/[^a-zA-Z]/', '', $input);
                
            case 'alphanumeric':
                return preg_replace('/[^a-zA-Z0-9]/', '', $input);
                
            case 'phone':
                return preg_replace('/[^0-9+\-\(\)\s]/', '', $input);
                
            case 'boolean':
                return filter_var($input, FILTER_VALIDATE_BOOLEAN);
                
            default:
                return htmlspecialchars(strip_tags(trim($input)), ENT_QUOTES | ENT_HTML5, 'UTF-8');
        }
    }
    
    /**
     * Valida permisos del usuario usando SP
     */
    public static function hasPermission($module, $action = 'view') {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }
        
        $user = $_SESSION['channel_user'] ?? null;
        if (!$user) return false;
        
        // Admin siempre tiene todos los permisos
        if (($user['UserRole'] ?? '') === 'Admin') return true;
        
        // Cache de permisos en sesión para evitar múltiples consultas
        $cacheKey = 'permissions_cache_' . $user['UserId'];
        if (!isset($_SESSION[$cacheKey])) {
            try {
                self::init();
                $sql = "EXEC sp_GetUserPermissions ?";
                $permissions = self::$db->getAll($sql, [$user['UserId']]);
                
                $_SESSION[$cacheKey] = [];
                foreach ($permissions as $perm) {
                    $key = strtolower($perm['Module'] . '.' . $perm['Permission']);
                    $_SESSION[$cacheKey][$key] = intval($perm['IsGranted'] ?? 0) === 1;
                }
                
                // Cache por 30 minutos
                $_SESSION[$cacheKey . '_expires'] = time() + 1800;
            } catch (Exception $e) {
                error_log("Failed to load permissions: " . $e->getMessage());
                
                // Fallback: permisos básicos por rol
                if ($user['UserRole'] === 'Partner') {
                    $allowedModules = ['Dashboard', 'Opportunities', 'Contracts', 'Reports'];
                    return in_array($module, $allowedModules);
                }
                
                if (!empty($user['IsSGS'])) {
                    $allowedModules = ['Dashboard', 'Companies', 'Opportunities', 'Reports', 'QA', 'Metrics'];
                    return in_array($module, $allowedModules);
                }
                
                return false;
            }
        }
        
        // Verificar expiración del cache
        if (isset($_SESSION[$cacheKey . '_expires']) && time() > $_SESSION[$cacheKey . '_expires']) {
            unset($_SESSION[$cacheKey]);
            unset($_SESSION[$cacheKey . '_expires']);
            return self::hasPermission($module, $action); // Recursivo para recargar
        }
        
        // Verificar permiso específico
        $key = strtolower($module . '.' . $action);
        return $_SESSION[$cacheKey][$key] ?? false;
    }
    
    /**
     * Log de eventos de seguridad usando SP
     */
    public static function logSecurityEvent($event, $details = '', $severity = 'INFO') {
        self::init();
        
        $user = $_SESSION['channel_user'] ?? null;
        $userId = $user['UserId'] ?? 0;
        $ipAddress = $_SERVER['REMOTE_ADDR'] ?? 'Unknown';
        
        try {
            // Usar el SP sp_LogSecurityEvent con parámetros
            $sql = "EXEC sp_LogSecurityEvent ?, ?, ?, ?, ?";
            
            self::$db->execute($sql, [
                $event,
                $userId,
                substr($ipAddress, 0, 90), // IPAddress es nvarchar(90)
                $details,
                $severity
            ]);
            
        } catch (Exception $e) {
            // Fallback: Log to file si falla BD
            $logDir = dirname(__DIR__) . '/logs/security';
            if (!is_dir($logDir)) {
                @mkdir($logDir, 0755, true);
            }
            
            $logFile = $logDir . '/' . date('Y-m-d') . '.log';
            $logEntry = sprintf(
                "[%s] %s | User: %d | IP: %s | Event: %s | Details: %s | Error: %s\n",
                date('Y-m-d H:i:s'),
                $severity,
                $userId,
                $ipAddress,
                $event,
                $details,
                $e->getMessage()
            );
            
            @file_put_contents($logFile, $logEntry, FILE_APPEND | LOCK_EX);
        }
    }
    
    /**
     * Encripta datos sensibles
     */
    public static function encrypt($data) {
        $config = parse_ini_file('/home/suppcenter/channel.conf');
        $key = $config['ENCRYPTION_KEY'] ?? 'change-this-default-key-32-chars';
        
        // Asegurar que la key tenga 32 caracteres
        $key = substr(str_pad($key, 32, '0'), 0, 32);
        
        $iv = random_bytes(16);
        $encrypted = openssl_encrypt($data, 'AES-256-CBC', $key, 0, $iv);
        
        if ($encrypted === false) {
            throw new Exception('Encryption failed');
        }
        
        return base64_encode($iv . $encrypted);
    }
    
    /**
     * Desencripta datos
     */
    public static function decrypt($data) {
        $config = parse_ini_file('/home/suppcenter/channel.conf');
        $key = $config['ENCRYPTION_KEY'] ?? 'change-this-default-key-32-chars';
        
        // Asegurar que la key tenga 32 caracteres
        $key = substr(str_pad($key, 32, '0'), 0, 32);
        
        $data = base64_decode($data);
        if ($data === false || strlen($data) < 16) {
            throw new Exception('Invalid encrypted data');
        }
        
        $iv = substr($data, 0, 16);
        $encrypted = substr($data, 16);
        
        $decrypted = openssl_decrypt($encrypted, 'AES-256-CBC', $key, 0, $iv);
        
        if ($decrypted === false) {
            throw new Exception('Decryption failed');
        }
        
        return $decrypted;
    }
    
    /**
     * Valida formato de password
     */
    public static function validatePassword($password) {
        $errors = [];
        
        // Mínimo 8 caracteres
        if (strlen($password) < 8) {
            $errors[] = 'Debe tener al menos 8 caracteres';
        }
        
        // Al menos una mayúscula
        if (!preg_match('/[A-Z]/', $password)) {
            $errors[] = 'Debe tener al menos una mayúscula';
        }
        
        // Al menos una minúscula
        if (!preg_match('/[a-z]/', $password)) {
            $errors[] = 'Debe tener al menos una minúscula';
        }
        
        // Al menos un número
        if (!preg_match('/[0-9]/', $password)) {
            $errors[] = 'Debe tener al menos un número';
        }
        
        // Al menos un carácter especial
        if (!preg_match('/[@$!%*?&#]/', $password)) {
            $errors[] = 'Debe tener al menos un carácter especial (@$!%*?&#)';
        }
        
        return [
            'valid' => empty($errors),
            'errors' => $errors,
            'message' => empty($errors) ? 'Password válido' : implode('. ', $errors)
        ];
    }
    
    /**
     * Hash seguro de password
     */
    public static function hashPassword($password) {
        return password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
    }
    
    /**
     * Verifica password
     */
    public static function verifyPassword($password, $hash) {
        return password_verify($password, $hash);
    }
    
    /**
     * Validación de archivos subidos
     */
    public static function validateUpload($file, $allowedTypes = [], $maxSize = 5242880) {
        // Verificar error de upload
        if ($file['error'] !== UPLOAD_ERR_OK) {
            $errorMessages = [
                UPLOAD_ERR_INI_SIZE => 'El archivo excede el límite del servidor',
                UPLOAD_ERR_FORM_SIZE => 'El archivo excede el límite del formulario',
                UPLOAD_ERR_PARTIAL => 'El archivo se subió parcialmente',
                UPLOAD_ERR_NO_FILE => 'No se subió ningún archivo',
                UPLOAD_ERR_NO_TMP_DIR => 'Falta carpeta temporal',
                UPLOAD_ERR_CANT_WRITE => 'Error al escribir archivo',
                UPLOAD_ERR_EXTENSION => 'Upload detenido por extensión'
            ];
            
            return [
                'valid' => false, 
                'message' => $errorMessages[$file['error']] ?? 'Error desconocido: ' . $file['error']
            ];
        }
        
        // Verificar tamaño (default 5MB)
        if ($file['size'] > $maxSize) {
            return [
                'valid' => false, 
                'message' => 'Archivo muy grande. Máximo: ' . round($maxSize / 1048576, 1) . 'MB'
            ];
        }
        
        // Verificar tipo MIME real
        $finfo = finfo_open(FILEINFO_MIME_TYPE);
        $mimeType = finfo_file($finfo, $file['tmp_name']);
        finfo_close($finfo);
        
        // Lista de tipos permitidos por defecto si no se especifica
        if (empty($allowedTypes)) {
            $allowedTypes = [
                'image/jpeg', 'image/png', 'image/gif', 'image/webp',
                'application/pdf',
                'application/msword', 
                'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
                'application/vnd.ms-excel',
                'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                'text/plain', 'text/csv'
            ];
        }
        
        if (!in_array($mimeType, $allowedTypes)) {
            return [
                'valid' => false, 
                'message' => 'Tipo de archivo no permitido: ' . $mimeType
            ];
        }
        
        // Verificar extensión peligrosa
        $extension = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
        $dangerousExtensions = [
            'php', 'phtml', 'php3', 'php4', 'php5', 'phps', 'phar',
            'exe', 'sh', 'bat', 'cmd', 'com', 'jar',
            'scr', 'vbs', 'js', 'asp', 'aspx', 'jsp'
        ];
        
        if (in_array($extension, $dangerousExtensions)) {
            self::logSecurityEvent('DANGEROUS_FILE_UPLOAD', 
                'Attempted upload: ' . $file['name'] . ', Type: ' . $mimeType,
                'CRITICAL'
            );
            return [
                'valid' => false, 
                'message' => 'Extensión de archivo no permitida'
            ];
        }
        
        // Sanitizar nombre de archivo
        $safeName = preg_replace('/[^a-zA-Z0-9._-]/', '_', $file['name']);
        
        return [
            'valid' => true,
            'message' => 'Archivo válido',
            'mime_type' => $mimeType,
            'safe_name' => $safeName,
            'original_name' => $file['name'],
            'size' => $file['size']
        ];
    }
    
    /**
     * Genera token temporal para operaciones sensibles
     */
    public static function generateTempToken($purpose = 'general', $expiry = 3600) {
        $token = bin2hex(random_bytes(32));
        
        if (!isset($_SESSION['temp_tokens'])) {
            $_SESSION['temp_tokens'] = [];
        }
        
        $_SESSION['temp_tokens'][$purpose] = [
            'token' => $token,
            'expiry' => time() + $expiry,
            'used' => false
        ];
        
        return $token;
    }
    
    /**
     * Valida token temporal
     */
    public static function validateTempToken($token, $purpose = 'general') {
        $stored = $_SESSION['temp_tokens'][$purpose] ?? null;
        
        if (!$stored) {
            return false;
        }
        
        // Verificar expiración
        if (time() > $stored['expiry']) {
            unset($_SESSION['temp_tokens'][$purpose]);
            return false;
        }
        
        // Verificar si ya fue usado
        if ($stored['used']) {
            return false;
        }
        
        // Verificar token
        if (!hash_equals($stored['token'], $token)) {
            self::logSecurityEvent('INVALID_TEMP_TOKEN', 
                'Purpose: ' . $purpose,
                'WARNING'
            );
            return false;
        }
        
        // Marcar como usado
        $_SESSION['temp_tokens'][$purpose]['used'] = true;
        
        return true;
    }
    
    /**
     * Método helper para QA_AI - Verifica si el usuario puede ejecutar QA
     */
    public static function canRunQA() {
        $user = $_SESSION['channel_user'] ?? null;
        if (!$user) return false;
        
        // Solo Admin o SGS pueden ejecutar QA
        return ($user['UserRole'] === 'Admin' || !empty($user['IsSGS']));
    }
    
    /**
     * Desbloquea cuenta después del tiempo de espera
     */
    public static function unlockAccount($email) {
        self::init();
        
        try {
            $sql = "EXEC sp_UnlockAccount ?";
            $result = self::$db->getFirst($sql, [
                substr($email, 0, 510) // Email es nvarchar(510)
            ]);
            
            return [
                'success' => true,
                'message' => $result['Message'] ?? 'Account unlocked'
            ];
        } catch (Exception $e) {
            return [
                'success' => false,
                'message' => 'Failed to unlock account: ' . $e->getMessage()
            ];
        }
    }
}