<?php
// ChannelConnection.php - Conexión SQL Server para Channel Management
//require_once __DIR__ . '/qa/qa_auditor.php';

class ChannelConnection {
    private static $instance = null;
    private $server;
    private $user;
    private $pass;
    private $database;
    private $sqlcmd = '/opt/mssql-tools/bin/sqlcmd';
    
    private function __construct($config) {
        $this->validateConfig($config);
        $this->server   = $config['SQLSERVER'];
        $this->user     = $config['SQLUSER'];
        $this->pass     = $config['SQLPASS'];
        $this->database = $config['SQLDB'];
    }
    
    /** Obtener instancia singleton */
    public static function getInstance($config) {
        if (self::$instance === null) {
            self::$instance = new self($config);
        }
        return self::$instance;
    }
    
    /** Validar configuración requerida */
    private function validateConfig($config) {
        $required = ['SQLSERVER', 'SQLDB', 'SQLUSER', 'SQLPASS'];
        foreach ($required as $key) {
            if (!isset($config[$key])) {
                throw new Exception("Missing required config: $key");
            }
        }
    }
    
    /** Ejecutar comando usando proc_open */
    private function executeCommand($cmd) {
        $descriptorspec = [
            0 => ["pipe", "r"], // stdin
            1 => ["pipe", "w"], // stdout
            2 => ["pipe", "w"]  // stderr
        ];
        $process = proc_open($cmd, $descriptorspec, $pipes);
        if (!is_resource($process)) {
            throw new Exception("No se pudo ejecutar el comando");
        }
        fclose($pipes[0]);

        $stdout = stream_get_contents($pipes[1]); fclose($pipes[1]);
        $stderr = stream_get_contents($pipes[2]); fclose($pipes[2]);
        $return_value = proc_close($process);
        if ($return_value !== 0 && !empty($stderr)) {
            throw new Exception("SQL Error: " . $stderr);
        }
        return $stdout;
    }

    /* ============================================================
     * Helpers de parámetros y logging
     * ============================================================ */
    private function formatParam($param) {
        if ($param === null || $param === 'NULL') return 'NULL';
        if ($param instanceof \DateTimeInterface) {
            return "'" . $param->format('Y-m-d H:i:s') . "'";
        }
        if (is_bool($param)) return $param ? '1' : '0';
        if (is_int($param) || is_float($param)) return (string)$param;
        // numérica en string
        if (is_string($param) && is_numeric($param)) return (string)$param;
        // por defecto string escapado
        return "'" . $this->escape((string)$param) . "'";
    }

    /** Reemplazar parámetros ? con valores formateados/escapados */
    private function bindParameters($sql, array $params) {
        $pos = 0;
        foreach ($params as $param) {
            $q = strpos($sql, '?', $pos);
            if ($q === false) break;
            $rep = $this->formatParam($param);
            $sql = substr_replace($sql, $rep, $q, 1);
            $pos = $q + strlen($rep);
        }
        return $sql;
    }

    /** Sanitiza SQL para logs (evita volcar valores sensibles) */
    private function maskForLog($sql) {
        // reemplaza literales entre comillas por '?'
        return preg_replace("/'([^']|'')*'/", "'?'", $sql);
    }
    
    /** Escapar string para SQL */
    public function escape($value) {
        return str_replace("'", "''", (string)$value);
    }

    /* ============================================================
     * Métodos de acceso
     * ============================================================ */

    /** Obtener un usuario para login (parametrizado) */
    public function getUserForLogin($email) {
        $sql = "
            SET NOCOUNT ON;
            SELECT 
                u.UserId, 
                u.Email, 
                u.PasswordHash, 
                u.FirstName + ' ' + u.LastName as FullName,
                u.UserRole,
                u.CompanyId,
                c.CompanyType,
                c.CompanyName,
                c.IsPartner,
                c.IsSGS,
                CAST(u.IsActive as INT) as IsActive
            FROM Users u
            INNER JOIN Companies c ON u.CompanyId = c.CompanyId
            WHERE u.Email = ?
        ";

        // Auditor con placeholders + params // QA_Auditor::checkSql($sql, [$email], __FUNCTION__, __FILE__, __LINE__);

        $sqlBound = $this->bindParameters($sql, [$email]);
        $cmd = sprintf(
            '%s -S %s -U %s -P %s -d %s -h -1 -W -s"|" -Q %s',
            $this->sqlcmd,
            escapeshellarg($this->server),
            escapeshellarg($this->user),
            escapeshellarg($this->pass),
            escapeshellarg($this->database),
            escapeshellarg($sqlBound)
        );
        
        $output = $this->executeCommand($cmd);
        if (empty(trim($output))) return null;

        $line = trim($output);
        $values = explode('|', $line);
        
        if (count($values) >= 11) {
            return [
                'UserId'       => trim($values[0]),
                'Email'        => trim($values[1]),
                'PasswordHash' => trim($values[2]),
                'FullName'     => trim($values[3]),
                'UserRole'     => trim($values[4]),
                'CompanyId'    => trim($values[5]),
                'CompanyType'  => trim($values[6]),
                'CompanyName'  => trim($values[7]),
                'IsPartner'    => trim($values[8]),
                'IsSGS'        => trim($values[9]),
                'IsActive'     => trim($values[10])
            ];
        }
        return null;
    }
    
    /** Obtener todos los resultados (admite $params) */
    public function getAll($sql, $params = []) {
        // Auditor ve placeholders + params // QA_Auditor::checkSql($sql, $params, __FUNCTION__, __FILE__, __LINE__);

        // Bind para ejecución
        if (!empty($params)) $sql = $this->bindParameters($sql, $params);

        $cmd = sprintf(
            '%s -S %s -U %s -P %s -d %s -W -s"|" -Q %s',
            $this->sqlcmd,
            escapeshellarg($this->server),
            escapeshellarg($this->user),
            escapeshellarg($this->pass),
            escapeshellarg($this->database),
            escapeshellarg("SET NOCOUNT ON; " . $sql)
        );
        
        $output = $this->executeCommand($cmd);
        if (empty(trim($output))) return [];
        
        $lines = explode("\n", trim($output));
        $results = [];
        $headers = [];
        $headersParsed = false;
        
        foreach ($lines as $line) {
            $line = trim($line);
            if ($line === '') continue;
            if (strpos($line, '---') !== false) continue; // separadores

            $values = array_map('trim', explode('|', $line));
            if (!$headersParsed) {
                $headers = $values;
                $headersParsed = true;
            } else {
                if (count($headers) === count($values)) {
                    $results[] = array_combine($headers, $values);
                }
            }
        }
        return $results;
    }
    
    /** Obtener primer resultado (admite $params) */
    public function getFirst($sql, $params = []) {
        $res = $this->getAll($sql, $params);
        return $res[0] ?? null;
    }

    /** Wrappers (compatibilidad con header que los invoca si existen) */
    public function scalarParams($sql, array $params = []) { return (int)$this->scalar($sql, $params); }
    public function getFirstParams($sql, array $params = []) { return $this->getFirst($sql, $params); }
    
    /** Alias genérico de lectura */
    public function query($sql, $params = []) {
        return $this->getAll($sql, $params);
    }
    
    /** Ejecuta (INSERT/UPDATE/DELETE) */
    public function execute($sql, $params = []) {
        // Auditor // QA_Auditor::checkSql($sql, $params, __FUNCTION__, __FILE__, __LINE__);

        if (!empty($params)) $sql = $this->bindParameters($sql, $params);

        // Log mascarado (no volcamos valores literales)
        error_log("EXECUTE SQL: " . $this->maskForLog($sql));

        $cmd = sprintf(
            '%s -S %s -U %s -P %s -d %s -Q %s 2>&1',
            $this->sqlcmd,
            escapeshellarg($this->server),
            escapeshellarg($this->user),
            escapeshellarg($this->pass),
            escapeshellarg($this->database),
            escapeshellarg($sql)
        );
        
        try {
            $output = $this->executeCommand($cmd);
            if (!empty($output)) error_log("EXECUTE OUTPUT: " . $output);
            return true;
        } catch (Exception $e) {
            error_log("EXECUTE ERROR: " . $e->getMessage());
            throw $e;
        }
    }

    /** Múltiples result sets (admite $params) */
    public function getMultipleResultSets($sql, $params = []) {
        // QA_Auditor::checkSql($sql, $params, __FUNCTION__, __FILE__, __LINE__);
        if (!empty($params)) $sql = $this->bindParameters($sql, $params);

        $fullSql = "SET NOCOUNT ON; " . $sql;
        $cmd = sprintf(
            '%s -S %s -U %s -P %s -d %s -W -s"|" -Q %s',
            $this->sqlcmd,
            escapeshellarg($this->server),
            escapeshellarg($this->user),
            escapeshellarg($this->pass),
            escapeshellarg($this->database),
            escapeshellarg($fullSql)
        );
        
        $output = $this->executeCommand($cmd);
        if (empty(trim($output))) return [];
        
        $lines = explode("\n", trim($output));
        $resultSets = [];
        $currentSet = [];
        $headers = [];
        $headersParsed = false;
        
        foreach ($lines as $line) {
            $line = trim($line);
            if ($line === '') {
                if ($currentSet) {
                    $resultSets[] = $currentSet;
                    $currentSet = [];
                    $headers = [];
                    $headersParsed = false;
                }
                continue;
            }
            if (strpos($line, '---') !== false) continue;

            $values = array_map('trim', explode('|', $line));
            if (!$headersParsed) {
                $headers = $values;
                $headersParsed = true;
            } else {
                if (count($headers) === count($values)) {
                    $currentSet[] = array_combine($headers, $values);
                }
            }
        }
        if (!empty($currentSet)) $resultSets[] = $currentSet;
        return $resultSets;
    }

    /** Obtiene un solo valor (admite $params) */
    public function scalar($sql, $params = []) {
        //QA_Auditor::checkSql($sql, $params, __FUNCTION__, __FILE__, __LINE__);
        if (!empty($params)) $sql = $this->bindParameters($sql, $params);

        $cmd = sprintf(
            '%s -S %s -U %s -P %s -d %s -h -1 -W -Q %s',
            $this->sqlcmd,
            escapeshellarg($this->server),
            escapeshellarg($this->user),
            escapeshellarg($this->pass),
            escapeshellarg($this->database),
            escapeshellarg("SET NOCOUNT ON; " . $sql)
        );
        $output = $this->executeCommand($cmd);
        return trim($output);
    }
    
    /** Test de conexión */
    public function testConnection() {
        try {
            $version = $this->scalar("SELECT @@VERSION");
            return !empty($version);
        } catch (Exception $e) {
            return false;
        }
    }
}
?>
