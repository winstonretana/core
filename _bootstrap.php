<?php
// api/_bootstrap.php - Bootstrap para APIs
declare(strict_types=1);

header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');

require_once __DIR__ . '/../ChannelConnection.php';
require_once __DIR__ . '/../includes/SecurityLayer.php';

function json_ok($data = [], $code = 200) {
    http_response_code($code);
    echo json_encode(['ok' => true, 'data' => $data], JSON_UNESCAPED_UNICODE);
    exit;
}

function json_err($message, $code = 400, $extra = null) {
    http_response_code($code);
    echo json_encode(['ok' => false, 'error' => $message, 'extra' => $extra], JSON_UNESCAPED_UNICODE);
    exit;
}

function get_db(): ChannelConnection {
    static $db;
    if ($db) return $db;
    
    $cfg = parse_ini_file('/home/suppcenter/channel.conf');
    if (!$cfg) json_err('Configuration error', 500);
    
    return $db = ChannelConnection::getInstance($cfg);
}

function body_json(): array {
    $raw = file_get_contents('php://input') ?: '';
    $data = json_decode($raw, true);
    return is_array($data) ? $data : [];
}

function sqlv($v) {
    $db = get_db();
    if ($v === null) return "NULL";
    if (is_int($v) || is_float($v)) return (string)$v;
    return "'" . $db->escape((string)$v) . "'";
}

// Apply security headers
SecurityLayer::applyHeaders();