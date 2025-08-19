<?php
// api/_auth.php - Autenticaci¨®n para APIs
declare(strict_types=1);
require_once __DIR__ . '/_bootstrap.php';

function read_token(): ?string {
    $header = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
    if (stripos($header, 'Bearer ') === 0) {
        return trim(substr($header, 7));
    }
    return $_COOKIE['access_token'] ?? null;
}

function require_db_token(): array {
    $token = read_token();
    if (!$token) json_err('No auth token', 401);
    
    // Check rate limit for API
    if (!SecurityLayer::checkRateLimit($_SERVER['REMOTE_ADDR'] ?? 'Unknown', 'api')) {
        json_err('Rate limit exceeded', 429);
    }
    
    $hash = hash('sha256', $token);
    $db = get_db();
    
    $sql = "SELECT u.UserId, u.Email, u.UserRole, u.CompanyId,
                   c.CompanyType, c.IsPartner, c.IsSGS,
                   t.TokenId, t.ExpiresAt
            FROM dbo.ApiTokens t
            JOIN dbo.Users u ON u.UserId = t.UserId
            LEFT JOIN dbo.Companies c ON u.CompanyId = c.CompanyId
            WHERE t.TokenHashHex = " . sqlv($hash) . "
            AND t.RevokedAt IS NULL
            AND t.ExpiresAt > SYSUTCDATETIME()
            AND u.IsActive = 1";
    
    $row = $db->queryRow($sql);
    if (!$row) json_err('Invalid/expired token', 401);
    
    // Update LastUsedAt
    $db->execute("UPDATE ApiTokens SET LastUsedAt = SYSUTCDATETIME() WHERE TokenId = ?", [$row['TokenId']]);
    
    return [
        'uid' => (int)$row['UserId'],
        'email' => $row['Email'],
        'role' => $row['UserRole'],
        'company_id' => (int)$row['CompanyId'],
        'company_type' => $row['CompanyType'],
        'is_partner' => $row['IsPartner'] == 1,
        'is_sgs' => $row['IsSGS'] == 1
    ];
}

function require_permission(string $module, string $perm, ?int $uid = null): array {
    $who = $uid ? ['uid' => $uid] : require_db_token();
    
    // Admin/SGS bypass
    if ($who['role'] === 'Admin' || $who['is_sgs']) {
        return $who;
    }
    
    $db = get_db();
    $sql = "EXEC dbo.sp_GetUserModulePermissions @UserId=" . sqlv($who['uid']) . ", @ModuleName=" . sqlv($module);
    $p = $db->queryRow($sql) ?: [];
    
    $map = [
        'view' => 'CanView',
        'create' => 'CanCreate',
        'edit' => 'CanEdit',
        'delete' => 'CanDelete',
        'approve' => 'CanApprove'
    ];
    
    $col = $map[strtolower($perm)] ?? null;
    if (!$col || empty($p[$col])) {
        json_err("Forbidden: $module/$perm", 403);
    }
    
    return $who;
}