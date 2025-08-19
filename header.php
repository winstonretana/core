<?php
// includes/header.php - Header con queries y menús restaurados
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// 1) Seguridad primero
require_once dirname(__DIR__) . '/includes/SecurityLayer.php';
SecurityLayer::applyHeaders();

// Validar sesión
if (!SecurityLayer::validateSession()) {
    header('Location: /app/login.php');
    exit;
}

// 2) Usuario
$user = $_SESSION['channel_user'] ?? null;
if (!$user || empty($user['UserId'])) {
    session_destroy();
    header('Location: /app/login.php');
    exit;
}

// 3) Conexión a BD y auth
require_once dirname(__DIR__) . '/ChannelConnection.php';
require_once dirname(__DIR__) . '/ChannelAuth.php';

$config = parse_ini_file('/home/suppcenter/channel.conf');
if (!$config) {
    error_log('Header: Cannot read configuration');
    die("Error: Sistema temporalmente no disponible");
}

try {
    $db = ChannelConnection::getInstance($config);
    $auth = new ChannelAuth($db);
} catch (Exception $e) {
    error_log('Header: Database connection failed: ' . $e->getMessage());
    die("Error: Sistema temporalmente no disponible");
}

// Verificar autenticación
if (!$auth->isLoggedIn()) {
    header('Location: /app/login.php');
    exit;
}

// 4) CSRF
$csrfToken = SecurityLayer::generateCSRF();

// 5) Métricas para accesos rápidos - QUERIES RESTAURADAS
$notificationCount = 0;
$quickAccess = [
    'contracts_expiring'     => 0,
    'recent_communications'  => 0,
    'open_incidents'         => 0,
    'work_orders'            => 0,
    'pending_amendments'     => 0,
    'pending_approvals'      => 0,
    'opportunities_at_risk'  => 0
];

try {
    // CONTRATOS POR VENCER (30 días)
    if (SecurityLayer::hasPermission('Contracts', 'CanView')) {
        $sql = "SELECT COUNT(*) AS Total
                FROM Contracts
                WHERE EndDate BETWEEN GETDATE() AND DATEADD(DAY, 30, GETDATE())
                  AND Status = 'Active'";
        if (empty($user['IsSGS']) && !empty($user['CompanyId'])) {
            $cid = intval($user['CompanyId']);
            $sql .= " AND (ClientId = {$cid} OR PartnerId = {$cid})";
        }
        $r = $db->getFirst($sql);
        $quickAccess['contracts_expiring'] = intval($r['Total'] ?? 0);
    }

    // COMUNICACIONES SIN CONTACTO RECIENTE (15 días)
    if (!empty($user['IsSGS']) || (($user['CompanyType'] ?? '') === 'Partner')) {
        $sql = "SELECT COUNT(DISTINCT c.CompanyId) AS Total
                FROM Companies c
                LEFT JOIN Communications comm
                  ON c.CompanyId = comm.CompanyId
                 AND comm.CommunicationDate > DATEADD(DAY, -15, GETDATE())
                WHERE c.IsActive = 1
                  AND comm.CommunicationId IS NULL";
        if (empty($user['IsSGS']) && !empty($user['CompanyId'])) {
            $cid = intval($user['CompanyId']);
            $sql .= " AND c.PartnerId = {$cid}";
        }
        $r = $db->getFirst($sql);
        $quickAccess['recent_communications'] = intval($r['Total'] ?? 0);
    }

    // INCIDENTES CRÍTICOS/ALTA
    if (SecurityLayer::hasPermission('Incidents', 'CanView')) {
        $sql = "SELECT COUNT(*) AS Total
                FROM Incidents
                WHERE Status IN ('Open','In Progress')
                  AND Priority IN ('Critical','High')";
        if (empty($user['IsSGS']) && !empty($user['CompanyId'])) {
            $cid = intval($user['CompanyId']);
            $sql .= " AND CompanyId = {$cid}";
        }
        $r = $db->getFirst($sql);
        $quickAccess['open_incidents'] = intval($r['Total'] ?? 0);
    }

    // WORK ORDERS (solo SGS)
    if (!empty($user['IsSGS']) && SecurityLayer::hasPermission('Fleet', 'CanView')) {
        $r = $db->getFirst("SELECT COUNT(*) AS Total FROM WorkOrders WHERE Status = 'OnSite' AND IsActive = 1");
        $quickAccess['work_orders'] = intval($r['Total'] ?? 0);
    }

    // AMENDMENTS PENDIENTES
    if (SecurityLayer::hasPermission('Contracts', 'CanView')) {
        $sql = "SELECT COUNT(*) AS Total FROM ContractAmendments WHERE Status = 'Pending'";
        if (empty($user['IsSGS']) && !empty($user['CompanyId'])) {
            $cid = intval($user['CompanyId']);
            $sql .= " AND EXISTS (
                        SELECT 1 FROM Contracts c
                        WHERE c.ContractId = ContractAmendments.ContractId
                          AND (c.ClientId = {$cid} OR c.PartnerId = {$cid})
                      )";
        }
        $r = $db->getFirst($sql);
        $quickAccess['pending_amendments'] = intval($r['Total'] ?? 0);
    }

    // OPORTUNIDADES EN RIESGO (3 días)
    if (SecurityLayer::hasPermission('Opportunities', 'CanView')) {
        try {
            $companyParam = (!empty($user['IsSGS']) || empty($user['CompanyId'])) ? null : intval($user['CompanyId']);
            $r = $db->getFirst("EXEC sp_GetOpportunitiesAtRiskCount ?, ?", [3, $companyParam]);
            $quickAccess['opportunities_at_risk'] = intval($r['AtRiskCount'] ?? 0);
        } catch (Exception $e) {
            // Fallback a query directo
            $sql = "SELECT COUNT(*) AS Total
                    FROM Opportunities
                    WHERE Status IN ('Pending','Qualifying','Proposal')
                      AND DATEDIFF(DAY, UpdatedAt, GETDATE()) > 3";
            if (empty($user['IsSGS']) && !empty($user['CompanyId'])) {
                $cid = intval($user['CompanyId']);
                $sql .= " AND PartnerId = {$cid}";
            }
            $r = $db->getFirst($sql);
            $quickAccess['opportunities_at_risk'] = intval($r['Total'] ?? 0);
        }
    }

    // APROBACIONES PENDIENTES (solo SGS)
    if (!empty($user['IsSGS']) && SecurityLayer::hasPermission('Opportunities', 'CanApprove')) {
        try {
            $r = $db->getFirst("EXEC sp_GetQueueCount");
            $quickAccess['pending_approvals'] = intval($r['QueueCount'] ?? 0);
        } catch (Exception $e) {
            $r = $db->getFirst("SELECT COUNT(*) AS Total FROM OpportunityApprovalQueue WHERE Status='Pending'");
            $quickAccess['pending_approvals'] = intval($r['Total'] ?? 0);
        }
    }
} catch (Exception $e) {
    error_log("Header metrics error: " . $e->getMessage());
}

// 6) QuickAccessWidget
$widgetPath = dirname(__DIR__) . '/widgets/quickaccess.widget.php';
if (is_file($widgetPath)) {
    require_once $widgetPath;
}
if (!class_exists('QuickAccessWidget')) {
    // Fallback si no existe el widget
    class QuickAccessWidget {
        private $items = [];
        public function addItem($id, $config) {
            if (!empty($config['visible'])) {
                $this->items[$id] = $config;
            }
        }
        public function render() {
            if (empty($this->items)) return;
            echo '<div class="bg-yellow-50 border-t border-yellow-200"><div class="px-4 py-2"><div class="flex items-center justify-between flex-wrap gap-2">';
            foreach ($this->items as $item) {
                if ($item['count'] > 0) {
                    echo '<a href="' . $item['url'] . '" class="flex items-center gap-2 px-3 py-1 bg-white rounded-lg shadow-sm hover:shadow-md transition-shadow">';
                    echo '<i class="bx ' . $item['icon'] . ' text-' . $item['color'] . '-600"></i>';
                    echo '<div class="text-sm"><span class="font-semibold">' . $item['count'] . '</span> ' . $item['label'] . '</div>';
                    if ($item['badge']) {
                        echo '<span class="px-2 py-0.5 bg-' . $item['badge_color'] . '-100 text-' . $item['badge_color'] . '-700 text-xs rounded-full">' . $item['badge'] . '</span>';
                    }
                    echo '</a>';
                }
            }
            echo '</div></div></div>';
        }
    }
}
$quickAccessBar = new QuickAccessWidget();

// Configurar items del QuickAccess
$quickAccessBar->addItem('at_risk', [
    'count'       => $quickAccess['opportunities_at_risk'],
    'label'       => 'Oportunidades',
    'sublabel'    => 'en riesgo',
    'url'         => '/app/opportunities.php?filter=at_risk',
    'icon'        => 'bx-error-circle',
    'color'       => 'red',
    'badge'       => $quickAccess['opportunities_at_risk'] > 0 ? '≤3 días' : null,
    'badge_color' => 'red',
    'visible'     => SecurityLayer::hasPermission('Opportunities', 'CanView'),
    'animate'     => $quickAccess['opportunities_at_risk'] > 0
]);

$quickAccessBar->addItem('approvals', [
    'count'       => $quickAccess['pending_approvals'],
    'label'       => 'Aprobaciones',
    'sublabel'    => 'en cola',
    'url'         => '/app/opportunities.php?view=queue',
    'icon'        => 'bx-time-five',
    'color'       => 'yellow',
    'badge'       => $quickAccess['pending_approvals'] > 0 ? 'Revisar' : null,
    'badge_color' => 'orange',
    'visible'     => SecurityLayer::hasPermission('Opportunities', 'CanApprove') && !empty($user['IsSGS']),
    'animate'     => false
]);

$quickAccessBar->addItem('contracts', [
    'count'       => $quickAccess['contracts_expiring'],
    'label'       => 'Contratos',
    'sublabel'    => 'por vencer',
    'url'         => '/app/contracts.php',
    'icon'        => 'bx-file',
    'color'       => 'blue',
    'badge'       => $quickAccess['contracts_expiring'] > 0 ? '30 días' : null,
    'badge_color' => 'orange',
    'visible'     => SecurityLayer::hasPermission('Contracts', 'CanView')
]);

$quickAccessBar->addItem('communications', [
    'count'       => $quickAccess['recent_communications'],
    'label'       => 'Comunicación',
    'sublabel'    => 'sin contacto',
    'url'         => '/app/communications.php',
    'icon'        => 'bx-chat',
    'color'       => 'orange',
    'badge'       => $quickAccess['recent_communications'] > 0 ? '+15 días' : null,
    'badge_color' => 'orange',
    'visible'     => !empty($user['IsSGS']) || (($user['CompanyType'] ?? '') === 'Partner')
]);

$quickAccessBar->addItem('incidents', [
    'count'       => $quickAccess['open_incidents'],
    'label'       => 'Incidentes',
    'sublabel'    => 'críticos',
    'url'         => '/app/incidents.php',
    'icon'        => 'bx-support',
    'color'       => 'red',
    'badge'       => $quickAccess['open_incidents'] > 0 ? 'Urgente' : null,
    'badge_color' => 'red',
    'visible'     => SecurityLayer::hasPermission('Incidents', 'CanView')
]);

$quickAccessBar->addItem('workorders', [
    'count'       => $quickAccess['work_orders'],
    'label'       => 'Work Orders',
    'sublabel'    => 'en sitio',
    'url'         => '/app/fleet.php?tab=usage',
    'icon'        => 'bx-car',
    'color'       => 'green',
    'badge'       => $quickAccess['work_orders'] > 0 ? 'Pendientes' : null,
    'badge_color' => 'green',
    'visible'     => !empty($user['IsSGS']) && SecurityLayer::hasPermission('Fleet', 'CanView')
]);

$quickAccessBar->addItem('amendments', [
    'count'       => $quickAccess['pending_amendments'],
    'label'       => 'Amendments',
    'sublabel'    => 'pendientes',
    'url'         => '/app/contracts.php?tab=amendments',
    'icon'        => 'bx-edit-alt',
    'color'       => 'purple',
    'badge'       => $quickAccess['pending_amendments'] > 0 ? 'Revisar' : null,
    'badge_color' => 'purple',
    'visible'     => SecurityLayer::hasPermission('Contracts', 'CanView')
]);
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Channel Management - <?= htmlspecialchars($user['CompanyName'] ?? 'SGS') ?></title>
    <meta name="description" content="Sistema de gestión de canales y partners">
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdn.jsdelivr.net/npm/boxicons@2.1.4/css/boxicons.min.css" rel="stylesheet">
    <?php if (SecurityLayer::canRunQA()): ?>
    <link rel="stylesheet" href="/app/qa/assets/qa-widget.css?v=<?= date('YmdHis') ?>">
    <?php endif; ?>
</head>
<body class="bg-gray-50">
<nav class="bg-white shadow-sm border-b border-gray-200 sticky top-0 z-50">
  <div class="px-4 sm:px-6 lg:px-8">
    <div class="flex justify-between h-16">
      <!-- Logo -->
      <a href="/app/dashboard.php" class="flex items-center hover:opacity-80 transition-opacity">
        <div class="w-10 h-10 bg-gradient-to-br from-indigo-500 to-purple-600 rounded-xl flex items-center justify-center shadow">
          <i class='bx bx-network-chart text-white text-xl'></i>
        </div>
        <div class="ml-3">
          <h1 class="text-xl font-semibold text-gray-900">Channel Management</h1>
          <p class="text-xs text-gray-500"><?= htmlspecialchars($user['CompanyName'] ?? 'System') ?></p>
        </div>
      </a>

      <!-- Right Side -->
      <div class="flex items-center space-x-3">
        <!-- Notifications -->
        <button class="relative p-2 text-gray-400 hover:text-gray-600 hover:bg-gray-50 rounded-lg transition-colors">
          <i class='bx bx-bell text-xl'></i>
          <?php if ($notificationCount > 0): ?>
          <span class="absolute -top-1 -right-1 h-5 min-w-[20px] bg-red-500 text-white text-xs rounded-full flex items-center justify-center px-1">
            <?= $notificationCount ?>
          </span>
          <?php endif; ?>
        </button>

        <!-- Quick Menu Grid -->
        <div class="dropdown relative">
          <button class="p-2 text-gray-400 hover:text-gray-600 hover:bg-gray-50 rounded-lg transition-colors">
            <i class='bx bx-grid-alt text-xl'></i>
            <?php if ($quickAccess['opportunities_at_risk'] > 0): ?>
              <span class="absolute -top-1 -right-1 h-2 w-2 bg-red-500 rounded-full animate-pulse"></span>
            <?php elseif ($quickAccess['pending_approvals'] > 0): ?>
              <span class="absolute -top-1 -right-1 h-2 w-2 bg-yellow-500 rounded-full"></span>
            <?php endif; ?>
          </button>

          <div class="dropdown-content">
            <!-- SECCIÓN: PRINCIPAL -->
            <div class="px-4 py-2 bg-gray-50">
              <span class="text-xs font-semibold text-gray-500 uppercase">Principal</span>
            </div>
            <a href="/app/dashboard.php" class="flex items-center gap-3 px-4 py-3 hover:bg-gray-50 text-gray-700">
              <i class='bx bx-home'></i><span class="text-sm">Dashboard</span>
            </a>

            <!-- SECCIÓN: GESTIÓN -->
            <?php if (SecurityLayer::hasPermission('Opportunities', 'CanView') ||
                      SecurityLayer::hasPermission('Contracts', 'CanView') ||
                      SecurityLayer::hasPermission('Products', 'CanView')): ?>
            <div class="border-t border-gray-100 pt-2">
              <div class="px-4 py-2 bg-gray-50">
                <span class="text-xs font-semibold text-gray-500 uppercase">Gestión</span>
              </div>

              <?php if (SecurityLayer::hasPermission('Opportunities', 'CanView')): ?>
              <a href="/app/opportunities.php" class="flex items-center gap-3 px-4 py-3 hover:bg-gray-50 text-gray-700">
                <i class='bx bx-target-lock'></i>
                <div class="flex-1 flex items-center justify-between">
                  <span class="text-sm">Oportunidades</span>
                  <?php if ($quickAccess['opportunities_at_risk'] > 0): ?>
                  <span class="bg-red-100 text-red-600 text-xs px-2 py-0.5 rounded-full font-medium animate-pulse">
                    <?= $quickAccess['opportunities_at_risk'] ?> en riesgo
                  </span>
                  <?php elseif ($quickAccess['pending_approvals'] > 0 && SecurityLayer::hasPermission('Opportunities', 'CanApprove')): ?>
                  <span class="bg-yellow-100 text-yellow-600 text-xs px-2 py-0.5 rounded-full font-medium">
                    <?= $quickAccess['pending_approvals'] ?> aprobaciones
                  </span>
                  <?php endif; ?>
                </div>
              </a>
              <?php endif; ?>

              <?php if (SecurityLayer::hasPermission('Contracts', 'CanView')): ?>
              <a href="/app/contracts.php" class="flex items-center gap-3 px-4 py-3 hover:bg-gray-50 text-gray-700">
                <i class='bx bx-file'></i><span class="text-sm">Contratos</span>
              </a>
              <?php endif; ?>

              <?php if (SecurityLayer::hasPermission('Products', 'CanView')): ?>
              <a href="/app/products.php" class="flex items-center gap-3 px-4 py-3 hover:bg-gray-50 text-gray-700">
                <i class='bx bx-package'></i><span class="text-sm">Productos</span>
              </a>
              <?php endif; ?>

              <?php if (SecurityLayer::hasPermission('Contacts', 'CanView')): ?>
              <a href="/app/contacts.php" class="flex items-center gap-3 px-4 py-3 hover:bg-gray-50 text-gray-700">
                <i class='bx bx-user-plus'></i><span class="text-sm">Contactos</span>
              </a>
              <?php endif; ?>

              <?php if (!empty($user['IsSGS']) || (($user['CompanyType'] ?? '') === 'Partner')): ?>
              <a href="/app/fleet.php" class="flex items-center gap-3 px-4 py-3 hover:bg-gray-50 text-gray-700">
                <i class='bx bx-car'></i><span class="text-sm">Vehículos</span>
              </a>
              <a href="/app/communications.php" class="flex items-center gap-3 px-4 py-3 hover:bg-gray-50 text-gray-700">
                <i class='bx bx-chat'></i><span class="text-sm">Comunicación</span>
              </a>
              <?php endif; ?>
            </div>
            <?php endif; ?>

            <!-- SECCIÓN: SOPORTE -->
            <?php if (SecurityLayer::hasPermission('Incidents', 'CanView')): ?>
            <div class="border-t border-gray-100 pt-2">
              <div class="px-4 py-2 bg-gray-50">
                <span class="text-xs font-semibold text-gray-500 uppercase">Soporte</span>
              </div>
              <a href="/app/incidents.php" class="flex items-center gap-3 px-4 py-3 hover:bg-gray-50 text-gray-700">
                <i class='bx bx-support'></i><span class="text-sm">Incidentes</span>
              </a>
            </div>
            <?php endif; ?>

            <!-- SECCIÓN: ADMINISTRACIÓN -->
            <?php if (SecurityLayer::hasPermission('Companies', 'CanView') ||
                      SecurityLayer::hasPermission('Users', 'CanView')): ?>
            <div class="border-t border-gray-100 pt-2">
              <div class="px-4 py-2 bg-gray-50">
                <span class="text-xs font-semibold text-gray-500 uppercase">Administración</span>
              </div>
              <?php if (SecurityLayer::hasPermission('Companies', 'CanView')): ?>
              <a href="/app/companies.php" class="flex items-center gap-3 px-4 py-3 hover:bg-gray-50 text-gray-700">
                <i class='bx bx-buildings'></i><span class="text-sm">Compañías</span>
              </a>
              <?php endif; ?>
              <?php if (SecurityLayer::hasPermission('Users', 'CanView')): ?>
              <a href="/app/users.php" class="flex items-center gap-3 px-4 py-3 hover:bg-gray-50 text-gray-700">
                <i class='bx bx-user-circle'></i><span class="text-sm">Usuarios</span>
              </a>
              <?php endif; ?>
            </div>
            <?php endif; ?>

            <div class="border-t border-gray-100">
              <a href="/app/logout.php" class="flex items-center gap-3 px-4 py-3 hover:bg-red-50 text-red-600">
                <i class='bx bx-log-out'></i><span class="text-sm">Cerrar sesión</span>
              </a>
            </div>
          </div>
        </div>

        <!-- User Menu -->
        <div class="dropdown relative">
          <button class="flex items-center gap-3 px-3 py-2 text-gray-700 hover:bg-gray-50 rounded-lg transition-colors">
            <div class="text-right">
              <p class="text-sm font-medium"><?= htmlspecialchars($user['FullName'] ?? $user['Email']) ?></p>
              <p class="text-xs text-gray-500"><?= htmlspecialchars($user['UserRole']) ?></p>
            </div>
            <div class="w-10 h-10 bg-purple-500 rounded-full flex items-center justify-center text-white font-medium shadow">
              <?= strtoupper(substr($user['FullName'] ?? $user['Email'], 0, 1)) ?>
            </div>
            <i class='bx bx-chevron-down text-gray-400 text-xs'></i>
          </button>

          <div class="dropdown-content">
            <div class="px-4 py-3 border-b border-gray-100">
              <p class="text-sm font-medium text-gray-900"><?= htmlspecialchars($user['FullName'] ?? 'Usuario') ?></p>
              <p class="text-xs text-gray-500"><?= htmlspecialchars($user['Email']) ?></p>
            </div>

            <a href="/app/profile.php" class="flex items-center gap-3 px-4 py-3 hover:bg-gray-50 text-gray-700">
              <i class='bx bx-user'></i><span class="text-sm">Mi Perfil</span>
            </a>

            <?php if (SecurityLayer::hasPermission('SystemConfig', 'CanView')): ?>
            <a href="/app/configuration.php" class="flex items-center gap-3 px-4 py-3 hover:bg-gray-50 text-gray-700">
              <i class='bx bx-cog'></i><span class="text-sm">Configuración</span>
            </a>
            <?php endif; ?>

            <?php if (SecurityLayer::hasPermission('Users', 'CanView')): ?>
            <a href="/app/permisos.php" class="flex items-center gap-3 px-4 py-3 hover:bg-gray-50 text-gray-700">
              <i class='bx bx-shield'></i><span class="text-sm">Permisos</span>
            </a>
            <?php endif; ?>

            <div class="border-t border-gray-100">
              <a href="/app/logout.php" class="flex items-center gap-3 px-4 py-3 hover:bg-red-50 text-red-600">
                <i class='bx bx-log-out'></i><span class="text-sm">Cerrar sesión</span>
              </a>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</nav>

<!-- QuickAccess Bar -->
<?php $quickAccessBar->render(); ?>

<!-- CSS para dropdowns y animaciones -->
<style>
.dropdown { position: relative; }
.dropdown-content {
  display: none; position: absolute; right: 0; background: #fff; min-width: 220px;
  box-shadow: 0 10px 25px rgba(0,0,0,0.1); z-index: 100; border-radius: 8px; border: 1px solid #e5e7eb;
  max-height: 80vh; overflow-y: auto;
}
.dropdown:hover .dropdown-content { display: block; }
.animate-pulse { animation: pulse 2s cubic-bezier(.4,0,.6,1) infinite; }
@keyframes pulse { 0%,100% {opacity:1;} 50% {opacity:.5;} }
.qa-fab { z-index: 9999 !important; }
.qa-fab.qa-db, .qa-fab.qa-analytics { display: none !important; }
</style>

<!-- QA Widget Scripts (solo Admin/SGS) -->
<?php if (SecurityLayer::canRunQA()): ?>
<script>
window.QA_CONFIG = {
  userId: <?= json_encode($user['UserId']) ?>,
  userRole: <?= json_encode($user['UserRole']) ?>,
  isSGS: <?= json_encode($user['IsSGS'] ?? false) ?>,
  csrfToken: <?= json_encode($csrfToken) ?>
};
</script>
<script src="/app/qa/assets/qa-widget.js?v=<?= date('YmdHis') ?>" defer></script>
<?php endif; ?>

<!-- JavaScript para mejorar UX -->
<script>
// Cerrar dropdowns al hacer clic fuera
document.addEventListener('click', function(e) {
  if (!e.target.closest('.dropdown')) {
    document.querySelectorAll('.dropdown-content').forEach(function(dd){ 
      dd.style.display = 'none'; 
    });
  }
});

// Evitar que los clicks dentro del dropdown lo cierren
document.querySelectorAll('.dropdown-content').forEach(function(dd){
  dd.addEventListener('click', function(e){ 
    e.stopPropagation(); 
  });
});
</script>