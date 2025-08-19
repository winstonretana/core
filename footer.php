<?php
// includes/footer.php
$user = $_SESSION['channel_user'] ?? null;
?>
<!-- Footer -->
<footer class="bg-white border-t border-gray-200 mt-auto">
    <div class="px-4 sm:px-6 lg:px-8">
        <div class="py-8">
            <!-- Footer Content Grid -->
            <div class="grid grid-cols-1 md:grid-cols-4 gap-8">
                <!-- Company Info -->
                <div class="col-span-1 md:col-span-2">
                    <div class="flex items-center mb-4">
                        <div class="w-10 h-10 bg-gradient-to-br from-indigo-500 to-purple-600 rounded-xl flex items-center justify-center shadow">
                            <i class='bx bx-network-chart text-white text-xl'></i>
                        </div>
                        <div class="ml-3">
                            <h3 class="text-lg font-semibold text-gray-900">Channel Management</h3>
                            <p class="text-xs text-gray-500">SuppCenter Global Services</p>
                        </div>
                    </div>
                    <p class="text-sm text-gray-600 max-w-md">
                        Sistema de gestión integral de oportunidades comerciales y partners. 
                        Optimizando procesos y maximizando resultados.
                    </p>
                </div>
                
                <!-- Quick Links -->
                <div>
                    <h4 class="text-sm font-semibold text-gray-900 mb-3">Acceso Rápido</h4>
                    <ul class="space-y-2">
                        <li>
                            <a href="/app/dashboard.php" class="text-sm text-gray-600 hover:text-indigo-600 transition-colors">
                                <i class='bx bx-home-alt text-xs mr-1'></i> Dashboard
                            </a>
                        </li>
                        
                        <?php if ($user && ($user['IsSGS'] || $user['IsPartner'])): ?>
                        <li>
                            <a href="/app/opportunities.php" class="text-sm text-gray-600 hover:text-indigo-600 transition-colors">
                                <i class='bx bx-target-lock text-xs mr-1'></i> Oportunidades
                            </a>
                        </li>
                        <?php endif; ?>
                        
                        <?php if ($user && $user['IsSGS'] && ($user['UserRole'] === 'Admin' || $user['UserRole'] === 'Manager')): ?>
                        <li>
                            <a href="/app/approvals.php" class="text-sm text-gray-600 hover:text-indigo-600 transition-colors">
                                <i class='bx bx-check-circle text-xs mr-1'></i> Aprobaciones
                                <?php if (($pendingCount ?? 0) > 0): ?>
                                <span class="ml-1 px-1.5 py-0.5 bg-yellow-100 text-yellow-800 rounded-full text-xs">
                                    <?= $pendingCount ?>
                                </span>
                                <?php endif; ?>
                            </a>
                        </li>
                        <?php endif; ?>
                        
                        <?php if ($user && $user['IsPartner']): ?>
                        <li>
                            <a href="/app/my-opportunities.php" class="text-sm text-gray-600 hover:text-indigo-600 transition-colors">
                                <i class='bx bx-briefcase text-xs mr-1'></i> Mis Oportunidades
                            </a>
                        </li>
                        <li>
                            <a href="/app/karma.php" class="text-sm text-gray-600 hover:text-indigo-600 transition-colors">
                                <i class='bx bx-trophy text-xs mr-1'></i> Karma/Darma
                            </a>
                        </li>
                        <?php endif; ?>
                    </ul>
                </div>
                
                <!-- Support & Help -->
                <div>
                    <h4 class="text-sm font-semibold text-gray-900 mb-3">Soporte</h4>
                    <ul class="space-y-2">
                        <li>
                            <a href="#" onclick="showHelp()" class="text-sm text-gray-600 hover:text-indigo-600 transition-colors">
                                <i class='bx bx-help-circle text-xs mr-1'></i> Centro de Ayuda
                            </a>
                        </li>
                        <li>
                            <a href="#" onclick="showDocs()" class="text-sm text-gray-600 hover:text-indigo-600 transition-colors">
                                <i class='bx bx-book text-xs mr-1'></i> Documentación
                            </a>
                        </li>
                        <li>
                            <a href="mailto:soporte@suppcenter.global" class="text-sm text-gray-600 hover:text-indigo-600 transition-colors">
                                <i class='bx bx-envelope text-xs mr-1'></i> Contacto
                            </a>
                        </li>
                        <li>
                            <span class="text-sm text-gray-500">
                                <i class='bx bx-phone text-xs mr-1'></i> +506 2222-3333
                            </span>
                        </li>
                    </ul>
                </div>
            </div>
            
            <!-- Bottom Bar -->
            <div class="mt-8 pt-8 border-t border-gray-200">
                <div class="flex flex-col md:flex-row justify-between items-center space-y-2 md:space-y-0">
                    <!-- Copyright -->
                    <div class="text-sm text-gray-500">
                        © <?= date('Y') ?> SuppCenter Global Services. Todos los derechos reservados.
                    </div>
                    
                    <!-- Version & Status -->
                    <div class="flex items-center space-x-4 text-sm text-gray-500">
                        <span class="flex items-center">
                            <span class="w-2 h-2 bg-green-500 rounded-full mr-2 animate-pulse"></span>
                            Sistema Operativo
                        </span>
                        <span>v3.0.0</span>
                        <span class="hidden md:inline">|</span>
                        <span class="hidden md:inline">
                            <?= date('d/m/Y H:i') ?>
                        </span>
                        <?php if ($user): ?>
                        <span class="hidden md:inline">|</span>
                        <span class="hidden md:inline">
                            <?= htmlspecialchars($user['CompanyName']) ?>
                        </span>
                        <?php endif; ?>
                    </div>
                </div>
            </div>
        </div>
    </div>
</footer>

<!-- Back to Top Button -->
<button onclick="scrollToTop()" 
        id="backToTop"
        class="hidden fixed bottom-8 right-8 p-3 bg-indigo-600 hover:bg-indigo-700 text-white rounded-full shadow-lg transition-all z-40">
    <i class='bx bx-chevron-up text-xl'></i>
</button>

<!-- Footer Scripts -->
<script>
// Show/Hide Back to Top Button
window.addEventListener('scroll', function() {
    const backToTop = document.getElementById('backToTop');
    if (window.pageYOffset > 300) {
        backToTop.classList.remove('hidden');
    } else {
        backToTop.classList.add('hidden');
    }
});

// Scroll to Top Function
function scrollToTop() {
    window.scrollTo({
        top: 0,
        behavior: 'smooth'
    });
}

// Help modal
function showHelp() {
    // TODO: Implementar modal de ayuda
    alert('Centro de Ayuda - En desarrollo');
}

// Documentation modal
function showDocs() {
    // TODO: Implementar documentación
    alert('Documentación - En desarrollo');
}
</script>

