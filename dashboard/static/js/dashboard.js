// ================================================================
//  SIEM Africa — Dashboard JS v3.0
//  Refresh automatique 30s + Chart.js + API stats
// ================================================================

const REFRESH_INTERVAL = 30000; // 30 secondes
let refreshTimer;
const progress = document.getElementById('refreshProgress');

// ── Refresh automatique ───────────────────────────────────────
function startRefreshTimer() {
    if (!progress) return;
    progress.style.transition = 'none';
    progress.style.width = '0%';

    setTimeout(() => {
        progress.style.transition = `width ${REFRESH_INTERVAL}ms linear`;
        progress.style.width = '100%';
    }, 50);

    refreshTimer = setTimeout(() => {
        if (typeof fetchStats === 'function') {
            fetchStats();
        } else {
            window.location.reload();
        }
        startRefreshTimer();
    }, REFRESH_INTERVAL);
}

// Réinitialiser quand l'utilisateur interagit
document.addEventListener('click', (e) => {
    if (e.target.closest('a') || e.target.closest('button')) return;
    clearTimeout(refreshTimer);
    startRefreshTimer();
});

// ── Fetch stats API /api/stats/ ───────────────────────────────
function fetchStats() {
    fetch('/api/stats/')
        .then(r => r.json())
        .then(data => {
            updateStat('sv-critique', data.critique);
            updateStat('sv-haute',    data.haute);
            updateStat('sv-moyenne',  data.moyenne);
            updateStat('sv-faible',   data.faible);
            updateStat('sv-honeypot', data.honeypot_24h);
            updateStat('sv-today',    data.aujourd_hui);
            updateStat('sv-resolues', data.resolues);
            updateStat('sv-fp',       data.fp_predits);

            // Mettre à jour les graphiques si disponibles
            if (window.chartAlertes7j && data.alertes_7j && data.alertes_7j.length > 0) {
                window.chartAlertes7j.data.labels   = data.alertes_7j.map(d => d.jour);
                window.chartAlertes7j.data.datasets[0].data = data.alertes_7j.map(d => d.critique || 0);
                window.chartAlertes7j.data.datasets[1].data = data.alertes_7j.map(d => d.haute || 0);
                window.chartAlertes7j.data.datasets[2].data = data.alertes_7j.map(d => d.nb || 0);
                window.chartAlertes7j.update('none');
            }

            if (window.chartCategories && data.top_categories && data.top_categories.length > 0) {
                window.chartCategories.data.labels   = data.top_categories.map(d => d.categorie);
                window.chartCategories.data.datasets[0].data = data.top_categories.map(d => d.nb);
                window.chartCategories.update('none');
            }

            if (window.chartParHeure && data.alertes_par_heure) {
                window.chartParHeure.data.datasets[0].data = data.alertes_par_heure;
                window.chartParHeure.update('none');
            }

            if (window.chartTopIps && data.top_ips && data.top_ips.length > 0) {
                window.chartTopIps.data.labels   = data.top_ips.slice(0,8).map(d => d.ip_source);
                window.chartTopIps.data.datasets[0].data = data.top_ips.slice(0,8).map(d => d.nb);
                window.chartTopIps.update('none');
            }
        })
        .catch(() => {}); // Silencieux si réseau KO
}

function updateStat(id, val) {
    const el = document.getElementById(id);
    if (el && val !== undefined) {
        const old = parseInt(el.textContent) || 0;
        const newVal = parseInt(val) || 0;
        el.textContent = newVal;
        // Flash si la valeur augmente
        if (newVal > old) {
            el.style.transition = 'color 0.3s';
            el.style.color = '#ef4444';
            setTimeout(() => el.style.color = '', 800);
        }
    }
}

// ── Initialisation Chart.js ───────────────────────────────────
function initCharts(data7j, dataCats, dataIps, dataHeures, lang) {
    const isDark = document.documentElement.getAttribute('data-theme') !== 'light';
    const textColor = isDark ? '#8fa3c0' : '#475569';
    const gridColor = isDark ? 'rgba(42,58,92,0.4)' : 'rgba(226,232,240,0.8)';

    Chart.defaults.color        = textColor;
    Chart.defaults.font.family  = "'JetBrains Mono', monospace";
    Chart.defaults.font.size    = 11;

    // Graphique 1 : Alertes 7 jours
    const ctx1 = document.getElementById('chartAlertes7j');
    if (ctx1 && data7j && data7j.length > 0) {
        window.chartAlertes7j = new Chart(ctx1, {
            type: 'line',
            data: {
                labels: data7j.map(d => d.jour),
                datasets: [
                    {
                        label: lang === 'en' ? 'Critical' : 'Critique',
                        data: data7j.map(d => d.critique || 0),
                        borderColor: '#ef4444',
                        backgroundColor: 'rgba(239,68,68,0.1)',
                        tension: 0.4, fill: true, pointRadius: 4,
                    },
                    {
                        label: lang === 'en' ? 'High' : 'Haute',
                        data: data7j.map(d => d.haute || 0),
                        borderColor: '#f97316',
                        backgroundColor: 'rgba(249,115,22,0.08)',
                        tension: 0.4, fill: true, pointRadius: 4,
                    },
                    {
                        label: 'Total',
                        data: data7j.map(d => d.nb || 0),
                        borderColor: '#3b82f6',
                        backgroundColor: 'rgba(59,130,246,0.05)',
                        tension: 0.4, fill: true,
                        borderDash: [4, 4], pointRadius: 3,
                    },
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                plugins: { legend: { position: 'top', labels: { boxWidth: 12 } } },
                scales: {
                    x: { grid: { color: gridColor } },
                    y: { grid: { color: gridColor }, beginAtZero: true }
                }
            }
        });
    }

    // Graphique 2 : Catégories (camembert)
    const ctx2 = document.getElementById('chartCategories');
    if (ctx2 && dataCats && dataCats.length > 0) {
        const colors = [
            '#3b82f6','#ef4444','#f97316','#eab308',
            '#22c55e','#a855f7','#06b6d4','#ec4899'
        ];
        window.chartCategories = new Chart(ctx2, {
            type: 'doughnut',
            data: {
                labels: dataCats.map(d => d.categorie),
                datasets: [{
                    data: dataCats.map(d => d.nb),
                    backgroundColor: colors,
                    borderWidth: 2,
                    borderColor: isDark ? '#1a2235' : '#ffffff',
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                plugins: {
                    legend: {
                        position: 'right',
                        labels: { boxWidth: 12, padding: 8 }
                    }
                },
                cutout: '65%',
            }
        });
    }

    // Graphique 3 : Par heure (histogramme)
    const ctx3 = document.getElementById('chartParHeure');
    if (ctx3) {
        const hours = Array.from({length: 24}, (_, i) => `${String(i).padStart(2,'0')}h`);
        window.chartParHeure = new Chart(ctx3, {
            type: 'bar',
            data: {
                labels: hours,
                datasets: [{
                    label: lang === 'en' ? 'Alerts' : 'Alertes',
                    data: (dataHeures && dataHeures.length) ? dataHeures : new Array(24).fill(0),
                    backgroundColor: 'rgba(59,130,246,0.6)',
                    borderColor: '#3b82f6',
                    borderWidth: 1,
                    borderRadius: 4,
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                plugins: { legend: { display: false } },
                scales: {
                    x: { grid: { color: gridColor } },
                    y: { grid: { color: gridColor }, beginAtZero: true }
                }
            }
        });
    }

    // Graphique 4 : Top IPs (barres horizontales)
    const ctx4 = document.getElementById('chartTopIps');
    if (ctx4 && dataIps && dataIps.length > 0) {
        const ipColors = dataIps.slice(0,8).map(d =>
            d.gravite_max >= 4 ? 'rgba(239,68,68,0.7)' :
            d.gravite_max >= 3 ? 'rgba(249,115,22,0.7)' :
            'rgba(59,130,246,0.7)'
        );
        window.chartTopIps = new Chart(ctx4, {
            type: 'bar',
            data: {
                labels: dataIps.slice(0,8).map(d => d.ip_source),
                datasets: [{
                    label: lang === 'en' ? 'Alerts' : 'Alertes',
                    data: dataIps.slice(0,8).map(d => d.nb),
                    backgroundColor: ipColors,
                    borderRadius: 4,
                }]
            },
            options: {
                indexAxis: 'y',
                responsive: true,
                maintainAspectRatio: true,
                plugins: { legend: { display: false } },
                scales: {
                    x: { grid: { color: gridColor }, beginAtZero: true },
                    y: {
                        grid: { display: false },
                        ticks: {
                            font: {
                                family: "'JetBrains Mono', monospace",
                                size: 10
                            }
                        }
                    }
                }
            }
        });
    }
}

// ── Démarrer au chargement ────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    startRefreshTimer();
});
