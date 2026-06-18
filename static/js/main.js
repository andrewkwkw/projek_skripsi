        // Chart Config
        Chart.defaults.color = '#94A3B8';
        Chart.defaults.font.family = 'Outfit';
        Chart.defaults.scale.grid.color = 'rgba(255, 255, 255, 0.05)';

        let chart1 = null;
        let chart2 = null;
        let currentTab = 'analysis';
        let currentRawLogs = [];
        let currentAnalysisLogs = [];
        let filteredAnalysisLogs = [];
        let currentPage = 1;
        const rowsPerPage = 50;

        let currentTopUsers = [];
        let filteredTopUsers = [];
        let currentTopUserPage = 1;
        const topUserRowsPerPage = 50;

        let liveTailInterval = null;
        let isLiveTailPaused = false;

        

        document.addEventListener('DOMContentLoaded', () => {
            setupLiveStream();

            // Search listener untuk Top Target User
            document.getElementById('search-topuser').addEventListener('input', (e) => {
                const query = e.target.value.toLowerCase();
                filteredTopUsers = currentTopUsers.filter(u => u.username.toLowerCase().includes(query));
                currentTopUserPage = 1;
                renderTopUsersTable();
            });
        });

        
        let eventSource = null;

        function fetchActiveData() {
            // Disabled manual fetch, managed by SSE
            const icon = document.getElementById('refresh-icon');
            icon.classList.add('fa-spin');
            setTimeout(() => icon.classList.remove('fa-spin'), 500);
        }

        function switchTab(tab) {
            currentTab = tab;
            const btnAnalysis = document.getElementById('tab-analysis');
            const btnTopuser = document.getElementById('tab-topuser');
            const btnLivelog = document.getElementById('tab-livelog');
            const btnRawdata = document.getElementById('tab-rawdata');
            
            const pageAnalysis = document.getElementById('page-analysis');
            const pageTopuser = document.getElementById('page-topuser');
            const pageLivelog = document.getElementById('page-livelog');
            const pageRawdata = document.getElementById('page-rawdata');
            
            const headerTitle = document.getElementById('header-title');
            const headerSubtitle = document.getElementById('header-subtitle');

            const activeClass = "w-full flex items-center gap-3 px-4 py-3.5 rounded-xl bg-primary/10 text-primary font-semibold border border-primary/20 transition-all shadow-[inset_4px_0_0_0_#3B82F6]";
            const inactiveClass = "w-full flex items-center gap-3 px-4 py-3.5 rounded-xl bg-transparent text-textMuted hover:text-white hover:bg-gray-800/50 font-medium border border-transparent transition-all";

            // Reset all buttons and pages
            btnAnalysis.className = inactiveClass;
            btnTopuser.className = inactiveClass;
            btnLivelog.className = inactiveClass;
            btnRawdata.className = inactiveClass;
            
            pageAnalysis.classList.add('hidden');
            pageTopuser.classList.add('hidden');
            pageLivelog.classList.add('hidden');
            pageRawdata.classList.add('hidden');

            if (tab === 'analysis') {
                btnAnalysis.className = activeClass;
                pageAnalysis.classList.remove('hidden');
                headerTitle.textContent = "Hasil Analisis Algoritma";
                headerSubtitle.textContent = "Pemantauan log otentikasi secara real-time";
                
            } else if (tab === 'topuser') {
                btnTopuser.className = activeClass;
                pageTopuser.classList.remove('hidden');
                headerTitle.textContent = "Target Username";
                headerSubtitle.textContent = "Analisis username paling diincar peretas";

            } else if (tab === 'livelog') {
                btnLivelog.className = activeClass;
                pageLivelog.classList.remove('hidden');
                headerTitle.textContent = "Log Aktivitas";
                headerSubtitle.textContent = "Rekapan login berhasil dan gagal terbaru";
                
            } else if (tab === 'rawdata') {
                btnRawdata.className = activeClass;
                pageRawdata.classList.remove('hidden');
                headerTitle.textContent = "Data Mentah";
                headerSubtitle.textContent = "Penelusuran full text file log";
            }
        }

        function toggleLoading(show, text = 'Memuat Data...') {
            const loading = document.getElementById('loading-state');
            const pages = document.querySelectorAll('#page-analysis, #page-topuser, #page-livelog, #page-rawdata');
            document.getElementById('loading-text').textContent = text;
            
            if (show) {
                loading.classList.remove('hidden');
                pages.forEach(p => p.classList.add('hidden'));
            } else {
                loading.classList.add('hidden');
                document.getElementById('page-' + currentTab).classList.remove('hidden');
            }
        }

        function changePage(direction) {
            currentPage += direction;
            renderAnalysisTable();
        }

        function renderAnalysisTable() {
            const tbody = document.getElementById('analysis-table');
            
            if(filteredAnalysisLogs.length === 0) {
                tbody.innerHTML = `<tr><td colspan="6" class="px-6 py-8 text-center text-textMuted">Data tidak ditemukan.</td></tr>`;
                document.getElementById('pagination-info').textContent = 'Tidak ada data';
                document.getElementById('btn-prev').disabled = true;
                document.getElementById('btn-next').disabled = true;
                return;
            }
            
            const totalRows = filteredAnalysisLogs.length;
            const totalPages = Math.ceil(totalRows / rowsPerPage);
            
            if(currentPage < 1) currentPage = 1;
            if(currentPage > totalPages) currentPage = totalPages;
            
            const startIndex = (currentPage - 1) * rowsPerPage;
            const endIndex = Math.min(startIndex + rowsPerPage, totalRows);
            const paginatedLogs = filteredAnalysisLogs.slice(startIndex, endIndex);
            
            let rows = '';
            paginatedLogs.forEach(log => {
                let sevBadge = '';
                if(log.severity === 'CRITICAL') sevBadge = '<span class="text-critical font-semibold">CRITICAL</span>';
                else if (log.severity === 'WARNING') sevBadge = '<span class="text-warning font-semibold">WARNING</span>';
                else sevBadge = '<span class="text-normal font-semibold">NORMAL</span>';

                let ifBadge = log.if_label === -1 ? '<span class="text-critical font-mono font-bold">-1</span>' : '<span class="text-textMuted font-mono">1</span>';

                rows += `
                    <tr class="hover:bg-panel transition-colors border-b border-borderWazuh last:border-0">
                        <td class="px-4 py-3 text-textMuted font-mono text-[11px]">${log.time_window || '-'}</td>
                        <td class="px-4 py-3 text-primary font-medium cursor-pointer hover:underline">${log.ip}</td>
                        <td class="px-4 py-3 font-mono text-textMain">${log.failed_count}</td>
                        <td class="px-4 py-3 font-mono text-textMuted">${log.z_score}</td>
                        <td class="px-4 py-3">${ifBadge}</td>
                        <td class="px-4 py-3 text-[11px]">${sevBadge}</td>
                                            </tr>
                `;
            });
            tbody.innerHTML = rows;

            document.getElementById('pagination-info').textContent = `Menampilkan ${startIndex + 1}-${endIndex} dari ${totalRows} data (Hal ${currentPage}/${totalPages})`;
            document.getElementById('btn-prev').disabled = (currentPage === 1);
            document.getElementById('btn-next').disabled = (currentPage === totalPages);
        }

        function prevTopUserPage() {
            if(currentTopUserPage > 1) {
                currentTopUserPage--;
                renderTopUsersTable();
            }
        }

        function nextTopUserPage() {
            const totalPages = Math.ceil(filteredTopUsers.length / topUserRowsPerPage);
            if(currentTopUserPage < totalPages) {
                currentTopUserPage++;
                renderTopUsersTable();
            }
        }

        // =====================================
        // SEARCH / FILTER FUNCTIONS
        // =====================================

        function filterAnalysisLogs() {
            const query = document.getElementById('search-analysis').value.toLowerCase();
            filteredAnalysisLogs = currentAnalysisLogs.filter(log => {
                return log.ip.toLowerCase().includes(query) || 
                       log.reason.toLowerCase().includes(query) ||
                       (log.time_window && log.time_window.toLowerCase().includes(query));
            });
            currentPage = 1;
            renderAnalysisTable();
        }

        function filterSuccessLogs() {
            const query = document.getElementById('search-success').value.toLowerCase();
            const filtered = currentSuccessLogs.filter(log => log.toLowerCase().includes(query));
            document.getElementById('log-success').innerHTML = filtered.join('<br>') || 'Tidak ada data matching.';
        }

        function filterFailedLogs() {
            const query = document.getElementById('search-failed').value.toLowerCase();
            const filtered = currentFailedLogs.filter(log => log.toLowerCase().includes(query));
            document.getElementById('log-failed').innerHTML = filtered.join('<br>') || 'Tidak ada data matching.';
        }

        
        function toggleLiveTail() {
            isLiveTailPaused = !isLiveTailPaused;
            const btnIcon = document.getElementById('icon-livetail');
            const btnText = document.getElementById('text-livetail');
            
            if (isLiveTailPaused) {
                btnIcon.className = 'fa-solid fa-play text-primary';
                btnText.textContent = 'Resume Live Tail';
            } else {
                btnIcon.className = 'fa-solid fa-pause text-warning';
                btnText.textContent = 'Pause Live Tail';
                // Force update right away when resuming
                if(!document.getElementById('log-search').value) {
                    document.getElementById('log-raw').innerHTML = currentRawLogs.join('') || 'Tidak ada data.';
                }
            }
        }

        function filterLogs() {
            const query = document.getElementById('log-search').value.toLowerCase();
            const filtered = currentRawLogs.filter(log => log.toLowerCase().includes(query));
            document.getElementById('log-raw').innerHTML = filtered.join('') || 'Tidak ada data matching.';
        }

        function renderTopUsersTable() {
            const tbody = document.getElementById('topuser-table');
            if(!filteredTopUsers || filteredTopUsers.length === 0) {
                tbody.innerHTML = `<tr><td colspan="3" class="px-6 py-8 text-center text-textMuted">Data tidak ditemukan.</td></tr>`;
                document.getElementById('topuser-pagination-info').textContent = 'Tidak ada data';
                document.getElementById('btn-topuser-prev').disabled = true;
                document.getElementById('btn-topuser-next').disabled = true;
                return;
            }

            const totalRows = filteredTopUsers.length;
            const totalPages = Math.ceil(totalRows / topUserRowsPerPage);
            const startIndex = (currentTopUserPage - 1) * topUserRowsPerPage;
            const endIndex = Math.min(startIndex + topUserRowsPerPage, totalRows);
            const paginatedData = filteredTopUsers.slice(startIndex, endIndex);

            let rows = '';
            paginatedData.forEach((u, idx) => {
                let absoluteIdx = startIndex + idx;
                rows += `
                    <tr class="hover:bg-panel border-b border-borderWazuh last:border-0 transition-colors">
                        <td class="px-4 py-3 text-center text-textMuted">${absoluteIdx + 1}</td>
                        <td class="px-4 py-3 font-medium text-textMain">${u.username}</td>
                        <td class="px-4 py-3 font-mono text-textMuted">${u.count}</td>
                    </tr>
                `;
            });
            tbody.innerHTML = rows;
            
            document.getElementById('topuser-pagination-info').textContent = `Menampilkan ${startIndex + 1}-${endIndex} dari ${totalRows} data (Hal ${currentTopUserPage}/${totalPages})`;
            document.getElementById('btn-topuser-prev').disabled = (currentTopUserPage === 1);
            document.getElementById('btn-topuser-next').disabled = (currentTopUserPage === totalPages);
        }

        // Variable global untuk mencegah fetching berkali-kali jika data belum berubah
        let lastLiveLogFetch = 0;
        let currentSuccessLogs = [];
        let currentFailedLogs = [];
        
        function fetchLiveLogData() {
            // Hindari spam fetch jika pindah-pindah tab dengan cepat (cache frontend 5 detik)
            const now = Date.now();
            if(now - lastLiveLogFetch < 5000 && currentRawLogs.length > 0) {
                return Promise.resolve();
            }
            
            toggleLoading(true, 'Menarik data log terbaru...');
            return fetch('/api/livelog')
                .then(res => res.json())
                .then(data => {
                    if(data.error) { alert(data.error); return; }
                    
                    currentSuccessLogs = data.success_logs;
                    currentFailedLogs = data.failed_logs;
                    currentRawLogs = data.raw_logs;
                    
                    document.getElementById('log-success').innerHTML = currentSuccessLogs.join('<br>') || 'Tidak ada data.';
                    document.getElementById('log-failed').innerHTML = currentFailedLogs.join('<br>') || 'Tidak ada data.';
                    document.getElementById('log-raw').innerHTML = currentRawLogs.join('') || 'Tidak ada data.';
                    
                    lastLiveLogFetch = Date.now();
                })
                .finally(() => toggleLoading(false));
        }

        function renderCharts(logs, summary) {
            const top15 = logs.slice(0, 15);
            const labels = top15.map(r => `${r.ip}`);
            const zscoreData = top15.map(r => r.z_score);
            
            // Tentukan threshold Z-Score
            const THRESHOLD = 3.0;
            const maxZ = Math.max(...zscoreData, THRESHOLD + 1); // Pastikan Y axis selalu muat

            // Global Chart Style Overrides
            Chart.defaults.color = '#9CA3AF';
            Chart.defaults.font.family = "'Inter', sans-serif";
            Chart.defaults.plugins.tooltip.backgroundColor = 'rgba(26, 29, 39, 0.9)';
            Chart.defaults.plugins.tooltip.titleColor = '#E0E0E0';
            Chart.defaults.plugins.tooltip.bodyColor = '#9CA3AF';
            Chart.defaults.plugins.tooltip.borderColor = '#343B4A';
            Chart.defaults.plugins.tooltip.borderWidth = 1;
            Chart.defaults.plugins.tooltip.padding = 12;
            Chart.defaults.plugins.tooltip.cornerRadius = 4;
            Chart.defaults.plugins.tooltip.displayColors = true;

            // CHART 1: Z-SCORE (Threshold Line Chart)
            if(chart1) chart1.destroy();
            const ctx1 = document.getElementById('chartZScore').getContext('2d');
            
            // Custom Plugin untuk menggambar Background Merah (Threshold Area)
            const thresholdAreaPlugin = {
                id: 'thresholdArea',
                beforeDraw: (chart) => {
                    const ctx = chart.canvas.getContext('2d');
                    const yAxis = chart.scales.y;
                    const xAxis = chart.scales.x;
                    
                    if (yAxis.max > THRESHOLD) {
                        const topY = yAxis.getPixelForValue(yAxis.max);
                        const bottomY = yAxis.getPixelForValue(THRESHOLD);
                        
                        ctx.save();
                        ctx.fillStyle = 'rgba(239, 68, 68, 0.05)'; // Merah sangat transparan
                        ctx.fillRect(xAxis.left, topY, xAxis.width, bottomY - topY);
                        
                        // Garis putus-putus merah
                        ctx.beginPath();
                        ctx.setLineDash([5, 5]);
                        ctx.moveTo(xAxis.left, bottomY);
                        ctx.lineTo(xAxis.right, bottomY);
                        ctx.lineWidth = 1;
                        ctx.strokeStyle = 'rgba(239, 68, 68, 0.8)';
                        ctx.stroke();
                        ctx.restore();
                        
                        // Teks label
                        ctx.font = '10px Inter';
                        ctx.fillStyle = 'rgba(239, 68, 68, 0.8)';
                        ctx.textAlign = 'right';
                        ctx.fillText('Area Threshold Anomali > ' + THRESHOLD, xAxis.right - 5, bottomY - 5);
                    }
                }
            };
            
            function createGradient(context, isFill) {
                try {
                    const chart = context.chart;
                    const {ctx, chartArea, scales} = chart;
                    
                    // Fallback color during initial setup before chartArea is available
                    if (!chartArea || chartArea.bottom === chartArea.top) {
                        return isFill ? 'rgba(59, 130, 246, 0.2)' : '#3B82F6';
                    }
                    
                    const yAxis = scales.y;
                    if(!yAxis) return isFill ? 'rgba(59, 130, 246, 0.2)' : '#3B82F6';
                    
                    const thresholdPixel = yAxis.getPixelForValue(THRESHOLD);
                    if (isNaN(thresholdPixel)) return isFill ? 'rgba(59, 130, 246, 0.2)' : '#3B82F6';

                    const gradient = ctx.createLinearGradient(0, chartArea.top, 0, chartArea.bottom);
                    let offset = (thresholdPixel - chartArea.top) / (chartArea.bottom - chartArea.top);
                    offset = Math.max(0, Math.min(1, offset));
                    
                    if (isFill) {
                        gradient.addColorStop(0, 'rgba(239, 68, 68, 0.5)'); // Merah atas
                        gradient.addColorStop(offset, 'rgba(239, 68, 68, 0.2)'); // Merah sampai threshold
                        gradient.addColorStop(offset, 'rgba(59, 130, 246, 0.4)'); // Biru mulai threshold
                        gradient.addColorStop(1, 'rgba(59, 130, 246, 0.05)'); // Biru pudar bawah
                    } else {
                        gradient.addColorStop(0, '#EF4444'); // Garis Merah atas
                        gradient.addColorStop(offset, '#EF4444');
                        gradient.addColorStop(offset, '#3B82F6'); // Garis Biru bawah
                        gradient.addColorStop(1, '#3B82F6');
                    }
                    return gradient;
                } catch (e) {
                    console.error("Gradient error", e);
                    return isFill ? 'rgba(59, 130, 246, 0.2)' : '#3B82F6';
                }
            }

            // Sanitasi data agar tidak ada 0 atau negatif (Logaritma tidak bisa 0)
            const safeZScoreData = zscoreData.map(val => Math.max(0.1, val));
            
            chart1 = new Chart(ctx1, {
                type: 'line',
                data: {
                    labels: labels,
                    datasets: [
                        {
                            label: 'Z-Score',
                            data: safeZScoreData,
                            borderWidth: 2,
                            tension: 0.3, // Curve mulus seperti di referensi
                            pointRadius: 4,
                            pointHoverRadius: 6,
                            fill: true, // Nyalakan fill area di bawah garis!
                            borderColor: function(context) { return createGradient(context, false); },
                            backgroundColor: function(context) { return createGradient(context, true); },
                            pointBackgroundColor: ctx => ctx.raw >= THRESHOLD ? '#EF4444' : '#3B82F6',
                            pointBorderColor: ctx => ctx.raw >= THRESHOLD ? '#EF4444' : '#3B82F6',
                        }
                    ]
                },
                plugins: [thresholdAreaPlugin],
                options: { 
                    responsive: true, maintainAspectRatio: false,
                    interaction: { mode: 'index', intersect: false },
                    plugins: { 
                        legend: { display: false },
                        tooltip: {
                            callbacks: {
                                title: (items) => `Target: ${items[0].label}`,
                                label: (item) => `Z-Score: ${item.raw}`
                            }
                        }
                    },
                    scales: { 
                        x: { 
                            grid: { color: 'rgba(255,255,255,0.05)' },
                            ticks: { font: { size: 10 } }
                        },
                        y: { 
                            type: 'logarithmic',
                            min: 0.1,
                            max: maxZ,
                            title: { display: true, text: 'Z-Score (Log Scale)', color: '#9CA3AF', font: { size: 10 } },
                            grid: { color: 'rgba(255,255,255,0.05)' }
                        }
                    }
                }
            });

            // CHART 2: ISOLATION FOREST
            if(chart2) chart2.destroy();
            const ctx2 = document.getElementById('chartIsolationForest').getContext('2d');
            
            const ifData = summary.chart_if || [];
            chart2 = new Chart(ctx2, {
                type: 'line',
                data: {
                    labels: labels,
                    datasets: [{
                        label: 'Isolation Forest Output',
                        data: ifData,
                        borderColor: '#10B981',
                        backgroundColor: '#10B981',
                        borderWidth: 2,
                        pointRadius: 5,
                        pointBackgroundColor: function(context) {
                            const index = context.dataIndex;
                            const value = context.dataset.data[index];
                            return value === -1 ? '#EF4444' : '#10B981'; // Merah jika Anomaly
                        },
                        pointBorderColor: 'transparent',
                        showLine: false
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        y: {
                            min: -1.5,
                            max: 1.5,
                            ticks: {
                                stepSize: 1,
                                callback: function(value) {
                                    if(value === -1) return '-1 (Anomaly)';
                                    if(value === 1) return '1 (Normal)';
                                    return '';
                                }
                            }
                        }
                    },
                    plugins: { legend: { display: false } }
                }
            });
        }

        
        function setupLiveStream() {
            toggleLoading(true, 'Menghubungkan ke Live Stream AI...');
            if(eventSource) {
                eventSource.close();
            }
            
            eventSource = new EventSource('/api/stream');
            eventSource.onmessage = function(event) {
                const data = JSON.parse(event.data);
                toggleLoading(false);
                
                // --- 1. Update Analysis (Charts, KPI, Table) ---
                if(data.analysis) {
                    const analysis = data.analysis;
                    
                    document.getElementById('kpi-total').textContent = analysis.summary.total_ips;
                    document.getElementById('kpi-unique').textContent = analysis.summary.total_ips;
                    document.getElementById('kpi-critical').textContent = analysis.summary.critical;
                    document.getElementById('stat-peak-z').textContent = analysis.peak_zscore_ip;
                    
                    currentAnalysisLogs = analysis.logs || [];
                    
                    // Jangan re-render tabel jika user sedang search
                    const searchQuery = document.getElementById('search-analysis').value;
                    if(!searchQuery) {
                        filteredAnalysisLogs = currentAnalysisLogs;
                        renderAnalysisTable();
                    }
                    
                    renderCharts(analysis.logs, analysis);
                    
                    currentTopUsers = analysis.top_users || [];
                    const topuserQuery = document.getElementById('search-topuser').value;
                    if(!topuserQuery) {
                        filteredTopUsers = currentTopUsers;
                        renderTopUsersTable();
                    }
                }
                
                // --- 2. Update Livelog & Raw Data ---
                if(data.livelog) {
                    currentSuccessLogs = data.livelog.success_logs || [];
                    currentFailedLogs = data.livelog.failed_logs || [];
                    currentRawLogs = data.livelog.raw_logs || [];
                    
                    // Hanya update UI jika user tidak sedang search
                    if(!document.getElementById('search-success').value) {
                        document.getElementById('log-success').innerHTML = currentSuccessLogs.join('<br>') || 'Tidak ada data.';
                    }
                    if(!document.getElementById('search-failed').value) {
                        document.getElementById('log-failed').innerHTML = currentFailedLogs.join('<br>') || 'Tidak ada data.';
                    }
                    if(!document.getElementById('log-search').value && !isLiveTailPaused) {
                        document.getElementById('log-raw').innerHTML = currentRawLogs.join('') || 'Tidak ada data.';
                    }
                }
            };
            
            eventSource.onerror = function(e) {
                console.error("SSE Connection Error", e);
                // toggleLoading(true, 'Koneksi terputus. Mencoba menghubungkan kembali...');
            };
        }











function filterAnalysisLogs() {
            const query = document.getElementById('search-analysis').value.toLowerCase();
            if(query === '') {
                filteredAnalysisLogs = currentAnalysisLogs;
            } else {
                filteredAnalysisLogs = currentAnalysisLogs.filter(log => 
                    log.ip.toLowerCase().includes(query) || 
                    log.severity.toLowerCase().includes(query) || 
                    log.reason.toLowerCase().includes(query) ||
                    (log.time_window && log.time_window.toLowerCase().includes(query))
                );
            }
            currentPage = 1; // Reset ke halaman pertama saat mencari
            renderAnalysisTable();
        }
