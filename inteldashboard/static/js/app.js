document.addEventListener('DOMContentLoaded', function () {
    console.log('DOM Content Loaded. Initializing AIntelMatrix Dashboard.');

    // --- Global State ---
    let matrixData = null;
    let loadedLayers = [];
    const layerColors = ["#3498db", "#f1c40f", "#e67e22", "#1abc9c", "#34495e", "#e74c3c"];

    // --- Element Selectors ---
    const navItems = document.querySelectorAll('.nav-item');
    const contentViews = document.querySelectorAll('.content-view');

    // Matrix Elements
    const matrixContainer = document.getElementById('attack-matrix');
    const loadingIndicator = document.getElementById('loadingIndicator');
    const statsContainer = document.getElementById('stats');
    const exportMatrixBtn = document.getElementById('export-matrix-csv-btn');

    // Modal Elements
    const techniqueModal = document.getElementById('technique-details-modal');
    const techniqueModalCloseBtn = techniqueModal.querySelector('.modal-close-btn');
    const modalTechniqueName = document.getElementById('modal-technique-name');
    const modalCoverageContent = document.getElementById('modal-coverage-content');

    const osModal = document.getElementById('os-search-modal');
    const osModalTitle = document.getElementById('os-modal-title');
    const osModalContent = document.getElementById('os-modal-content');
    const osModalExportBtn = document.getElementById('os-modal-export-csv');

    const userDataModal = document.getElementById('userDataModal');
    const userDataContent = document.getElementById('userDataContent');
    const userDataStatus = document.getElementById('userDataStatus');
    const showUserDataBtn = document.getElementById('showUserDataBtn');

    const analysisResultsModal = document.getElementById('analysis-results-modal');
    const analysisModalTitle = document.getElementById('analysis-modal-title');
    const analysisModalBody = document.getElementById('analysis-modal-body');

    // Heatmap Elements
    const generateHeatmapBtn = document.getElementById('generate-heatmap-btn');
    const heatmapMatrixContainer = document.getElementById('heatmap-matrix');
    const heatmapLoading = document.getElementById('heatmapLoading');

    // Bubble Plot Elements
    const generateBubblePlotBtn = document.getElementById('generate-bubble-plot-btn');
    const bubblePlotContainer = document.getElementById('bubble-plot-svg');
    const bubblePlotLoading = document.getElementById('bubble-plot-loading');

    // Threat Layers Elements
    const navigatorFileInput = document.getElementById('navigator-file-input');
    const clearLayersBtn = document.getElementById('clear-layers-btn');
    const layerList = document.getElementById('layer-list');

    // Analysis Tools Elements
    const documentUploadInput = document.getElementById('documentUpload');
    const docAnalysisLoading = document.getElementById('doc-analysis-loading');
    const docAnalysisResults = document.getElementById('doc-analysis-results');

    const urlInput = document.getElementById('url-input');
    const analyzeUrlBtn = document.getElementById('analyze-url-btn');
    const urlAnalysisLoading = document.getElementById('url-analysis-loading');
    const urlAnalysisResults = document.getElementById('url-analysis-results');

    const githubRepoInput = document.getElementById('github-repo-input');
    const analyzeGithubRepoBtn = document.getElementById('analyze-github-repo-btn');
    const githubRepoAnalysisLoading = document.getElementById('github-repo-analysis-loading');
    const githubRepoAnalysisResults = document.getElementById('github-repo-analysis-results');

    // Management Elements
    const osDistLoading = document.getElementById('os-dist-loading');
    const osDistList = document.getElementById('os-dist-list');
    const missingTagsLoading = document.getElementById('missing-tags-loading');
    const missingTagsList = document.getElementById('missing-tags-list');
    const exportMissingBtn = document.getElementById('export-missing-csv-btn');

    // AI Agent Elements
    const aiQueryInput = document.getElementById('ai-query-input');
    const sendAiQueryBtn = document.getElementById('send-ai-query-btn');
    const aiLoading = document.getElementById('ai-loading');
    const aiResponseArea = document.getElementById('ai-response-area');
    const useUserDataCheckbox = document.getElementById('useUserDataCheckbox');

    // --- Navigation Logic ---
    function setupNavigation() {
        navItems.forEach(item => {
            item.addEventListener('click', function (e) {
                e.preventDefault();

                // 1. Update UI Active States
                navItems.forEach(nav => nav.classList.remove('active'));
                this.classList.add('active');

                // 2. Switch Views
                const targetId = this.getAttribute('data-target');
                contentViews.forEach(view => {
                    if (view.id === targetId) {
                        view.classList.add('active');
                        initializeView(targetId); // Lazy load data
                    } else {
                        view.classList.remove('active');
                    }
                });
            });
        });
    }

    function initializeView(viewId) {
        console.log('Initializing view:', viewId);

        if (viewId === 'dashboard-view' && !matrixContainer.dataset.rendered && matrixData) {
            renderMainMatrix();
            matrixContainer.dataset.rendered = 'true';
        }
        else if (viewId === 'risk-heatmap-view' && !heatmapMatrixContainer.dataset.rendered) {
            renderRiskMap();
            heatmapMatrixContainer.dataset.rendered = 'true';
        }
        else if (viewId === 'bubble-plot-view' && !bubblePlotContainer.dataset.rendered) {
            renderBubblePlot();
            bubblePlotContainer.dataset.rendered = 'true';
        }
        else if (viewId === 'threat-layers-view') {
            updateLayerList(); // Ensure list is up to date
        }
        else if (viewId === 'management-view') {
            if (!osDistList.dataset.loaded) {
                fetchOsDistributionData();
                osDistList.dataset.loaded = 'true';
            }
            if (!missingTagsList.dataset.loaded) {
                fetchMissingTagsData();
                missingTagsList.dataset.loaded = 'true';
            }
        }
    }

    setupNavigation();

    // --- Modal Handling ---
    document.querySelectorAll('.modal-close-btn').forEach(btn => {
        btn.onclick = function () {
            this.closest('.modal-overlay').classList.add('hidden'); // Use class toggle
            this.closest('.modal-overlay').style.display = ''; // Reset inline style if any (support legacy)
        };
    });

    window.onclick = (event) => {
        if (event.target.classList.contains('modal-overlay')) {
            event.target.classList.add('hidden');
        }
    };

    function showModal(modalElement) {
        modalElement.classList.remove('hidden');
        modalElement.style.display = 'flex'; // Ensure flex layout for centering
    }


    // --- Core Data Fetching ---
    // Initial load of matrix data
    fetch('/api/matrix')
        .then(response => response.json())
        .then(data => {
            if (data.error) {
                statsContainer.innerText = `Error: ${data.error}`;
                return;
            }
            matrixData = data;
            // If on dashboard view (default), render immediately
            if (document.getElementById('dashboard-view').classList.contains('active')) {
                renderMainMatrix();
                matrixContainer.dataset.rendered = 'true';
            }
        })
        .catch(error => {
            statsContainer.innerText = "Failed to load ATT&CK data. Please check the backend server.";
            console.error('Error fetching ATT&CK data:', error);
        });


    // --- Feature Implementations ---

    // 1. Matrix & Heatmap Rendering
    function renderMainMatrix() {
        if (matrixData) {
            loadingIndicator.style.display = 'none';
            renderMatrix(matrixContainer, false);
        }
    }

    function renderRiskMap() {
        if (!matrixData) {
            heatmapMatrixContainer.innerHTML = '<p style="text-align: center; padding: 20px;">Matrix data not loaded yet.</p>';
            return;
        }
        if (loadedLayers.length === 0) {
            heatmapMatrixContainer.innerHTML = '<p style="text-align: center; padding: 20px;">Load at least one Navigator layer to generate a risk map.</p>';
            return;
        }
        heatmapLoading.classList.remove('hidden');
        renderMatrix(heatmapMatrixContainer, true);
        heatmapLoading.classList.add('hidden');
    }

    function renderMatrix(containerElement, isHeatmap) {
        if (!matrixData) {
            containerElement.innerHTML = '<p style="text-align: center;">ATT&CK Matrix data not available.</p>';
            return;
        }

        containerElement.innerHTML = '';
        const matrixDiv = document.createElement('div');
        matrixDiv.classList.add('matrix');
        containerElement.appendChild(matrixDiv);

        let coveredCount = 0;
        let totalTechniques = 0;

        matrixData.forEach(tactic => {
            const tacticColumn = document.createElement('div');
            tacticColumn.classList.add('tactic-column');

            const tacticHeader = document.createElement('div');
            tacticHeader.classList.add('tactic-header');
            tacticHeader.innerText = tactic.name;
            tacticColumn.appendChild(tacticHeader);

            const allTechniquesInTactic = [...tactic.techniques];
            tactic.techniques.forEach(tech => {
                allTechniquesInTactic.push(...tech.subtechniques);
            });

            allTechniquesInTactic.forEach(technique => {
                if (!technique.is_subtechnique) {
                    const techCell = document.createElement('div');
                    techCell.classList.add('technique-cell');
                    if (technique.is_subtechnique) techCell.classList.add('subtechnique-cell');

                    techCell.innerText = technique.name;
                    techCell.dataset.id = technique.id;

                    // Layer Logic
                    let layerUsageCount = 0;
                    loadedLayers.forEach(layer => {
                        layer.techniques.forEach(layerTech => {
                            if (layerTech.techniqueID === technique.id) layerUsageCount++;
                        });
                    });

                    // Styling Logic
                    if (isHeatmap) {
                        if (layerUsageCount > 0 && technique.covered) techCell.classList.add('risk-medium');
                        else if (layerUsageCount > 0 && !technique.covered) techCell.classList.add('risk-high');
                        else if (layerUsageCount === 0 && technique.covered) techCell.classList.add('risk-low');
                    } else {
                        if (technique.covered && layerUsageCount > 0) techCell.classList.add('overlap-covered');
                        else if (technique.covered) techCell.classList.add('search-covered');
                        else if (layerUsageCount > 0) techCell.classList.add('layer-covered');
                        else techCell.classList.add('uncovered'); // Explicit uncovered state
                    }

                    totalTechniques++;
                    if (technique.covered) coveredCount++;

                    if (!isHeatmap) {
                        techCell.addEventListener('click', () => showTechniqueDetailsModal(technique));
                    }

                    tacticColumn.appendChild(techCell);

                    // Subtechniques (Simplified loop for brevity, same logic applies)
                    technique.subtechniques.forEach(subtech => {
                        const subCell = document.createElement('div');
                        subCell.classList.add('technique-cell', 'subtechnique-cell');
                        subCell.innerText = subtech.name;

                        let subLayerCount = 0;
                        loadedLayers.forEach(l => l.techniques.forEach(t => { if (t.techniqueID === subtech.id) subLayerCount++; }));

                        if (isHeatmap) {
                            if (subLayerCount > 0 && subtech.covered) subCell.classList.add('risk-medium');
                            else if (subLayerCount > 0 && !subtech.covered) subCell.classList.add('risk-high');
                            else if (subLayerCount === 0 && subtech.covered) subCell.classList.add('risk-low');
                        } else {
                            if (subtech.covered && subLayerCount > 0) subCell.classList.add('overlap-covered');
                            else if (subtech.covered) subCell.classList.add('search-covered');
                            else if (subLayerCount > 0) subCell.classList.add('layer-covered');
                        }

                        totalTechniques++;
                        if (subtech.covered) coveredCount++;

                        if (!isHeatmap) subCell.addEventListener('click', () => showTechniqueDetailsModal(subtech));
                        tacticColumn.appendChild(subCell);
                    });
                }
            });
            matrixDiv.appendChild(tacticColumn);
        });

        if (!isHeatmap) {
            statsContainer.innerText = `Technique Coverage: ${coveredCount} of ${totalTechniques} (${((coveredCount / totalTechniques) * 100).toFixed(1)}%)`;
        }
    }

    // 2. Technique Modal
    async function showTechniqueDetailsModal(technique) {
        modalTechniqueName.innerHTML = `${technique.name} (${technique.id}) <a href="${technique.url}" target="_blank" style="font-size: 0.6em; vertical-align: super;">&#x2197;</a>`;
        modalCoverageContent.innerHTML = '<p class="text-center">Loading details...</p>';
        showModal(techniqueModal);

        let contentHtml = '';

        // Internal Coverage
        if (technique.searches && technique.searches.length > 0) {
            contentHtml += `<div class="coverage-source">
                                <div class="source-title">Internal Detections (${technique.searches.length}):</div>
                                <div>`;
            technique.searches.forEach(search => {
                contentHtml += `<div class="search-item">
                                    <div class="search-name">${search.name}</div>
                                    <div class="search-query">${search.query}</div>
                                    <div class="search-os">OS: ${search.os}</div>
                                </div>`;
            });
            contentHtml += `</div></div>`;
        } else {
            contentHtml += `<div class="coverage-source"><div class="source-title">No internal searches cover this technique.</div></div>`;
        }

        // Threat Groups (AI Augmented)
        try {
            const response = await fetch('/api/techniques/' + technique.id + '/groups');
            const data = await response.json();

            if (data.groups && data.groups.length > 0) {
                contentHtml += `<div class="coverage-source">
                                    <div class="source-title mt-4">Threat Access (${data.groups.length} Groups):</div>
                                    <div style="font-size:0.9em; margin-bottom: 10px;">Checking AI for procedural examples...</div>
                                    <div id="all-groups-usage-container"></div>
                                </div>`;

                modalCoverageContent.innerHTML = contentHtml;
                const container = document.getElementById('all-groups-usage-container');

                // Lazy load AI responses for groups
                data.groups.forEach(group => {
                    const groupDiv = document.createElement('div');
                    groupDiv.classList.add('group-usage-item');

                    const containerId = `usage-${group.id}-${technique.id}`;
                    groupDiv.innerHTML = `
                        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
                            <h4 style="margin:0;">${group.name}</h4>
                            <button class="btn btn-secondary btn-sm analyze-btn" style="font-size:12px; padding:4px 8px; height:auto;">Analyze Usage</button>
                        </div>
                        <div id="${containerId}" class="usage-details"></div>
                    `;
                    container.appendChild(groupDiv);

                    // Attach click listener to the specific button
                    const btn = groupDiv.querySelector('.analyze-btn');
                    btn.addEventListener('click', () => {
                        const outputDiv = document.getElementById(containerId);
                        outputDiv.innerHTML = '<span class="loader" style="width:16px; height:16px; border-width:2px;"></span> Analyzing...';
                        btn.disabled = true;

                        fetch('/api/ai_query', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ query: `How does ${group.name} use ${technique.name} (${technique.id})?`, use_user_data: false })
                        })
                            .then(res => res.json())
                            .then(aiData => {
                                outputDiv.innerHTML = aiData.response || 'No specific data found.';
                                btn.remove(); // Remove button after successful load
                            })
                            .catch(err => {
                                outputDiv.innerHTML = '<span style="color:var(--danger-red)">Analysis failed.</span>';
                                btn.disabled = false;
                            });
                    });
                });

            } else {
                contentHtml += `<div class="mt-4"><p>No known threat groups match this technique in default dataset.</p></div>`;
                modalCoverageContent.innerHTML = contentHtml;
            }
        } catch (e) {
            modalCoverageContent.innerHTML = contentHtml + `<p style="color:red">Error fetching threat data.</p>`;
        }
    }

    // 3. Threat Layers
    navigatorFileInput.addEventListener('change', (event) => {
        const files = event.target.files;
        if (!files.length) return;

        Array.from(files).forEach(file => {
            const reader = new FileReader();
            reader.onload = (e) => {
                try {
                    const layer = JSON.parse(e.target.result);
                    layer.color = layerColors[loadedLayers.length % layerColors.length];
                    loadedLayers.push(layer);
                    updateLayerList();
                    // Invalidate rendered states to force refresh
                    heatmapMatrixContainer.dataset.rendered = '';
                    bubblePlotContainer.dataset.rendered = '';
                    matrixContainer.dataset.rendered = '';

                    // Re-render current view if necessary
                    if (document.getElementById('dashboard-view').classList.contains('active')) renderMainMatrix();
                } catch (error) {
                    alert('Failed to parse JSON: ' + error.message);
                }
            };
            reader.readAsText(file);
        });
    });

    clearLayersBtn.addEventListener('click', () => {
        loadedLayers = [];
        updateLayerList();
        heatmapMatrixContainer.dataset.rendered = '';
        bubblePlotContainer.dataset.rendered = '';
        matrixContainer.dataset.rendered = '';
        renderMainMatrix();
    });

    function updateLayerList() {
        layerList.innerHTML = '';
        if (loadedLayers.length === 0) {
            layerList.innerHTML = '<li style="border:none; color: #888;">No layers loaded. Upload a Navigator JSON file to begin.</li>';
            return;
        }
        loadedLayers.forEach((layer, index) => {
            const li = document.createElement('li');
            li.innerHTML = `
                <div style="display:flex; align-items:center; gap:10px;">
                    <span class="layer-color-swatch" style="background-color: ${layer.color}; width:12px; height:12px; border-radius:2px;"></span>
                    <strong>${layer.name}</strong> 
                    <span style="font-size:0.8em; color:#666;">(${layer.domain})</span>
                </div>
                <button class="remove-layer-btn" data-index="${index}" style="background:none; border:none; cursor:pointer; color:red;">&times;</button>
            `;
            li.querySelector('.remove-layer-btn').addEventListener('click', (e) => {
                loadedLayers.splice(index, 1);
                updateLayerList();
                // Invalidate states
                heatmapMatrixContainer.dataset.rendered = '';
                bubblePlotContainer.dataset.rendered = '';
                matrixContainer.dataset.rendered = '';
                renderMainMatrix();
            });
            layerList.appendChild(li);
        });
    }

    // 4. Bubble Plot
    generateBubblePlotBtn.addEventListener('click', renderBubblePlot);

    function renderBubblePlot() {
        if (loadedLayers.length === 0) {
            bubblePlotContainer.innerHTML = '<p class="text-center p-4">No layers loaded. Cannot generate plot.</p>';
            return;
        }

        bubblePlotLoading.classList.remove('hidden');
        const svg = d3.select("#bubble-plot-svg");
        svg.selectAll("*").remove(); // Clear previous

        // Simulating delay for effect/processing
        setTimeout(() => {
            const width = bubblePlotContainer.getBoundingClientRect().width || 800;
            const height = 600;
            bubblePlotContainer.querySelector('svg').setAttribute('width', width);
            bubblePlotContainer.querySelector('svg').setAttribute('height', height);

            const techniqueCounts = {};
            loadedLayers.forEach(layer => {
                layer.techniques.forEach(tech => {
                    if (tech.enabled) techniqueCounts[tech.techniqueID] = (techniqueCounts[tech.techniqueID] || 0) + 1;
                });
            });

            const data = Object.entries(techniqueCounts).map(([id, count]) => ({ id, value: count }));
            const pack = d3.pack().size([width, height]).padding(5);
            const root = d3.hierarchy({ children: data }).sum(d => d.value);
            const nodes = pack(root).leaves();
            const color = d3.scaleOrdinal(d3.schemeCategory10);

            const node = svg.selectAll(".node")
                .data(nodes).enter().append("g")
                .attr("transform", d => `translate(${d.x},${d.y})`);

            node.append("circle")
                .attr("r", d => d.r)
                .attr("fill", d => color(d.data.id));

            node.append("text")
                .attr("dy", ".3em")
                .style("text-anchor", "middle")
                .text(d => d.data.id.substring(0, d.r / 3))
                .style("font-size", d => Math.min(d.r, 12) + "px")
                .style("fill", "white");

            bubblePlotLoading.classList.add('hidden');
        }, 100);
    }

    // 5. Heatmap Button
    generateHeatmapBtn.addEventListener('click', renderRiskMap);

    // 6. AI Agent
    sendAiQueryBtn.addEventListener('click', async () => {
        const query = aiQueryInput.value.trim();
        if (!query) return;

        aiLoading.classList.remove('hidden');
        aiResponseArea.innerHTML = '';

        try {
            const res = await fetch('/api/ai_query', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ query: query, use_user_data: useUserDataCheckbox.checked })
            });
            const data = await res.json();
            aiResponseArea.innerText = data.response || data.error || 'No response';
        } catch (e) {
            aiResponseArea.innerText = 'Error communicating with AI agent.';
        } finally {
            aiLoading.classList.add('hidden');
        }
    });

    // 7. Analysis Tools (Simplified for brevity, following same pattern)
    // Document Analysis
    documentUploadInput.addEventListener('change', async (e) => {
        const files = e.target.files;
        if (!files.length) return;

        docAnalysisLoading.classList.remove('hidden');
        docAnalysisResults.innerHTML = '';
        const formData = new FormData();
        Array.from(files).forEach(f => formData.append('files', f));

        try {
            const res = await fetch('/api/analyze_document', { method: 'POST', body: formData });
            const data = await res.json();
            showAnalysisResultsModal(data.results || [{ error: data.error || 'Unknown error' }]);
        } catch (e) { console.error(e); }
        finally { docAnalysisLoading.classList.add('hidden'); }
    });

    // URL Analysis
    analyzeUrlBtn.addEventListener('click', async () => {
        const urls = urlInput.value.trim().split('\n').filter(u => u);
        if (!urls.length) return;

        urlAnalysisLoading.classList.remove('hidden');
        urlAnalysisResults.innerHTML = '';

        // Sequential fetch for demo purposes
        for (let u of urls) {
            try {
                const res = await fetch('/api/analyze_url', {
                    method: 'POST', headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ url: u })
                });
                const data = await res.json();
                const div = document.createElement('div');
                div.className = 'list-item';
                div.innerHTML = `<strong>${u}</strong>: ${data.status || 'Failed'}`;
                urlAnalysisResults.appendChild(div);
            } catch (e) { }
        }
        urlAnalysisLoading.classList.add('hidden');
    });

    // Github Analysis
    analyzeGithubRepoBtn.addEventListener('click', async () => {
        const repos = githubRepoInput.value.trim().split('\n').filter(r => r);
        if (!repos.length) return;

        githubRepoAnalysisLoading.classList.remove('hidden');
        githubRepoAnalysisResults.innerHTML = '';

        for (let r of repos) {
            try {
                const res = await fetch('/api/analyze_github_repo', {
                    method: 'POST', headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ repo_url: r })
                });
                const data = await res.json();
                showAnalysisResultsModal(data.results || []);
            } catch (e) { }
        }
        githubRepoAnalysisLoading.classList.add('hidden');
    });

    // Management Data Fetchers
    async function fetchOsDistributionData() {
        osDistLoading.classList.remove('hidden');
        try {
            const res = await fetch('/api/os_distribution');
            const data = await res.json();
            osDistList.innerHTML = '';
            for (let os in data) {
                const li = document.createElement('li');
                li.className = 'list-item';
                li.innerText = `${os}: ${data[os]} searches`;
                osDistList.appendChild(li);
            }
        } catch (e) { }
        osDistLoading.classList.add('hidden');
    }

    async function fetchMissingTagsData() {
        missingTagsLoading.classList.remove('hidden');
        try {
            const res = await fetch('/api/missing_tags');
            const data = await res.json();
            missingTagsList.innerHTML = '';
            data.forEach(item => {
                const li = document.createElement('li');
                li.className = 'list-item';
                li.innerHTML = `<strong>${item.name}</strong><br><small>${item.query}</small>`;
                missingTagsList.appendChild(li);
            });
        } catch (e) { }
        missingTagsLoading.classList.add('hidden');
    }

    // Modal Helper
    function showAnalysisResultsModal(results) {
        analysisModalBody.innerHTML = '';
        results.forEach(r => {
            const div = document.createElement('div');
            div.className = 'list-item';
            div.innerHTML = `<h4>${r.filename || r.source_url || 'Result'}</h4>
                              <p>Status: ${r.status}</p>
                              <pre style="background:#eee; padding:5px;">Techniques: ${(r.techniques || []).map(t => t.id).join(', ')}</pre>`;
            analysisModalBody.appendChild(div);
        });
        showModal(analysisResultsModal);
    }

    // User Data Modal
    if (showUserDataBtn) {
        showUserDataBtn.addEventListener('click', async () => {
            showModal(userDataModal);
            userDataContent.innerText = 'Loading...';
            const res = await fetch('/api/user_data');
            const data = await res.json();
            userDataContent.innerText = JSON.stringify(data, null, 2);
        });
    }

    exportMatrixBtn.addEventListener('click', () => { window.location.href = '/api/matrix/csv'; });
    exportMissingBtn.addEventListener('click', () => { window.location.href = '/api/missing_tags/csv'; });

});
