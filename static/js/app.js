// 全局变量
let scanStartTime = null;
let scanTimer = null;

// 设置活动导航项
function setActiveNav(activeItem) {
    document.querySelectorAll('.nav-link').forEach(item => {
        item.classList.remove('active');
    });
    activeItem.classList.add('active');
}

// 更新扫描时间显示
function updateScanTime() {
    if (scanStartTime) {
        const elapsed = Math.floor((Date.now() - scanStartTime) / 1000);
        const minutes = Math.floor(elapsed / 60);
        const seconds = elapsed % 60;
        document.getElementById('scan-time').textContent =
            `${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
    }
}

// 显示通知
function showNotification(message, type = 'info') {
    // 创建通知元素
    const notification = document.createElement('div');
    notification.className = `alert alert-${type} alert-dismissible fade show position-fixed`;
    notification.style.cssText = 'top: 20px; right: 20px; z-index: 9999; min-width: 300px;';
    notification.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;

    document.body.appendChild(notification);

    // 自动移除
    setTimeout(() => {
        if (notification.parentNode) {
            notification.remove();
        }
    }, 5000);
}

document.addEventListener('DOMContentLoaded', function () {
    // 初始化目标列表
    loadTargets();

    // 添加目标按钮事件 - 显示模态框
    document.getElementById('add-target-btn').addEventListener('click', function () {
        const modal = new bootstrap.Modal(document.getElementById('addTargetModal'));
        modal.show();
    });

    // 保存目标按钮事件
    document.getElementById('saveTargetBtn').addEventListener('click', function () {
        saveNewTarget();
    });

    // 导航栏点击事件
    document.getElementById('nav-targets').addEventListener('click', function (e) {
        e.preventDefault();
        setActiveNav(this);
        document.querySelector('.page-title').textContent = '目标管理';
        document.querySelector('.page-subtitle').textContent = '管理和配置扫描目标';
        showEmptyState();
    });

    document.getElementById('nav-info-gathering').addEventListener('click', function (e) {
        e.preventDefault();
        setActiveNav(this);
        document.querySelector('.page-title').textContent = '信息收集';
        document.querySelector('.page-subtitle').textContent = '子域名枚举和服务发现';
        showInfoGatheringInterface();
    });

    document.getElementById('nav-vuln-scan').addEventListener('click', function (e) {
        e.preventDefault();
        setActiveNav(this);
        document.querySelector('.page-title').textContent = '漏洞扫描';
        document.querySelector('.page-subtitle').textContent = '自动化漏洞检测和分析';
        showVulnScanInterface();
    });

    document.getElementById('nav-report').addEventListener('click', function (e) {
        e.preventDefault();
        setActiveNav(this);
        document.querySelector('.page-title').textContent = '扫描历史';
        document.querySelector('.page-subtitle').textContent = '查看和分析历史扫描记录';
        loadScanHistory();
    });

    // 加载扫描历史
    function loadScanHistory() {
        fetch('/api/history')
            .then(response => response.json())
            .then(data => {
                const resultsContainer = document.getElementById('scan-results');
                resultsContainer.innerHTML = '';

                if (data.length === 0) {
                    resultsContainer.innerHTML = '<p>暂无历史记录</p>';
                    return;
                }

                const historyList = document.createElement('div');
                historyList.className = 'history-list';

                data.forEach(item => {
                    const historyItem = document.createElement('div');
                    historyItem.className = 'history-item p-3 mb-2 border rounded';
                    historyItem.innerHTML = `
                        <h5>${item.target}</h5>
                        <p><strong>扫描类型:</strong> ${item.scan_type}</p>
                        <p><strong>扫描时间:</strong> ${item.created_at}</p>
                        <button class="btn btn-sm btn-primary view-details" data-id="${item.id}">查看详情</button>
                    `;
                    historyList.appendChild(historyItem);
                });

                resultsContainer.appendChild(historyList);

                // 添加查看详情事件
                document.querySelectorAll('.view-details').forEach(btn => {
                    btn.addEventListener('click', function () {
                        const scanId = this.getAttribute('data-id');
                        viewScanDetails(scanId);
                    });
                });
            });
    }

    // 查看扫描详情
    function viewScanDetails(scanId) {
        const resultsContainer = document.getElementById('scan-results');
        resultsContainer.innerHTML = '<p>加载中...</p>';

        fetch(`/api/history/${scanId}`)
            .then(response => response.json())
            .then(data => {
                resultsContainer.innerHTML = `
                    <button class="btn btn-secondary mb-3" onclick="loadScanHistory()">
                        <i class="bi bi-arrow-left"></i> 返回列表
                    </button>
                    <div class="card">
                        <div class="card-header">
                            <h5>扫描详情 - ${data.target}</h5>
                        </div>
                        <div class="card-body">
                            <p><strong>扫描类型:</strong> ${data.scan_type}</p>
                            <p><strong>扫描时间:</strong> ${data.created_at}</p>
                            <hr>
                            <div id="scan-details"></div>
                        </div>
                    </div>
                `;

                if (data.scan_type === 'port_scan') {
                    displayPortScanResults(data.result);
                } else {
                    document.getElementById('scan-details').innerHTML =
                        '<pre class="p-3 bg-light rounded">' +
                        JSON.stringify(data.result, null, 2) +
                        '</pre>';
                }
            })
            .catch(error => {
                resultsContainer.innerHTML = `
                    <div class="alert alert-danger">
                        加载失败: ${error.message}
                        <button class="btn btn-sm btn-secondary mt-2" onclick="loadScanHistory()">
                            返回列表
                        </button>
                    </div>
                `;
            });
    }

    // 全局暴露函数
    window.loadScanHistory = loadScanHistory;
    window.viewScanDetails = viewScanDetails;
});

// 显示空状态
function showEmptyState() {
    const resultsContainer = document.getElementById('scan-results');
    resultsContainer.innerHTML = `
        <div class="empty-state">
            <div class="empty-icon">
                <i class="fas fa-search"></i>
            </div>
            <h5>等待扫描结果</h5>
            <p class="text-muted">选择目标并启动扫描以查看详细结果</p>
        </div>
    `;
}

// 显示即将推出功能
function showComingSoon(message) {
    const resultsContainer = document.getElementById('scan-results');
    resultsContainer.innerHTML = `
        <div class="empty-state">
            <div class="empty-icon">
                <i class="fas fa-rocket"></i>
            </div>
            <h5>功能开发中</h5>
            <p class="text-muted">${message}</p>
            <button class="btn btn-outline-light mt-3">
                <i class="fas fa-bell me-2"></i>通知我更新
            </button>
        </div>
    `;
}

// 加载目标列表
function loadTargets() {
    const targetList = document.getElementById('target-list');

    fetch('/api/targets')
        .then(response => response.json())
        .then(data => {
            targetList.innerHTML = '';

            if (data.length === 0) {
                targetList.innerHTML = `
                    <div class="empty-state text-center py-4">
                        <div class="empty-icon">
                            <i class="fas fa-crosshairs"></i>
                        </div>
                        <p class="text-muted mb-0">暂无扫描目标</p>
                        <small class="text-muted">点击下方按钮添加第一个目标</small>
                    </div>
                `;
                return;
            }

            data.forEach((target, index) => {
                const targetItem = document.createElement('div');
                targetItem.className = 'target-item fade-in-up';
                targetItem.style.animationDelay = `${index * 0.1}s`;
                const targetUrl = target.url || target.ip || target.name;
                targetItem.innerHTML = `
                    <div class="d-flex justify-content-between align-items-start">
                        <div class="flex-grow-1">
                            <h6 class="mb-1">${target.name || target.url}</h6>
                            <small class="text-muted d-block">${target.url || target.ip}</small>
                            <span class="badge bg-primary mt-1">${getTypeLabel(target.type)}</span>
                        </div>
                        <div class="target-actions">
                            <div class="btn-group">
                                <button class="btn btn-sm btn-outline-light dropdown-toggle" data-bs-toggle="dropdown" title="选择扫描类型">
                                    <i class="fas fa-play"></i>
                                </button>
                                <ul class="dropdown-menu dropdown-menu-dark dropdown-menu-end">
                                    <li><a class="dropdown-item" href="#" onclick="scanTarget('${targetUrl}', 'port_scan'); return false;">
                                        <i class="fas fa-network-wired me-2"></i>端口扫描
                                    </a></li>
                                    <li><a class="dropdown-item" href="#" onclick="startQuickWebScan('${targetUrl}'); return false;">
                                        <i class="fas fa-bug me-2"></i>Web 漏洞扫描
                                    </a></li>
                                    <li><a class="dropdown-item" href="#" onclick="startQuickServiceScan('${targetUrl}'); return false;">
                                        <i class="fas fa-server me-2"></i>服务漏洞扫描
                                    </a></li>
                                    <li><a class="dropdown-item" href="#" onclick="startQuickDirScan('${targetUrl}'); return false;">
                                        <i class="fas fa-folder-open me-2"></i>目录扫描
                                    </a></li>
                                    <li><hr class="dropdown-divider"></li>
                                    <li><a class="dropdown-item" href="#" onclick="startQuickRecon('${targetUrl}', ${target.id}); return false;">
                                        <i class="fas fa-rocket me-2"></i>综合侦察
                                    </a></li>
                                </ul>
                            </div>
                            <button class="btn btn-sm btn-outline-light ms-1" onclick="editTarget(${target.id})" title="编辑">
                                <i class="fas fa-edit"></i>
                            </button>
                        </div>
                    </div>
                `;
                targetList.appendChild(targetItem);
            });
        })
        .catch(error => {
            targetList.innerHTML = `
                <div class="alert alert-danger">
                    <i class="fas fa-exclamation-triangle me-2"></i>
                    加载目标失败: ${error.message}
                </div>
            `;
        });
}

// 获取类型标签
function getTypeLabel(type) {
    const labels = {
        'website': '网站',
        'api': 'API',
        'network': '网络',
        'service': '服务'
    };
    return labels[type] || type;
}

// 保存新目标
function saveNewTarget() {
    const form = document.getElementById('addTargetForm');
    const formData = new FormData(form);

    const targetData = {
        name: document.getElementById('targetName').value || `目标-${new Date().toLocaleString()}`,
        url: document.getElementById('targetUrl').value,
        type: document.getElementById('targetType').value,
        tags: document.getElementById('targetTags').value.split(',').map(tag => tag.trim()).filter(tag => tag)
    };

    // 验证必填字段
    if (!targetData.url) {
        showNotification('请输入目标地址', 'warning');
        return;
    }

    // 显示加载状态
    const saveBtn = document.getElementById('saveTargetBtn');
    const originalText = saveBtn.innerHTML;
    saveBtn.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>保存中...';
    saveBtn.disabled = true;

    fetch('/api/targets', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(targetData)
    })
        .then(response => {
            if (!response.ok) {
                throw new Error('网络响应不正常');
            }
            return response.json();
        })
        .then(data => {
            if (data.status === 'success') {
                // 关闭模态框
                const modal = bootstrap.Modal.getInstance(document.getElementById('addTargetModal'));
                modal.hide();

                // 清空表单
                form.reset();

                // 刷新目标列表
                loadTargets();

                // 显示成功通知
                showNotification('目标添加成功！正在启动扫描...', 'success');

                // 自动启动扫描
                setTimeout(() => {
                    startScan(targetData.url, 'port_scan');
                }, 1000);
            } else {
                throw new Error(data.message || '未知错误');
            }
        })
        .catch(error => {
            showNotification(`添加目标失败: ${error.message}`, 'danger');
        })
        .finally(() => {
            // 恢复按钮状态
            saveBtn.innerHTML = originalText;
            saveBtn.disabled = false;
        });
}

// 扫描指定目标 - 根据当前活动页面决定扫描类型
function scanTarget(target, scanType) {
    // 检查当前活动的导航项
    const activeNav = document.querySelector('.nav-link.active');
    const activeId = activeNav ? activeNav.id : '';

    // 如果没有指定扫描类型，根据当前页面决定
    if (scanType === 'port_scan') {
        if (activeId === 'nav-info-gathering') {
            // 在信息收集页面，执行综合侦察
            showNotification(`正在启动综合侦察: ${target}`, 'info');
            // 需要先获取目标 ID
            getOrCreateTarget(target).then(targetId => {
                if (targetId) {
                    startQuickRecon(target, targetId);
                } else {
                    showNotification('无法获取目标信息', 'danger');
                }
            });
            return;
        } else if (activeId === 'nav-vuln-scan') {
            // 在漏洞扫描页面，执行 Web 漏洞扫描
            startQuickWebScan(target);
            return;
        }
    }

    // 默认行为：端口扫描
    showNotification(`正在启动对 ${target} 的端口扫描...`, 'info');
    startScan(target, scanType);
}

// 编辑目标（占位符功能）
function editTarget(targetId) {
    showNotification('编辑功能即将推出', 'info');
}

// 快速 Web 漏洞扫描
function startQuickWebScan(target) {
    showNotification(`正在启动 Web 漏洞扫描: ${target}`, 'info');
    const url = target.includes('://') ? target : `https://${target}`;

    fetch('/api/vuln-scan/web', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target_url: url })
    })
        .then(response => response.json())
        .then(data => {
            if (data.status === 'started') {
                showNotification(`Web 漏洞扫描已启动，扫描 ID: ${data.scan_id}`, 'success');
                // 切换到漏洞扫描界面
                document.getElementById('nav-vuln-scan').click();
                setTimeout(() => {
                    const resultsDiv = document.getElementById('vuln-scan-results');
                    if (resultsDiv) {
                        resultsDiv.innerHTML = `
                        <div class="text-center py-4">
                            <div class="spinner-border text-warning" role="status">
                                <span class="visually-hidden">扫描中...</span>
                            </div>
                            <p class="mt-3">正在扫描 ${target} 的 Web 漏洞...</p>
                            <small class="text-muted" id="vuln-scan-status">初始化中...</small>
                        </div>
                    `;
                        monitorVulnScan(data.scan_id, resultsDiv, 'web');
                    }
                }, 500);
            } else {
                showNotification(`扫描启动失败: ${data.message}`, 'danger');
            }
        })
        .catch(error => {
            showNotification(`请求失败: ${error.message}`, 'danger');
        });
}

// 快速服务漏洞扫描
function startQuickServiceScan(target) {
    showNotification(`正在启动服务漏洞扫描: ${target}`, 'info');
    // 提取主机名/IP
    let host = target.replace(/^https?:\/\//, '').split('/')[0].split(':')[0];

    fetch('/api/vuln-scan/service', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: host })
    })
        .then(response => response.json())
        .then(data => {
            if (data.status === 'started') {
                showNotification(`服务漏洞扫描已启动`, 'success');
                document.getElementById('nav-vuln-scan').click();
                setTimeout(() => {
                    const resultsDiv = document.getElementById('vuln-scan-results');
                    if (resultsDiv) {
                        resultsDiv.innerHTML = `
                        <div class="text-center py-4">
                            <div class="spinner-border text-warning" role="status"></div>
                            <p class="mt-3">正在扫描 ${host} 的服务漏洞...</p>
                            <small class="text-muted" id="vuln-scan-status">初始化中...</small>
                        </div>
                    `;
                        monitorVulnScan(data.scan_id, resultsDiv, 'service');
                    }
                }, 500);
            } else {
                showNotification(`扫描启动失败: ${data.message}`, 'danger');
            }
        })
        .catch(error => {
            showNotification(`请求失败: ${error.message}`, 'danger');
        });
}

// 快速目录扫描
function startQuickDirScan(target) {
    showNotification(`正在启动目录扫描: ${target}`, 'info');
    const url = target.includes('://') ? target : `https://${target}`;

    fetch('/api/vuln-scan/directory', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target_url: url })
    })
        .then(response => response.json())
        .then(data => {
            if (data.status === 'started') {
                showNotification(`目录扫描已启动`, 'success');
                document.getElementById('nav-vuln-scan').click();
                setTimeout(() => {
                    const resultsDiv = document.getElementById('vuln-scan-results');
                    if (resultsDiv) {
                        resultsDiv.innerHTML = `
                        <div class="text-center py-4">
                            <div class="spinner-border text-warning" role="status"></div>
                            <p class="mt-3">正在扫描 ${target} 的目录结构...</p>
                            <small class="text-muted" id="vuln-scan-status">初始化中...</small>
                        </div>
                    `;
                        monitorDirScan(data.scan_id, resultsDiv);
                    }
                }, 500);
            } else {
                showNotification(`扫描启动失败: ${data.message}`, 'danger');
            }
        })
        .catch(error => {
            showNotification(`请求失败: ${error.message}`, 'danger');
        });
}

// 快速综合侦察
function startQuickRecon(target, targetId) {
    showNotification(`正在启动综合侦察: ${target}`, 'info');
    document.getElementById('nav-info-gathering').click();

    setTimeout(() => {
        const resultsDiv = document.getElementById('info-gathering-results');
        if (resultsDiv) {
            resultsDiv.innerHTML = `
                <div class="text-center py-4">
                    <div class="spinner-border text-primary" role="status"></div>
                    <p class="mt-3">正在对 ${target} 进行综合侦察...</p>
                    <small class="text-muted">包括子域名、DNS、服务指纹和技术栈识别</small>
                    <div class="progress mt-3" style="height: 20px;">
                        <div class="progress-bar progress-bar-striped progress-bar-animated" id="recon-progress" style="width: 0%">0%</div>
                    </div>
                </div>
            `;

            fetch('/api/recon/comprehensive', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ target_id: targetId })
            })
                .then(response => response.json())
                .then(data => {
                    if (data.scan_id) {
                        monitorReconProgress(data.scan_id, resultsDiv, target);
                    } else if (data.status === 'completed') {
                        displayComprehensiveResults(data, resultsDiv);
                    } else {
                        resultsDiv.innerHTML = `<div class="alert alert-danger">启动侦察失败: ${data.message || '未知错误'}</div>`;
                    }
                })
                .catch(error => {
                    resultsDiv.innerHTML = `<div class="alert alert-danger">请求失败: ${error.message}</div>`;
                });
        }
    }, 500);
}

// 启动扫描任务
function startScan(target, scanType) {
    fetch('/api/scan', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            target: target,
            scan_type: scanType
        })
    })
        .then(response => response.json())
        .then(data => {
            if (data.status === 'started') {
                monitorScanProgress(data.scan_id);
            }
        });
}

// 监控扫描进度
function monitorScanProgress(scanId) {
    const progressBar = document.getElementById('scan-progress');
    const statusText = document.getElementById('scan-status');
    const statusBadge = document.getElementById('scan-status-badge');
    const scanTimeElement = document.getElementById('scan-time');

    let estimatedProgress = 0;
    const maxProgress = 90; // 最大预估进度

    // 设置扫描开始时间
    scanStartTime = Date.now();

    // 启动计时器
    scanTimer = setInterval(updateScanTime, 1000);

    // 更新进度条
    const updateProgress = (progress, status, badgeText = '扫描中') => {
        progressBar.style.width = `${progress}%`;
        progressBar.querySelector('.progress-text').textContent = `${progress}%`;
        statusText.textContent = status;
        statusBadge.textContent = badgeText;
        statusBadge.className = `scan-status-badge ${progress === 100 ? 'bg-success' : 'bg-primary'}`;
    };

    // 初始状态
    updateProgress(5, '正在启动扫描...', '启动中');

    // 模拟进度增长
    const progressInterval = setInterval(() => {
        estimatedProgress = Math.min(estimatedProgress + Math.random() * 10, maxProgress);
        updateProgress(Math.floor(estimatedProgress), '扫描进行中...', '扫描中');
    }, 1500);

    const checkProgress = () => {
        fetch(`/api/scan/${scanId}`)
            .then(response => response.json())
            .then(data => {
                if (data.status === 'completed') {
                    clearInterval(progressInterval);
                    clearInterval(scanTimer);
                    updateProgress(100, '扫描完成！', '已完成');

                    showNotification('扫描完成！正在加载结果...', 'success');

                    setTimeout(() => {
                        displayScanResults(data.result);
                        // 重置进度条
                        setTimeout(() => {
                            updateProgress(0, '准备扫描...', '待机中');
                            scanTimeElement.textContent = '';
                            scanStartTime = null;
                        }, 3000);
                    }, 1000);
                } else if (data.status === 'running') {
                    setTimeout(checkProgress, 2000);
                } else if (data.status === 'error') {
                    clearInterval(progressInterval);
                    clearInterval(scanTimer);
                    updateProgress(0, `扫描错误: ${data.message || '未知错误'}`, '错误');
                    statusBadge.className = 'scan-status-badge bg-danger';
                    showNotification(`扫描失败: ${data.message || '未知错误'}`, 'danger');
                    scanStartTime = null;
                    scanTimeElement.textContent = '';
                } else if (data.status === 'not_found') {
                    clearInterval(progressInterval);
                    clearInterval(scanTimer);
                    updateProgress(0, '扫描任务未找到', '错误');
                    statusBadge.className = 'scan-status-badge bg-warning';
                    showNotification('扫描任务未找到，请重新启动扫描', 'warning');
                    scanStartTime = null;
                    scanTimeElement.textContent = '';
                }
            })
            .catch(error => {
                clearInterval(progressInterval);
                clearInterval(scanTimer);
                updateProgress(0, '网络错误', '错误');
                statusBadge.className = 'scan-status-badge bg-danger';
                showNotification(`网络错误: ${error.message}`, 'danger');
                scanStartTime = null;
                scanTimeElement.textContent = '';
            });
    };

    // 开始检查进度
    setTimeout(checkProgress, 2000);
}

// 显示扫描结果
function displayScanResults(results) {
    const resultsContainer = document.getElementById('scan-results');
    resultsContainer.innerHTML = '';

    const message = typeof results.message === 'string' ? results.message : '';
    const ports = Array.isArray(results.ports) ? results.ports : [];

    renderPortResults(resultsContainer, ports, message);
}

function displayPortScanResults(resultData) {
    const detailsContainer = document.getElementById('scan-details');
    detailsContainer.innerHTML = '';

    const { ports, message, raw } = normalisePortScanResult(resultData);

    if (raw) {
        detailsContainer.innerHTML = `
            <div class="alert alert-secondary">
                当前扫描结果格式不受支持，显示原始数据。
            </div>
            <pre class="p-3 bg-light rounded border">${JSON.stringify(raw, null, 2)}</pre>
        `;
        return;
    }

    renderPortResults(detailsContainer, ports, message);
}

function normalisePortScanResult(resultData) {
    if (Array.isArray(resultData)) {
        return { ports: resultData, message: '', raw: null };
    }

    if (resultData && typeof resultData === 'object') {
        if (Array.isArray(resultData.ports)) {
            return {
                ports: resultData.ports,
                message: typeof resultData.message === 'string' ? resultData.message : '',
                raw: null
            };
        }

        if (Array.isArray(resultData.raw)) {
            return { ports: resultData.raw, message: '', raw: null };
        }

        const rawValue = Object.prototype.hasOwnProperty.call(resultData, 'raw')
            ? resultData.raw
            : resultData;

        return { ports: [], message: '', raw: rawValue };
    }

    return { ports: [], message: '', raw: resultData };
}

function renderPortResults(container, ports, emptyMessage) {
    const portList = Array.isArray(ports) ? ports : [];

    if (portList.length === 0) {
        const info = document.createElement('div');
        info.className = 'alert alert-info';
        info.textContent = emptyMessage || '扫描完成，未发现开放端口。';
        container.appendChild(info);
        return;
    }

    portList.forEach(port => {
        container.appendChild(createPortItem(port));
    });
}

function createPortItem(port) {
    const portItem = document.createElement('div');
    portItem.className = 'port-item fade-in-up';

    const protocol = port.protocol ? String(port.protocol).toUpperCase() : '未知协议';
    const service = port.service || '未知服务';
    const state = port.state || '未知状态';

    // 根据端口号确定图标和颜色
    const portInfo = getPortInfo(port.port);

    portItem.innerHTML = `
        <div class="d-flex justify-content-between align-items-start">
            <div class="flex-grow-1">
                <div class="d-flex align-items-center mb-2">
                    <div class="port-icon me-3">
                        <i class="${portInfo.icon}"></i>
                    </div>
                    <div>
                        <h6 class="mb-0">端口 ${port.port}</h6>
                        <small class="text-muted">${protocol} 协议</small>
                    </div>
                </div>
                <div class="port-details">
                    <div class="row">
                        <div class="col-md-6">
                            <strong>服务:</strong> <span class="text-primary">${service}</span>
                        </div>
                        <div class="col-md-6">
                            <strong>状态:</strong> <span class="badge bg-success">${state}</span>
                        </div>
                    </div>
                    ${portInfo.description ? `<div class="mt-2"><small class="text-muted">${portInfo.description}</small></div>` : ''}
                </div>
            </div>
            <div class="port-actions">
                <button class="btn btn-sm btn-outline-light" onclick="analyzePort(${port.port})" title="分析端口">
                    <i class="fas fa-search"></i>
                </button>
            </div>
        </div>
    `;

    return portItem;
}

// 获取端口信息
function getPortInfo(port) {
    const portMap = {
        21: { icon: 'fas fa-file-upload', description: 'FTP - 文件传输协议' },
        22: { icon: 'fas fa-terminal', description: 'SSH - 安全外壳协议' },
        23: { icon: 'fas fa-terminal', description: 'Telnet - 远程登录协议' },
        25: { icon: 'fas fa-envelope', description: 'SMTP - 简单邮件传输协议' },
        53: { icon: 'fas fa-globe', description: 'DNS - 域名系统' },
        80: { icon: 'fas fa-globe', description: 'HTTP - 超文本传输协议' },
        110: { icon: 'fas fa-envelope', description: 'POP3 - 邮局协议' },
        143: { icon: 'fas fa-envelope', description: 'IMAP - 互联网消息访问协议' },
        443: { icon: 'fas fa-lock', description: 'HTTPS - 安全超文本传输协议' },
        993: { icon: 'fas fa-envelope', description: 'IMAPS - 安全IMAP' },
        995: { icon: 'fas fa-envelope', description: 'POP3S - 安全POP3' },
        3389: { icon: 'fas fa-desktop', description: 'RDP - 远程桌面协议' },
        5432: { icon: 'fas fa-database', description: 'PostgreSQL - 数据库' },
        3306: { icon: 'fas fa-database', description: 'MySQL - 数据库' }
    };

    return portMap[port] || { icon: 'fas fa-network-wired', description: null };
}

// 分析端口（占位符功能）
function analyzePort(port) {
    showNotification(`端口 ${port} 详细分析功能即将推出`, 'info');
}

// 显示信息收集界面
function showInfoGatheringInterface() {
    const resultsContainer = document.getElementById('scan-results');
    resultsContainer.innerHTML = `
        <div class="row">
            <div class="col-md-6">
                <div class="card mb-3">
                    <div class="card-header">
                        <h6 class="mb-0"><i class="fas fa-search me-2"></i>子域名枚举</h6>
                    </div>
                    <div class="card-body">
                        <p class="text-muted small">通过 DNS 爆破和证书透明度日志发现子域名</p>
                        <div class="mb-3">
                            <input type="text" class="form-control" id="subdomainTarget" placeholder="example.com">
                        </div>
                        <button class="btn btn-primary" onclick="startSubdomainEnum()">
                            <i class="fas fa-play me-2"></i>开始枚举
                        </button>
                    </div>
                </div>
            </div>
            <div class="col-md-6">
                <div class="card mb-3">
                    <div class="card-header">
                        <h6 class="mb-0"><i class="fas fa-network-wired me-2"></i>服务指纹识别</h6>
                    </div>
                    <div class="card-body">
                        <p class="text-muted small">扫描端口并识别服务版本信息</p>
                        <div class="mb-3">
                            <input type="text" class="form-control" id="serviceTarget" placeholder="192.168.1.1 或 example.com">
                        </div>
                        <button class="btn btn-primary" onclick="startServiceDiscovery()">
                            <i class="fas fa-fingerprint me-2"></i>开始识别
                        </button>
                    </div>
                </div>
            </div>
        </div>
        <div class="row">
            <div class="col-md-6">
                <div class="card mb-3">
                    <div class="card-header">
                        <h6 class="mb-0"><i class="fas fa-globe-americas me-2"></i>DNS 分析</h6>
                    </div>
                    <div class="card-body">
                        <p class="text-muted small">查询 A、MX、NS、TXT 等 DNS 记录</p>
                        <div class="mb-3">
                            <input type="text" class="form-control" id="dnsTarget" placeholder="example.com">
                        </div>
                        <button class="btn btn-info" onclick="startDNSAnalysis()">
                            <i class="fas fa-dns me-2"></i>分析 DNS
                        </button>
                    </div>
                </div>
            </div>
            <div class="col-md-6">
                <div class="card mb-3">
                    <div class="card-header">
                        <h6 class="mb-0"><i class="fas fa-microchip me-2"></i>技术栈识别</h6>
                    </div>
                    <div class="card-body">
                        <p class="text-muted small">识别网站使用的框架、CMS 和技术</p>
                        <div class="mb-3">
                            <input type="text" class="form-control" id="techTarget" placeholder="https://example.com">
                        </div>
                        <button class="btn btn-info" onclick="startTechIdentification()">
                            <i class="fas fa-code me-2"></i>识别技术栈
                        </button>
                    </div>
                </div>
            </div>
        </div>
        <div class="row">
            <div class="col-12">
                <div class="card">
                    <div class="card-header d-flex justify-content-between align-items-center">
                        <h6 class="mb-0"><i class="fas fa-chart-bar me-2"></i>扫描结果</h6>
                        <button class="btn btn-sm btn-outline-primary" onclick="startComprehensiveRecon()">
                            <i class="fas fa-rocket me-2"></i>综合侦察
                        </button>
                    </div>
                    <div class="card-body">
                        <div id="info-gathering-results">
                            <div class="text-center text-muted py-4">
                                <i class="fas fa-search fa-2x mb-3"></i>
                                <p>选择上方的扫描类型开始信息收集</p>
                                <small class="text-muted">或点击"综合侦察"进行全面扫描</small>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    `;
}

// 显示漏洞扫描界面
function showVulnScanInterface() {
    const resultsContainer = document.getElementById('scan-results');
    resultsContainer.innerHTML = `
        <div class="row">
            <div class="col-md-4">
                <div class="card">
                    <div class="card-header">
                        <h6 class="mb-0"><i class="fas fa-globe me-2"></i>Web应用扫描</h6>
                    </div>
                    <div class="card-body">
                        <p class="text-muted">扫描Web应用的常见漏洞</p>
                        <div class="mb-3">
                            <input type="text" class="form-control" id="webTarget" placeholder="https://example.com">
                        </div>
                        <button class="btn btn-warning" onclick="startWebVulnScan()">
                            <i class="fas fa-bug me-2"></i>开始扫描
                        </button>
                    </div>
                </div>
            </div>
            <div class="col-md-4">
                <div class="card">
                    <div class="card-header">
                        <h6 class="mb-0"><i class="fas fa-database me-2"></i>服务漏洞扫描</h6>
                    </div>
                    <div class="card-body">
                        <p class="text-muted">检测网络服务的已知漏洞</p>
                        <div class="mb-3">
                            <input type="text" class="form-control" id="serviceVulnTarget" placeholder="192.168.1.1">
                        </div>
                        <button class="btn btn-warning" onclick="startServiceVulnScan()">
                            <i class="fas fa-shield-alt me-2"></i>开始扫描
                        </button>
                    </div>
                </div>
            </div>
            <div class="col-md-4">
                <div class="card">
                    <div class="card-header">
                        <h6 class="mb-0"><i class="fas fa-folder me-2"></i>目录扫描</h6>
                    </div>
                    <div class="card-body">
                        <p class="text-muted">发现隐藏的目录和文件</p>
                        <div class="mb-3">
                            <input type="text" class="form-control" id="dirTarget" placeholder="https://example.com">
                        </div>
                        <button class="btn btn-warning" onclick="startDirScan()">
                            <i class="fas fa-folder-open me-2"></i>开始扫描
                        </button>
                    </div>
                </div>
            </div>
        </div>
        <div class="row mt-4">
            <div class="col-12">
                <div class="card">
                    <div class="card-header">
                        <h6 class="mb-0"><i class="fas fa-exclamation-triangle me-2"></i>漏洞报告</h6>
                    </div>
                    <div class="card-body">
                        <div id="vuln-scan-results">
                            <div class="text-center text-muted py-4">
                                <i class="fas fa-shield-alt fa-2x mb-3"></i>
                                <p>选择上方的扫描类型开始漏洞检测</p>
                                <div class="alert alert-warning mt-3">
                                    <i class="fas fa-exclamation-triangle me-2"></i>
                                    <strong>注意：</strong>仅在授权的目标上进行漏洞扫描
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    `;
}

// 子域名枚举功能
function startSubdomainEnum() {
    const target = document.getElementById('subdomainTarget').value;
    if (!target) {
        showNotification('请输入目标域名', 'warning');
        return;
    }

    const resultsDiv = document.getElementById('info-gathering-results');
    resultsDiv.innerHTML = `
        <div class="text-center py-4">
            <div class="spinner-border text-primary" role="status">
                <span class="visually-hidden">扫描中...</span>
            </div>
            <p class="mt-3">正在枚举 ${target} 的子域名...</p>
            <small class="text-muted">这可能需要几分钟时间，请稍候...</small>
        </div>
    `;

    // 首先需要获取或创建目标 ID
    // 调用真实的子域名枚举 API
    fetch('/api/targets', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            name: target,
            url: `https://${target}`,
            type: 'domain'
        })
    })
        .then(response => response.json())
        .then(data => {
            const targetId = data.target?.id;
            if (!targetId) {
                // 尝试从现有目标中查找
                return fetch('/api/targets')
                    .then(r => r.json())
                    .then(targets => {
                        const found = targets.find(t => t.url?.includes(target) || t.name?.includes(target));
                        return found?.id;
                    });
            }
            return targetId;
        })
        .then(targetId => {
            if (!targetId) {
                resultsDiv.innerHTML = `<div class="alert alert-danger">无法找到或创建目标</div>`;
                return;
            }

            // 调用子域名枚举 API
            return fetch('/api/recon/subdomain', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ target_id: targetId })
            });
        })
        .then(response => {
            if (response) return response.json();
        })
        .then(data => {
            if (!data) return;

            if (data.status === 'completed') {
                const subdomains = data.subdomains || [];
                if (subdomains.length === 0) {
                    resultsDiv.innerHTML = `
                    <div class="alert alert-info">
                        <i class="fas fa-info-circle me-2"></i>
                        未发现子域名。尝试使用其他工具或检查域名是否正确。
                    </div>
                `;
                    return;
                }

                resultsDiv.innerHTML = `
                <h6 class="mb-3"><i class="fas fa-globe me-2"></i>发现 ${subdomains.length} 个子域名：</h6>
                <div class="table-responsive">
                    <table class="table table-hover">
                        <thead><tr><th>子域名</th><th>来源</th><th>操作</th></tr></thead>
                        <tbody>
                            ${subdomains.map(sub => `
                                <tr>
                                    <td><code>${sub.subdomain || sub}</code></td>
                                    <td>${sub.source || '-'}</td>
                                    <td>
                                        <button class="btn btn-sm btn-outline-primary" onclick="scanSubdomain('${sub.subdomain || sub}')">
                                            <i class="fas fa-search"></i> 扫描
                                        </button>
                                    </td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                </div>
            `;
            } else {
                resultsDiv.innerHTML = `<div class="alert alert-danger">扫描失败: ${data.message || '未知错误'}</div>`;
            }
        })
        .catch(error => {
            resultsDiv.innerHTML = `<div class="alert alert-danger">请求失败: ${error.message}</div>`;
        });
}

// 扫描子域名
function scanSubdomain(subdomain) {
    showNotification(`正在扫描 ${subdomain}...`, 'info');
    // 直接对子域名进行端口扫描
    fetch('/api/targets', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            name: subdomain,
            url: `https://${subdomain}`,
            type: 'domain'
        })
    })
        .then(r => r.json())
        .then(data => {
            if (data.target?.url) {
                scanTarget(data.target.url, 'port_scan');
            }
        });
}

// 服务发现功能
function startServiceDiscovery() {
    const target = document.getElementById('serviceTarget').value;
    if (!target) {
        showNotification('请输入目标地址', 'warning');
        return;
    }

    const resultsDiv = document.getElementById('info-gathering-results');
    resultsDiv.innerHTML = `
        <div class="text-center py-4">
            <div class="spinner-border text-primary" role="status">
                <span class="visually-hidden">扫描中...</span>
            </div>
            <p class="mt-3">正在识别 ${target} 的服务指纹...</p>
            <small class="text-muted">包括端口扫描和服务版本检测...</small>
        </div>
    `;

    // 创建或获取目标
    fetch('/api/targets', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            name: target,
            url: target.includes('://') ? target : `http://${target}`,
            type: target.match(/^\d+\.\d+\.\d+\.\d+$/) ? 'ip' : 'domain'
        })
    })
        .then(r => r.json())
        .then(data => {
            const targetId = data.target?.id;
            if (!targetId) {
                return fetch('/api/targets')
                    .then(r => r.json())
                    .then(targets => {
                        const found = targets.find(t => t.url?.includes(target) || t.name?.includes(target));
                        return found?.id;
                    });
            }
            return targetId;
        })
        .then(targetId => {
            if (!targetId) {
                resultsDiv.innerHTML = `<div class="alert alert-danger">无法找到或创建目标</div>`;
                return;
            }

            // 调用服务指纹识别 API
            return fetch('/api/recon/services', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ target_id: targetId })
            });
        })
        .then(response => {
            if (response) return response.json();
        })
        .then(data => {
            if (!data) return;

            if (data.status === 'completed') {
                const services = data.services || [];
                if (services.length === 0) {
                    resultsDiv.innerHTML = `
                    <div class="alert alert-info">
                        <i class="fas fa-info-circle me-2"></i>
                        未发现开放服务。目标可能使用了防火墙或服务未启动。
                    </div>
                `;
                    return;
                }

                resultsDiv.innerHTML = `
                <h6 class="mb-3"><i class="fas fa-server me-2"></i>发现 ${services.length} 个服务：</h6>
                <div class="table-responsive">
                    <table class="table table-hover">
                        <thead><tr><th>端口</th><th>协议</th><th>服务</th><th>版本</th><th>状态</th></tr></thead>
                        <tbody>
                            ${services.map(svc => `
                                <tr>
                                    <td><strong>${svc.port}</strong></td>
                                    <td>${svc.protocol || 'tcp'}</td>
                                    <td><span class="badge bg-primary">${svc.service || '未知'}</span></td>
                                    <td>${svc.version || '-'}</td>
                                    <td><span class="badge bg-success">开放</span></td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                </div>
                <div class="mt-3">
                    <button class="btn btn-warning" onclick="runVulnScanOnServices('${target}')">
                        <i class="fas fa-bug me-2"></i>对这些服务进行漏洞扫描
                    </button>
                </div>
            `;
            } else {
                resultsDiv.innerHTML = `<div class="alert alert-danger">扫描失败: ${data.message || '未知错误'}</div>`;
            }
        })
        .catch(error => {
            resultsDiv.innerHTML = `<div class="alert alert-danger">请求失败: ${error.message}</div>`;
        });
}

// 对服务进行漏洞扫描
function runVulnScanOnServices(target) {
    document.getElementById('nav-vuln-scan').click();
    setTimeout(() => {
        const input = document.getElementById('serviceVulnTarget');
        if (input) {
            input.value = target;
            startServiceVulnScan();
        }
    }, 500);
}

// DNS 分析功能
function startDNSAnalysis() {
    const target = document.getElementById('dnsTarget').value;
    if (!target) {
        showNotification('请输入目标域名', 'warning');
        return;
    }

    const resultsDiv = document.getElementById('info-gathering-results');
    resultsDiv.innerHTML = `
        <div class="text-center py-4">
            <div class="spinner-border text-info" role="status">
                <span class="visually-hidden">分析中...</span>
            </div>
            <p class="mt-3">正在分析 ${target} 的 DNS 记录...</p>
        </div>
    `;

    // 创建或获取目标
    getOrCreateTarget(target)
        .then(targetId => {
            if (!targetId) {
                resultsDiv.innerHTML = `<div class="alert alert-danger">无法找到或创建目标</div>`;
                return;
            }

            // 调用 DNS 分析 API
            return fetch('/api/recon/dns', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ target_id: targetId })
            });
        })
        .then(response => {
            if (response) return response.json();
        })
        .then(data => {
            if (!data) return;

            if (data.status === 'completed' || data.dns) {
                const dns = data.dns || {};
                let html = `<h6 class="mb-3"><i class="fas fa-globe-americas me-2"></i>DNS 分析结果</h6>`;

                const recordTypes = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA'];
                let hasRecords = false;

                recordTypes.forEach(type => {
                    const records = dns[type] || dns[type.toLowerCase()];
                    if (records && records.length > 0) {
                        hasRecords = true;
                        html += `
                            <div class="card mb-2">
                                <div class="card-header py-2">
                                    <strong>${type} 记录</strong>
                                    <span class="badge bg-primary float-end">${records.length}</span>
                                </div>
                                <ul class="list-group list-group-flush">
                                    ${records.map(r => `<li class="list-group-item"><code>${r}</code></li>`).join('')}
                                </ul>
                            </div>
                        `;
                    }
                });

                if (!hasRecords) {
                    html += `<div class="alert alert-info">未找到 DNS 记录，可能域名不存在或 DNS 服务器未响应。</div>`;
                }

                resultsDiv.innerHTML = html;
            } else {
                resultsDiv.innerHTML = `<div class="alert alert-danger">DNS 分析失败: ${data.message || '未知错误'}</div>`;
            }
        })
        .catch(error => {
            resultsDiv.innerHTML = `<div class="alert alert-danger">请求失败: ${error.message}</div>`;
        });
}

// 技术栈识别功能
function startTechIdentification() {
    const target = document.getElementById('techTarget').value;
    if (!target) {
        showNotification('请输入目标 URL', 'warning');
        return;
    }

    const resultsDiv = document.getElementById('info-gathering-results');
    resultsDiv.innerHTML = `
        <div class="text-center py-4">
            <div class="spinner-border text-info" role="status">
                <span class="visually-hidden">识别中...</span>
            </div>
            <p class="mt-3">正在识别 ${target} 的技术栈...</p>
        </div>
    `;

    getOrCreateTarget(target)
        .then(targetId => {
            if (!targetId) {
                resultsDiv.innerHTML = `<div class="alert alert-danger">无法找到或创建目标</div>`;
                return;
            }

            // 调用技术栈识别 API
            return fetch('/api/recon/tech', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ target_id: targetId })
            });
        })
        .then(response => {
            if (response) return response.json();
        })
        .then(data => {
            if (!data) return;

            if (data.status === 'completed' || data.technologies) {
                const techs = data.technologies || [];
                if (techs.length === 0) {
                    resultsDiv.innerHTML = `
                        <div class="alert alert-info">
                            <i class="fas fa-info-circle me-2"></i>
                            未能识别技术栈。可能目标网站不可访问或使用了自定义技术。
                        </div>
                    `;
                    return;
                }

                // 按类别分组技术
                const categories = {};
                techs.forEach(tech => {
                    const cat = tech.category || '其他';
                    if (!categories[cat]) categories[cat] = [];
                    categories[cat].push(tech);
                });

                let html = `<h6 class="mb-3"><i class="fas fa-microchip me-2"></i>识别到 ${techs.length} 项技术</h6>`;
                html += '<div class="row">';

                Object.entries(categories).forEach(([category, items]) => {
                    html += `
                        <div class="col-md-6 mb-3">
                            <div class="card">
                                <div class="card-header py-2">${category}</div>
                                <ul class="list-group list-group-flush">
                                    ${items.map(item => `
                                        <li class="list-group-item d-flex justify-content-between">
                                            <span>${item.name}</span>
                                            ${item.version ? `<span class="badge bg-secondary">${item.version}</span>` : ''}
                                        </li>
                                    `).join('')}
                                </ul>
                            </div>
                        </div>
                    `;
                });

                html += '</div>';
                resultsDiv.innerHTML = html;
            } else {
                resultsDiv.innerHTML = `<div class="alert alert-danger">技术栈识别失败: ${data.message || '未知错误'}</div>`;
            }
        })
        .catch(error => {
            resultsDiv.innerHTML = `<div class="alert alert-danger">请求失败: ${error.message}</div>`;
        });
}

// 综合侦察功能
function startComprehensiveRecon() {
    const subdomainTarget = document.getElementById('subdomainTarget')?.value;
    const serviceTarget = document.getElementById('serviceTarget')?.value;
    const target = subdomainTarget || serviceTarget;

    if (!target) {
        showNotification('请先在任一输入框输入目标', 'warning');
        return;
    }

    const resultsDiv = document.getElementById('info-gathering-results');
    resultsDiv.innerHTML = `
        <div class="text-center py-4">
            <div class="spinner-border text-primary" role="status">
                <span class="visually-hidden">扫描中...</span>
            </div>
            <p class="mt-3">正在对 ${target} 进行综合侦察...</p>
            <small class="text-muted">包括子域名、DNS、服务指纹和技术栈识别</small>
            <div class="progress mt-3" style="height: 20px;">
                <div class="progress-bar progress-bar-striped progress-bar-animated" id="recon-progress" style="width: 0%">0%</div>
            </div>
        </div>
    `;

    getOrCreateTarget(target)
        .then(targetId => {
            if (!targetId) {
                resultsDiv.innerHTML = `<div class="alert alert-danger">无法找到或创建目标</div>`;
                return;
            }

            // 调用综合侦察 API
            return fetch('/api/recon/comprehensive', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ target_id: targetId })
            });
        })
        .then(response => {
            if (response) return response.json();
        })
        .then(data => {
            if (!data) return;

            if (data.scan_id) {
                // 监控综合侦察进度
                monitorReconProgress(data.scan_id, resultsDiv, target);
            } else if (data.status === 'completed') {
                displayComprehensiveResults(data, resultsDiv);
            } else {
                resultsDiv.innerHTML = `<div class="alert alert-danger">启动侦察失败: ${data.message || '未知错误'}</div>`;
            }
        })
        .catch(error => {
            resultsDiv.innerHTML = `<div class="alert alert-danger">请求失败: ${error.message}</div>`;
        });
}

// 监控侦察进度
function monitorReconProgress(scanId, resultsDiv, target) {
    const checkStatus = () => {
        fetch(`/api/recon/${scanId}`)
            .then(response => response.json())
            .then(data => {
                const progressBar = document.getElementById('recon-progress');
                if (progressBar) {
                    progressBar.style.width = `${data.progress || 0}%`;
                    progressBar.textContent = `${data.progress || 0}%`;
                }

                if (data.status === 'running') {
                    setTimeout(checkStatus, 3000);
                } else if (data.status === 'completed') {
                    displayComprehensiveResults(data.results || data, resultsDiv);
                } else if (data.status === 'error') {
                    resultsDiv.innerHTML = `<div class="alert alert-danger">侦察错误: ${data.error}</div>`;
                }
            })
            .catch(error => {
                resultsDiv.innerHTML = `<div class="alert alert-danger">获取状态失败: ${error.message}</div>`;
            });
    };
    setTimeout(checkStatus, 2000);
}

// 显示综合侦察结果
function displayComprehensiveResults(data, container) {
    let html = '<h6 class="mb-3"><i class="fas fa-rocket me-2"></i>综合侦察结果</h6>';

    // 子域名
    if (data.subdomains && data.subdomains.length > 0) {
        html += `
            <div class="card mb-3">
                <div class="card-header"><i class="fas fa-globe me-2"></i>子域名 (${data.subdomains.length})</div>
                <div class="card-body" style="max-height: 200px; overflow-y: auto;">
                    ${data.subdomains.slice(0, 20).map(s => `<span class="badge bg-primary me-1 mb-1">${s.subdomain || s}</span>`).join('')}
                    ${data.subdomains.length > 20 ? `<span class="text-muted">... 还有 ${data.subdomains.length - 20} 个</span>` : ''}
                </div>
            </div>
        `;
    }

    // 服务
    if (data.services && data.services.length > 0) {
        html += `
            <div class="card mb-3">
                <div class="card-header"><i class="fas fa-server me-2"></i>服务 (${data.services.length})</div>
                <div class="card-body">
                    <table class="table table-sm">
                        <thead><tr><th>端口</th><th>服务</th><th>版本</th></tr></thead>
                        <tbody>
                            ${data.services.slice(0, 10).map(s => `<tr><td>${s.port}</td><td>${s.service}</td><td>${s.version || '-'}</td></tr>`).join('')}
                        </tbody>
                    </table>
                </div>
            </div>
        `;
    }

    // 技术栈
    if (data.technologies && data.technologies.length > 0) {
        html += `
            <div class="card mb-3">
                <div class="card-header"><i class="fas fa-microchip me-2"></i>技术栈</div>
                <div class="card-body">
                    ${data.technologies.map(t => `<span class="badge bg-info me-1 mb-1">${t.name}</span>`).join('')}
                </div>
            </div>
        `;
    }

    container.innerHTML = html;
}

// 辅助函数：获取或创建目标
function getOrCreateTarget(target) {
    return fetch('/api/targets', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            name: target,
            url: target.includes('://') ? target : `https://${target}`,
            type: target.match(/^\d+\.\d+\.\d+\.\d+$/) ? 'ip' : 'domain'
        })
    })
        .then(r => r.json())
        .then(data => {
            if (data.target?.id) return data.target.id;
            // 尝试从现有目标中查找
            return fetch('/api/targets')
                .then(r => r.json())
                .then(targets => {
                    const found = targets.find(t => t.url?.includes(target) || t.name?.includes(target));
                    return found?.id;
                });
        });
}

// Web应用漏洞扫描
function startWebVulnScan() {
    const target = document.getElementById('webTarget').value;
    if (!target) {
        showNotification('请输入目标URL', 'warning');
        return;
    }

    const resultsDiv = document.getElementById('vuln-scan-results');
    resultsDiv.innerHTML = `
        <div class="text-center py-4">
            <div class="spinner-border text-warning" role="status">
                <span class="visually-hidden">扫描中...</span>
            </div>
            <p class="mt-3">正在扫描 ${target} 的Web应用漏洞...</p>
            <small class="text-muted" id="vuln-scan-status">初始化中...</small>
        </div>
    `;

    // 调用真实 API
    fetch('/api/vuln-scan/web', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target_url: target })
    })
        .then(response => response.json())
        .then(data => {
            if (data.status === 'started') {
                monitorVulnScan(data.scan_id, resultsDiv, 'web');
            } else {
                resultsDiv.innerHTML = `<div class="alert alert-danger">扫描启动失败: ${data.message}</div>`;
            }
        })
        .catch(error => {
            resultsDiv.innerHTML = `<div class="alert alert-danger">请求失败: ${error.message}</div>`;
        });
}

// 监控漏洞扫描进度
function monitorVulnScan(scanId, resultsDiv, scanType) {
    const checkStatus = () => {
        fetch(`/api/vuln-scan/${scanId}`)
            .then(response => response.json())
            .then(data => {
                if (data.status === 'running') {
                    const statusEl = document.getElementById('vuln-scan-status');
                    if (statusEl) {
                        statusEl.textContent = `${data.current_status || '扫描中...'} (${data.progress || 0}%)`;
                    }
                    setTimeout(checkStatus, 2000);
                } else if (data.status === 'completed') {
                    displayVulnScanResults(data.results, resultsDiv, scanType);
                } else if (data.status === 'error') {
                    resultsDiv.innerHTML = `<div class="alert alert-danger">扫描错误: ${data.error}</div>`;
                }
            })
            .catch(error => {
                resultsDiv.innerHTML = `<div class="alert alert-danger">获取状态失败: ${error.message}</div>`;
            });
    };
    setTimeout(checkStatus, 2000);
}

// 显示漏洞扫描结果
function displayVulnScanResults(results, container, scanType) {
    if (!results || results.length === 0) {
        container.innerHTML = `
            <div class="alert alert-success">
                <i class="fas fa-check-circle me-2"></i>
                扫描完成，未发现安全问题！
            </div>
        `;
        return;
    }

    const severityColors = {
        'critical': 'danger',
        'high': 'warning',
        'medium': 'info',
        'low': 'secondary',
        'info': 'light'
    };

    const severityIcons = {
        'critical': 'skull-crossbones',
        'high': 'exclamation-triangle',
        'medium': 'exclamation-circle',
        'low': 'info-circle',
        'info': 'info'
    };

    let html = `<h6 class="mb-3">发现 ${results.length} 个安全问题：</h6>`;

    results.forEach(vuln => {
        const severity = (vuln.severity || 'info').toLowerCase();
        const color = severityColors[severity] || 'secondary';
        const icon = severityIcons[severity] || 'info-circle';

        html += `
            <div class="card mb-3 border-${color}">
                <div class="card-header bg-${color} ${severity === 'low' || severity === 'info' ? 'text-dark' : 'text-white'}">
                    <i class="fas fa-${icon} me-2"></i>
                    <strong>${vuln.title}</strong>
                    <span class="badge bg-dark float-end">${severity.toUpperCase()}</span>
                </div>
                <div class="card-body">
                    <p>${vuln.description}</p>
                    ${vuln.affected_url ? `<p><strong>影响URL:</strong> <code>${vuln.affected_url}</code></p>` : ''}
                    ${vuln.cve ? `<p><strong>CVE:</strong> ${vuln.cve}</p>` : ''}
                    ${vuln.remediation ? `<p><strong>修复建议:</strong> ${vuln.remediation}</p>` : ''}
                </div>
            </div>
        `;
    });

    // 添加导出按钮
    html += `
        <div class="d-flex gap-2 mt-3">
            <button class="btn btn-primary" onclick="exportVulnReport('${scanType}')">
                <i class="fas fa-download me-2"></i>导出报告
            </button>
        </div>
    `;

    container.innerHTML = html;
}

// 服务漏洞扫描
function startServiceVulnScan() {
    const target = document.getElementById('serviceVulnTarget').value;
    if (!target) {
        showNotification('请输入目标地址', 'warning');
        return;
    }

    const resultsDiv = document.getElementById('vuln-scan-results');
    resultsDiv.innerHTML = `
        <div class="text-center py-4">
            <div class="spinner-border text-warning" role="status">
                <span class="visually-hidden">扫描中...</span>
            </div>
            <p class="mt-3">正在扫描 ${target} 的服务漏洞...</p>
            <small class="text-muted" id="vuln-scan-status">初始化中...</small>
        </div>
    `;

    fetch('/api/vuln-scan/service', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: target })
    })
        .then(response => response.json())
        .then(data => {
            if (data.status === 'started') {
                monitorVulnScan(data.scan_id, resultsDiv, 'service');
            } else {
                resultsDiv.innerHTML = `<div class="alert alert-danger">扫描启动失败: ${data.message}</div>`;
            }
        })
        .catch(error => {
            resultsDiv.innerHTML = `<div class="alert alert-danger">请求失败: ${error.message}</div>`;
        });
}

// 目录扫描
function startDirScan() {
    const target = document.getElementById('dirTarget').value;
    if (!target) {
        showNotification('请输入目标URL', 'warning');
        return;
    }

    const resultsDiv = document.getElementById('vuln-scan-results');
    resultsDiv.innerHTML = `
        <div class="text-center py-4">
            <div class="spinner-border text-warning" role="status">
                <span class="visually-hidden">扫描中...</span>
            </div>
            <p class="mt-3">正在扫描 ${target} 的目录结构...</p>
            <small class="text-muted" id="vuln-scan-status">初始化中...</small>
        </div>
    `;

    fetch('/api/vuln-scan/directory', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target_url: target })
    })
        .then(response => response.json())
        .then(data => {
            if (data.status === 'started') {
                monitorDirScan(data.scan_id, resultsDiv);
            } else {
                resultsDiv.innerHTML = `<div class="alert alert-danger">扫描启动失败: ${data.message}</div>`;
            }
        })
        .catch(error => {
            resultsDiv.innerHTML = `<div class="alert alert-danger">请求失败: ${error.message}</div>`;
        });
}

// 监控目录扫描进度
function monitorDirScan(scanId, resultsDiv) {
    const checkStatus = () => {
        fetch(`/api/vuln-scan/${scanId}`)
            .then(response => response.json())
            .then(data => {
                if (data.status === 'running') {
                    const statusEl = document.getElementById('vuln-scan-status');
                    if (statusEl) {
                        statusEl.textContent = `${data.current_status || '扫描中...'} (${data.progress || 0}%)`;
                    }
                    setTimeout(checkStatus, 1500);
                } else if (data.status === 'completed') {
                    displayDirScanResults(data.results, resultsDiv);
                } else if (data.status === 'error') {
                    resultsDiv.innerHTML = `<div class="alert alert-danger">扫描错误: ${data.error}</div>`;
                }
            })
            .catch(error => {
                resultsDiv.innerHTML = `<div class="alert alert-danger">获取状态失败: ${error.message}</div>`;
            });
    };
    setTimeout(checkStatus, 1500);
}

// 显示目录扫描结果
function displayDirScanResults(results, container) {
    if (!results || results.length === 0) {
        container.innerHTML = `
            <div class="alert alert-info">
                <i class="fas fa-info-circle me-2"></i>
                扫描完成，未发现可访问的目录或文件。
            </div>
        `;
        return;
    }

    const statusColors = {
        200: 'success',
        301: 'info',
        302: 'info',
        403: 'warning',
        500: 'danger'
    };

    let html = `<h6 class="mb-3">发现 ${results.length} 个路径：</h6>`;
    html += '<div class="table-responsive"><table class="table table-hover">';
    html += '<thead><tr><th>路径</th><th>状态码</th><th>大小</th><th>类型</th></tr></thead>';
    html += '<tbody>';

    results.forEach(item => {
        const color = statusColors[item.status_code] || 'secondary';
        html += `
            <tr>
                <td><a href="${item.url}" target="_blank">${item.url}</a></td>
                <td><span class="badge bg-${color}">${item.status_code}</span></td>
                <td>${formatBytes(item.content_length)}</td>
                <td>${item.content_type ? item.content_type.split(';')[0] : '-'}</td>
            </tr>
        `;
    });

    html += '</tbody></table></div>';
    container.innerHTML = html;
}

// 格式化字节大小
function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// 导出漏洞报告
function exportVulnReport(scanType) {
    showNotification('正在生成报告...', 'info');

    const target = document.getElementById('webTarget')?.value ||
        document.getElementById('serviceVulnTarget')?.value || 'Unknown';

    fetch('/api/report/generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            report_type: 'markdown',
            scan_data: {
                target: target,
                scan_type: scanType,
                vulnerabilities: window.lastScanResults || []
            }
        })
    })
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success') {
                showNotification('报告生成成功！', 'success');
                if (data.content) {
                    const blob = new Blob([data.content], { type: 'text/markdown' });
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = `vuln_report_${Date.now()}.md`;
                    a.click();
                    URL.revokeObjectURL(url);
                }
            } else {
                showNotification('报告生成失败: ' + data.message, 'danger');
            }
        })
        .catch(error => {
            showNotification('导出失败: ' + error.message, 'danger');
        });
}

// 编辑目标功能的实现
function editTarget(targetId) {
    showNotification('目标编辑功能正在开发中', 'info');
}