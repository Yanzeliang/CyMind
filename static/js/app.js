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

document.addEventListener('DOMContentLoaded', function() {
    // 初始化目标列表
    loadTargets();
    
    // 添加目标按钮事件 - 显示模态框
    document.getElementById('add-target-btn').addEventListener('click', function() {
        const modal = new bootstrap.Modal(document.getElementById('addTargetModal'));
        modal.show();
    });
    
    // 保存目标按钮事件
    document.getElementById('saveTargetBtn').addEventListener('click', function() {
        saveNewTarget();
    });

    // 导航栏点击事件
    document.getElementById('nav-targets').addEventListener('click', function(e) {
        e.preventDefault();
        setActiveNav(this);
        document.querySelector('.page-title').textContent = '目标管理';
        document.querySelector('.page-subtitle').textContent = '管理和配置扫描目标';
        showEmptyState();
    });

    document.getElementById('nav-info-gathering').addEventListener('click', function(e) {
        e.preventDefault();
        setActiveNav(this);
        document.querySelector('.page-title').textContent = '信息收集';
        document.querySelector('.page-subtitle').textContent = '子域名枚举和服务发现';
        showInfoGatheringInterface();
    });

    document.getElementById('nav-vuln-scan').addEventListener('click', function(e) {
        e.preventDefault();
        setActiveNav(this);
        document.querySelector('.page-title').textContent = '漏洞扫描';
        document.querySelector('.page-subtitle').textContent = '自动化漏洞检测和分析';
        showVulnScanInterface();
    });

    document.getElementById('nav-report').addEventListener('click', function(e) {
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
                    btn.addEventListener('click', function() {
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
                targetItem.innerHTML = `
                    <div class="d-flex justify-content-between align-items-start">
                        <div class="flex-grow-1">
                            <h6 class="mb-1">${target.name || target.url}</h6>
                            <small class="text-muted d-block">${target.url || target.ip}</small>
                            <span class="badge bg-primary mt-1">${getTypeLabel(target.type)}</span>
                        </div>
                        <div class="target-actions">
                            <button class="btn btn-sm btn-outline-light me-1" onclick="scanTarget('${target.url || target.ip}', 'port_scan')" title="端口扫描">
                                <i class="fas fa-play"></i>
                            </button>
                            <button class="btn btn-sm btn-outline-light" onclick="editTarget(${target.id})" title="编辑">
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

// 扫描指定目标
function scanTarget(target, scanType) {
    showNotification(`正在启动对 ${target} 的扫描...`, 'info');
    startScan(target, scanType);
}

// 编辑目标（占位符功能）
function editTarget(targetId) {
    showNotification('编辑功能即将推出', 'info');
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
                <div class="card">
                    <div class="card-header">
                        <h6 class="mb-0"><i class="fas fa-search me-2"></i>子域名枚举</h6>
                    </div>
                    <div class="card-body">
                        <p class="text-muted">发现目标域名的所有子域名</p>
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
                <div class="card">
                    <div class="card-header">
                        <h6 class="mb-0"><i class="fas fa-network-wired me-2"></i>服务发现</h6>
                    </div>
                    <div class="card-body">
                        <p class="text-muted">扫描目标的开放端口和服务</p>
                        <div class="mb-3">
                            <input type="text" class="form-control" id="serviceTarget" placeholder="192.168.1.1 或 example.com">
                        </div>
                        <button class="btn btn-primary" onclick="startServiceDiscovery()">
                            <i class="fas fa-play me-2"></i>开始扫描
                        </button>
                    </div>
                </div>
            </div>
        </div>
        <div class="row mt-4">
            <div class="col-12">
                <div class="card">
                    <div class="card-header">
                        <h6 class="mb-0"><i class="fas fa-chart-bar me-2"></i>扫描结果</h6>
                    </div>
                    <div class="card-body">
                        <div id="info-gathering-results">
                            <div class="text-center text-muted py-4">
                                <i class="fas fa-search fa-2x mb-3"></i>
                                <p>选择上方的扫描类型开始信息收集</p>
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
            <small class="text-muted">这可能需要几分钟时间</small>
        </div>
    `;
    
    // 模拟子域名发现结果
    setTimeout(() => {
        const mockSubdomains = [
            'www.' + target,
            'mail.' + target,
            'ftp.' + target,
            'admin.' + target,
            'api.' + target,
            'dev.' + target
        ];
        
        resultsDiv.innerHTML = `
            <h6 class="mb-3">发现 ${mockSubdomains.length} 个子域名：</h6>
            <div class="row">
                ${mockSubdomains.map(subdomain => `
                    <div class="col-md-6 mb-2">
                        <div class="d-flex align-items-center">
                            <i class="fas fa-globe text-primary me-2"></i>
                            <span>${subdomain}</span>
                            <button class="btn btn-sm btn-outline-primary ms-auto" onclick="scanTarget('${subdomain}', 'port_scan')">
                                <i class="fas fa-search"></i>
                            </button>
                        </div>
                    </div>
                `).join('')}
            </div>
            <div class="alert alert-info mt-3">
                <i class="fas fa-info-circle me-2"></i>
                这是模拟结果。实际功能需要集成subfinder、amass等工具。
            </div>
        `;
    }, 3000);
}

// 服务发现功能
function startServiceDiscovery() {
    const target = document.getElementById('serviceTarget').value;
    if (!target) {
        showNotification('请输入目标地址', 'warning');
        return;
    }
    
    // 直接调用现有的端口扫描功能
    showNotification(`正在对 ${target} 进行服务发现...`, 'info');
    startScan(target, 'port_scan');
    
    // 将结果显示在信息收集区域
    const resultsDiv = document.getElementById('info-gathering-results');
    resultsDiv.innerHTML = `
        <div class="text-center py-4">
            <div class="spinner-border text-primary" role="status">
                <span class="visually-hidden">扫描中...</span>
            </div>
            <p class="mt-3">正在扫描 ${target} 的开放端口...</p>
        </div>
    `;
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
        </div>
    `;
    
    // 模拟漏洞扫描结果
    setTimeout(() => {
        const mockVulns = [
            { name: 'HTTP安全头缺失', severity: 'low', description: '缺少X-Frame-Options等安全头' },
            { name: '目录遍历测试', severity: 'info', description: '未发现目录遍历漏洞' },
            { name: 'SQL注入测试', severity: 'info', description: '未发现SQL注入漏洞' }
        ];
        
        resultsDiv.innerHTML = `
            <h6 class="mb-3">Web应用扫描结果：</h6>
            ${mockVulns.map(vuln => `
                <div class="alert alert-${vuln.severity === 'low' ? 'warning' : 'info'} d-flex align-items-center">
                    <i class="fas fa-${vuln.severity === 'low' ? 'exclamation-triangle' : 'info-circle'} me-3"></i>
                    <div class="flex-grow-1">
                        <strong>${vuln.name}</strong>
                        <p class="mb-0 small">${vuln.description}</p>
                    </div>
                    <span class="badge bg-${vuln.severity === 'low' ? 'warning' : 'info'}">${vuln.severity.toUpperCase()}</span>
                </div>
            `).join('')}
            <div class="alert alert-info mt-3">
                <i class="fas fa-info-circle me-2"></i>
                这是模拟结果。实际功能需要集成nuclei、xray等漏洞扫描工具。
            </div>
        `;
    }, 4000);
}

// 服务漏洞扫描
function startServiceVulnScan() {
    const target = document.getElementById('serviceVulnTarget').value;
    if (!target) {
        showNotification('请输入目标地址', 'warning');
        return;
    }
    
    showNotification('服务漏洞扫描功能正在开发中', 'info');
}

// 目录扫描
function startDirScan() {
    const target = document.getElementById('dirTarget').value;
    if (!target) {
        showNotification('请输入目标URL', 'warning');
        return;
    }
    
    showNotification('目录扫描功能正在开发中', 'info');
}

// 编辑目标功能的实现
function editTarget(targetId) {
    showNotification('目标编辑功能正在开发中', 'info');
    // TODO: 实现目标编辑功能
    // 1. 获取目标详情
    // 2. 显示编辑模态框
    // 3. 保存修改
}