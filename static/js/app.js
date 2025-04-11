// 设置活动导航项
function setActiveNav(activeItem) {
    document.querySelectorAll('.nav-link').forEach(item => {
        item.classList.remove('active');
    });
    activeItem.classList.add('active');
}

document.addEventListener('DOMContentLoaded', function() {
    // 初始化目标列表
    loadTargets();
    
    // 添加目标按钮事件
    document.getElementById('add-target-btn').addEventListener('click', function() {
        showAddTargetModal();
    });

    // 导航栏点击事件
    document.getElementById('nav-targets').addEventListener('click', function(e) {
        e.preventDefault();
        setActiveNav(this);
        document.querySelector('.main-content h4').textContent = '目标管理';
        document.getElementById('scan-results').innerHTML = '';
    });

    document.getElementById('nav-info-gathering').addEventListener('click', function(e) {
        e.preventDefault();
        setActiveNav(this);
        document.querySelector('.main-content h4').textContent = '信息收集';
        document.getElementById('scan-results').innerHTML = '<p>信息收集功能开发中...</p>';
    });

    document.getElementById('nav-vuln-scan').addEventListener('click', function(e) {
        e.preventDefault();
        setActiveNav(this);
        document.querySelector('.main-content h4').textContent = '漏洞扫描';
        document.getElementById('scan-results').innerHTML = '<p>漏洞扫描功能开发中...</p>';
    });

    document.getElementById('nav-report').addEventListener('click', function(e) {
        e.preventDefault();
        setActiveNav(this);
        document.querySelector('.main-content h4').textContent = '历史扫描记录';
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

// 加载目标列表
function loadTargets() {
    fetch('/api/targets')
        .then(response => response.json())
        .then(data => {
            const targetList = document.getElementById('target-list');
            targetList.innerHTML = '';
            
            if (data.length === 0) {
                targetList.innerHTML = '<p>暂无目标</p>';
                return;
            }
            
            data.forEach(target => {
                const targetItem = document.createElement('div');
                targetItem.className = 'target-item mb-2 p-2 border rounded';
                targetItem.innerHTML = `
                    <h6>${target.name || target.url}</h6>
                    <small class="text-muted">${target.type}</small>
                `;
                targetList.appendChild(targetItem);
            });
        });
}

// 显示添加目标模态框
function showAddTargetModal() {
    const targetUrl = prompt('请输入目标URL:', 'http://example.com');
    if (targetUrl) {
        const targetData = {
            url: targetUrl,
            name: `目标-${new Date().toLocaleString()}`,
            type: 'website'
        };
        
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
                loadTargets(); // 刷新目标列表
                // 触发端口扫描
                startScan(targetData.url, 'port_scan');
            } else {
                alert('添加目标失败: ' + (data.message || '未知错误'));
            }
        })
        .catch(error => {
            alert('添加目标时出错: ' + error.message);
        });
    }
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
    let estimatedProgress = 0;
    const maxProgress = 90; // 最大预估进度
    
    // 更新进度条
    const updateProgress = (progress, status) => {
        progressBar.style.width = `${progress}%`;
        progressBar.textContent = `${progress}%`;
        statusText.textContent = status;
    };

    // 初始状态
    updateProgress(5, '正在启动扫描...');

    const progressInterval = setInterval(() => {
        estimatedProgress = Math.min(estimatedProgress + 5, maxProgress);
        updateProgress(estimatedProgress, '扫描进行中...');
    }, 1000);

    const checkProgress = () => {
        fetch(`/api/scan/${scanId}`)
            .then(response => response.json())
            .then(data => {
                if (data.status === 'completed') {
                    clearInterval(progressInterval);
                    updateProgress(100, '扫描完成!');
                    setTimeout(() => {
                        displayScanResults(data.result);
                        updateProgress(0, '准备扫描...');
                    }, 1000);
                } else if (data.status === 'running') {
                    setTimeout(checkProgress, 2000);
                } else if (data.status === 'error') {
                    clearInterval(progressInterval);
                    updateProgress(0, `扫描错误: ${data.message}`);
                }
            });
    };
    checkProgress();
}

// 显示扫描结果
function displayScanResults(results) {
    const resultsContainer = document.getElementById('scan-results');
    resultsContainer.innerHTML = '';
    
    if (results.ports) {
        results.ports.forEach(port => {
            const portItem = document.createElement('div');
            portItem.className = 'port-item p-3 mb-2 bg-light rounded';
            portItem.innerHTML = `
                <strong>端口:</strong> ${port.port} (${port.protocol})<br>
                <strong>服务:</strong> ${port.service}<br>
                <strong>状态:</strong> ${port.state}
            `;
            resultsContainer.appendChild(portItem);
        });
    }
}
