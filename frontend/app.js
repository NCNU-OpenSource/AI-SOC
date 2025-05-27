const API_URL = 'http://localhost:3000';

// 获取最新分析结果
async function getLatestAnalysis() {
    try {
        const response = await fetch(`${API_URL}/api/latest-analysis`);
        const data = await response.json();
        
        // 更新時間戳
        const timestampElement = document.getElementById('timestamp');
        if (data.timestamp) {
            timestampElement.textContent = `Last updated: ${new Date(data.timestamp).toLocaleString()}`;
        }
        
        // 更新分析結果
        const resultsDiv = document.getElementById('analysisResults');
        if (data.results) {
            resultsDiv.innerHTML = `
                <div class="alert ${data.results.is_attack ? 'alert-danger' : 'alert-success'}">
                    <h4>攻擊狀態: ${data.results.is_attack ? '檢測到攻擊' : '正常'}</h4>
                    <p>${data.results.general_response || '無分析說明'}</p>
                    ${data.results.need_test_command && data.results.shell_script ? `
                        <div class="mt-3">
                            <h5>建議的測試命令：</h5>
                            <pre>${data.results.shell_script}</pre>
                        </div>
                    ` : ''}
                </div>
            `;
        } else {
            resultsDiv.innerHTML = '<div class="alert alert-info">No analysis results available</div>';
        }
    } catch (error) {
        console.error('Error fetching analysis:', error);
        showError('Failed to fetch analysis results');
    }
}

// 触发新的分析
async function triggerAnalysis() {
    try {
        const button = document.getElementById('triggerAnalysis');
        button.disabled = true;
        button.textContent = 'Analyzing...';

        const response = await fetch(`${API_URL}/api/trigger-analysis`, {
            method: 'POST'
        });
        
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        const data = await response.json();
        if (data.error) {
            throw new Error(data.message || 'Analysis failed');
        }
        
        await getLatestAnalysis();
    } catch (error) {
        console.error('Error triggering analysis:', error);
        showError(`Failed to trigger analysis: ${error.message}`);
    } finally {
        const button = document.getElementById('triggerAnalysis');
        button.disabled = false;
        button.textContent = 'Trigger Analysis';
    }
}

// 显示错误信息
function showError(message) {
    const resultsElement = document.getElementById('analysisResults');
    resultsElement.innerHTML = `<div class="alert alert-danger">${message}</div>`;
}

// 事件监听器
document.getElementById('triggerAnalysis').addEventListener('click', triggerAnalysis);

// 页面加载时获取最新结果
getLatestAnalysis();

// 定期刷新结果（每30秒）
setInterval(getLatestAnalysis, 30000);

// 每30秒更新一次儀表板
setInterval(updateDashboard, 30000);

async function updateDashboard() {
    try {
        const response = await fetch('/api/latest-analysis');
        const data = await response.json();
        
        // 更新時間戳
        document.getElementById('timestamp').textContent = 
            new Date(data.timestamp).toLocaleString();
        
        // 更新分析結果
        const resultsDiv = document.getElementById('analysisResults');
        resultsDiv.innerHTML = `
            <div class="alert ${data.results.is_attack ? 'alert-danger' : 'alert-success'}">
                <h4>攻擊狀態: ${data.results.is_attack ? '檢測到攻擊' : '正常'}</h4>
                <p>${data.results.general_response || '無分析說明'}</p>
                ${data.results.need_test_command && data.results.shell_script ? `
                    <div class="mt-3">
                        <h5>建議的測試命令：</h5>
                        <pre>${data.results.shell_script}</pre>
                    </div>
                ` : ''}
            </div>
        `;
    } catch (error) {
        console.error('Error updating dashboard:', error);
    }
} 