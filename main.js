import OpenAI from 'openai';
import fs from 'fs';

const openai = new OpenAI({
    baseURL: "https://openrouter.ai/api/v1",
    apiKey: "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",
});

// 定義可疑的 User-Agent 模式
const suspiciousUserAgents = {
    'sqlmap': 'SQL 注入工具',
    'Dalfox': 'XSS 掃描工具',
    'curl': '自動化工具',
    'python-requests': '自動化工具'
};

// 定義可疑的 URL 模式
const suspiciousPatterns = {
    'file=../../': '路徑遍歷攻擊',
    '/admin': '管理員頁面訪問',
    '/etc/passwd': '系統文件訪問嘗試'
};

// 分析單行日誌
function analyzeLogLine(line, lineNumber) {
    const issues = [];

    // 檢查 User-Agent
    for (const [agent, description] of Object.entries(suspiciousUserAgents)) {
        if (line.includes(agent)) {
            issues.push({
                type: '可疑工具使用',
                description: description,
                details: `使用 ${agent} 工具`
            });
        }
    }

    // 檢查 URL 模式
    for (const [pattern, description] of Object.entries(suspiciousPatterns)) {
        if (line.includes(pattern)) {
            issues.push({
                type: '可疑請求',
                description: description,
                details: `包含 ${pattern} 模式`
            });
        }
    }

    // 檢查 HTTP 狀態碼
    const statusCode = line.match(/\s(\d{3})\s/)?.[1];
    if (statusCode) {
        if (statusCode === '403') {
            issues.push({
                type: '訪問被拒絕',
                description: '請求被安全機制攔截',
                details: 'HTTP 403 Forbidden'
            });
        } else if (statusCode === '500') {
            issues.push({
                type: '服務器錯誤',
                description: '可能導致服務器錯誤的請求',
                details: 'HTTP 500 Internal Server Error'
            });
        }
    }

    // 檢查來源
    if (line.includes('http://evil.com')) {
        issues.push({
            type: '可疑來源',
            description: '來自已知惡意域名',
            details: '來源: http://evil.com'
        });
    }

    return issues.length > 0 ? {
        line_number: lineNumber,
        line_content: line,
        issues: issues
    } : null;
}

async function main() {
    try {
        console.log("開始分析日誌...");
        // 讀取 log 檔案
        const logContent = fs.readFileSync('attack_logs_apache_style.txt', 'utf8');

        // 檢查檔案內容是否為空
        if (!logContent.trim()) {
            console.error("錯誤：檔案內容為空");
            return;
        }

        const completion = await openai.chat.completions.create({
            model: "meta-llama/llama-4-scout:free",
            messages: [{
                role: "user",
                content: `請直接回傳 JSON 格式的分析結果，不要加入任何其他說明或格式： {
                    "is_attack": true/false, // 是否為攻擊行為
                    "need_test_command": true/false, // 是否需要進一步測試命令確認
                    "shell_script": "測試命令或空字串", // 若 need_test_command 為 true，必須提供測試命令
                    "general_response": "攻擊說明" // 對此次攻擊的綜合描述
                }
                注意事項：
                1. 如果 need_test_command 為 true，必須在 shell_script 中提供相應的測試命令
                分析以下 log：
                ${logContent}`
            }]
        });

        console.log(`收到 API 回應`);

        if (completion.choices && completion.choices[0] && completion.choices[0].message) {
            console.log(`\n模型回應：`);
            console.log(completion.choices[0].message);

            try {
                const content = completion.choices[0].message.content;
                if (!content) {
                    console.log("模型回應內容為空");
                    return;
                }

                // 使用正則表達式提取 JSON 部分
                const jsonMatch = content.match(/\{[\s\S]*\}/);
                if (jsonMatch) {
                    const jsonStr = jsonMatch[0];
                    const json = JSON.parse(jsonStr);
                    console.log(`\n解析後的 JSON：`, json);
                } else {
                    console.error("❌ 無法找到 JSON 內容");
                    console.log("原始內容：", content);
                }
            } catch (err) {
                console.error("❌ JSON 解析失敗：", err);
                console.log("原始內容：", completion.choices[0].message.content);
            }
        } else {
            console.log("模型回應格式不正確：", completion);
        }
    } catch (error) {
        console.error("發生錯誤：", error);
        if (error.response) {
            console.error("API 回應：", error.response.data);
        }
    }
}

console.log("程式開始執行...");
main().catch(error => {
    console.error("主程式錯誤：", error);
}); 