import express from 'express';
import cors from 'cors';
import OpenAI from 'openai';
import fs from 'fs';
import dotenv from 'dotenv';
import cron from 'node-cron';
import path from 'path';
import { fileURLToPath } from 'url';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Middleware
app.use(cors());
app.use(express.json());

// 設置靜態文件目錄（前端文件）
app.use(express.static(path.join(__dirname, '../frontend')));

// 檢查必要的環境變數
if (!process.env.OPENAI_API_KEY) {
    console.error('錯誤：未設置 OPENAI_API_KEY 環境變數');
    process.exit(1);
}

// OpenAI 配置
const openai = new OpenAI({
    apiKey: process.env.OPENAI_API_KEY
});

// 儲存最新的分析結果
let latestAnalysis = {
    timestamp: null,
    results: null
};

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

  return issues.length > 0 ? {
    line_number: lineNumber,
    line_content: line,
    issues: issues
  } : null;
}

// 分析日誌檔案
async function analyzeLogs() {
    try {
        console.log("開始分析日誌...");
        
        // 讀取日誌檔案
        const logContent = fs.readFileSync('attack_logs_apache_style.txt', 'utf8');
        
        if (!logContent.trim()) {
            throw new Error("日誌檔案內容為空");
        }

        const completion = await openai.chat.completions.create({
            model: "gpt-3.5-turbo",
            messages: [
                {
                    role: "user",
                    content: `請直接回傳 JSON 格式的分析結果，不要加入任何其他說明或格式：

{
  "is_attack": true/false,                 // 是否為攻擊行為
  "need_test_command": true/false,        // 是否需要進一步測試命令確認
  "shell_script": "測試命令或空字串",     // 若 need_test_command 為 true，必須提供測試命令
  "general_response": "攻擊說明"          // 對此次攻擊的綜合描述
}

分析以下 log：
${logContent}`
                }
            ]
        });

        if (!completion.choices?.[0]?.message?.content) {
            throw new Error("API 回傳的資料格式不正確");
        }

        const jsonMatch = completion.choices[0].message.content.match(/\{[\s\S]*\}/);
        if (!jsonMatch) {
            throw new Error("無法從 API 回應中提取 JSON 資料");
        }

        const analysisResult = JSON.parse(jsonMatch[0]);
        
        // 更新最新分析结果
        latestAnalysis = {
            timestamp: new Date(),
            results: analysisResult
        };

        return analysisResult;
    } catch (error) {
        console.error("分析日誌時發生錯誤：", error);
        throw error;
    }
}

// API 端點
app.get('/api/latest-analysis', (req, res) => {
    if (!latestAnalysis.results) {
        res.json({
            timestamp: new Date(),
            results: null
        });
        return;
    }
    res.json(latestAnalysis);
});

// 手動觸發分析
app.post('/api/trigger-analysis', async (req, res) => {
    try {
        const results = await analyzeLogs();
        if (!results) {
            throw new Error("分析結果為空");
        }
        const response = {
            timestamp: new Date(),
            results: {
                is_attack: results.is_attack || false,
                need_test_command: results.need_test_command || false,
                shell_script: results.shell_script || "",
                general_response: results.general_response || "無分析結果"
            }
        };
        latestAnalysis = response;
        res.json(response);
    } catch (error) {
        console.error("觸發分析時發生錯誤：", error);
        res.status(500).json({ 
            error: true,
            message: error.message || "分析失敗"
        });
    }
});

// 定期執行分析任務
cron.schedule('*/5 * * * *', async () => {
    console.log('執行定期分析...');
    try {
        await analyzeLogs();
    } catch (error) {
        console.error("定期分析任務失敗：", error);
    }
});

// 處理所有其他路由，返回前端的 index.html
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, '../frontend/index.html'));
});

app.listen(PORT, () => {
    console.log(`伺服器運行在連接埠 ${PORT}`);
}); 