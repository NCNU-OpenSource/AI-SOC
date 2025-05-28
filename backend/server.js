import express from 'express';
import cors from 'cors';
import OpenAI from 'openai';
import fs from 'fs';
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';
import axios from 'axios';
import mysql from 'mysql2/promise';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// MySQL 連線設定
const pool = mysql.createPool({
    host: '198.19.249.33',
    user: 'aiioc',
    password: 'aiioc',
    database: 'aiioc',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// 初始化資料庫
async function initializeDatabase() {
    try {
        const connection = await pool.getConnection();
        await connection.query(`
            CREATE TABLE IF NOT EXISTS analysis_results (
                id INT AUTO_INCREMENT PRIMARY KEY,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                is_attack BOOLEAN,
                need_test_command BOOLEAN,
                shell_script TEXT,
                general_response TEXT,
                raw_logs TEXT
            )
        `);
        connection.release();
        console.log('資料庫初始化完成');
    } catch (error) {
        console.error('資料庫初始化失敗:', error);
    }
}

// 儲存分析結果到資料庫
async function saveAnalysisResult(result, rawLogs) {
    try {
        const [rows] = await pool.execute(
            'INSERT INTO analysis_results (is_attack, need_test_command, shell_script, general_response, raw_logs) VALUES (?, ?, ?, ?, ?)',
            [
                result.is_attack,
                result.need_test_command,
                result.shell_script || '',
                result.general_response,
                rawLogs
            ]
        );
        console.log('分析結果已儲存到資料庫');
        return rows.insertId;
    } catch (error) {
        console.error('儲存分析結果失敗:', error);
        throw error;
    }
}

// 獲取歷史分析結果
async function getAnalysisHistory(limit = 10) {
    try {
        // Ensure limit is a number and convert to integer
        const numericLimit = parseInt(limit, 10);
        if (isNaN(numericLimit) || numericLimit < 1) {
            throw new Error('Invalid limit value');
        }
        
        const [rows] = await pool.execute(
            'SELECT * FROM analysis_results ORDER BY timestamp DESC LIMIT 10',
            [numericLimit]
        );
        return rows;
    } catch (error) {
        console.error('獲取歷史記錄失敗:', error);
        throw error;
    }
}

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
    baseURL: "https://openrouter.ai/api/v1",
		apiKey: "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"
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
        
        // 從 Prometheus 獲取數據
        const prometheusUrl = 'http://163.22.17.116:9091/api/v1/query';
        const now = Math.floor(Date.now() / 1000);
        const response = await axios.get(prometheusUrl, {
            params: {
                query: `nginx_nginx_requests_total[20s]`,
                time: now
            }
        });

        if (!response.data?.data?.result) {
            throw new Error("無法從 Prometheus 獲取數據");
        }

        // 收集所有請求
        const requests = response.data.data.result.flatMap(series => {
            const { method, endpoint, status_code, ip } = series.metric;
            return series.values.map(([timestamp, value]) => {
                const formattedTime = new Date(timestamp * 1000).toLocaleString();
                return {
                    logEntry: `${ip} - - [${formattedTime}] "${method} ${endpoint} HTTP/1.1" ${status_code} - "-" "-" "-" "-"`,
                    timestamp: formattedTime,
                    metadata: { method, endpoint, status_code, ip }
                };
            });
        });

        if (requests.length === 0) {
            console.log("此時間範圍內沒有新的請求");
            return null;
        }

        // 分析每個請求
        const analysisResults = [];
        for (const request of requests) {
            try {
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
                        分析以下單一請求：
                        ${request.logEntry}`
                    }]
                });

                if (!completion.choices?.[0]?.message?.content) {
                    throw new Error("API 回傳的資料格式不正確");
                }

                const content = completion.choices[0].message.content;
                const jsonMatch = content.match(/(\[|\{)[\s\S]*(\]|\})/);
                if (jsonMatch) {
                    const jsonStr = jsonMatch[0];
                    const analysisResult = JSON.parse(jsonStr);
                    
                    // 加入請求的元數據
                    analysisResult.timestamp = request.timestamp;
                    analysisResult.request_metadata = request.metadata;
                    
                    // 儲存分析結果到資料庫
                    await saveAnalysisResult(analysisResult, request.logEntry);
                    
                    analysisResults.push(analysisResult);
                }
            } catch (error) {
                console.error(`分析請求失敗: ${request.logEntry}`, error);
                // 繼續處理下一個請求
                continue;
            }
        }

        // 如果有任何成功的分析結果，返回彙總結果
        if (analysisResults.length > 0) {
            const summary = {
                is_attack: analysisResults.some(result => result.is_attack),
                need_test_command: analysisResults.some(result => result.need_test_command),
                shell_script: analysisResults
                    .filter(result => result.shell_script)
                    .map(result => result.shell_script)
                    .join('\n'),
                general_response: analysisResults
                    .filter(result => result.is_attack)
                    .map(result => {
                        const metadata = result.request_metadata;
                        return `${result.timestamp} - ${metadata.ip} 訪問 ${metadata.method} ${metadata.endpoint}: ${result.general_response}`;
                    })
                    .join('\n') || "無攻擊行為"
            };
            return summary;
        }

        return null;
    } catch (error) {
        console.error("分析日誌時發生錯誤：", error);
        throw error;
    }
}

// API 端點
app.get('/api/latest-analysis', async (req, res) => {
    try {
        const history = await getAnalysisHistory(1);
        if (history.length === 0) {
            res.json({
                timestamp: new Date(),
                results: null
            });
            return;
        }
        const latest = history[0];
        res.json({
            timestamp: latest.timestamp,
            results: {
                is_attack: latest.is_attack,
                need_test_command: latest.need_test_command,
                shell_script: latest.shell_script,
                general_response: latest.general_response
            }
        });
    } catch (error) {
        res.status(500).json({
            error: true,
            message: error.message
        });
    }
});

// 獲取歷史分析結果的端點
app.get('/api/analysis-history', async (req, res) => {
    try {
        const limit = parseInt(req.query.limit) || 10;
        const history = await getAnalysisHistory(limit);
        res.json(history);
    } catch (error) {
        res.status(500).json({
            error: true,
            message: error.message
        });
    }
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
        res.json(response);
    } catch (error) {
        console.error("觸發分析時發生錯誤：", error);
        res.status(500).json({ 
            error: true,
            message: error.message || "分析失敗"
        });
    }
});

// 定期執行分析任務 (每10秒執行一次)
setInterval(async () => {
    console.log('執行定期分析...');
    try {
        await analyzeLogs();
    } catch (error) {
        console.error("定期分析任務失敗：", error);
    }
}, 10000);

// 初始化資料庫
initializeDatabase().catch(console.error);

// 處理所有其他路由，返回前端的 index.html
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, '../frontend/index.html'));
});

app.listen(PORT, () => {
    console.log(`伺服器運行在連接埠 ${PORT}`);
}); 
