# AI-SOC (AI 安全運營中心)
AI-SOC 是一個結合 LLM 技術的安全運營中心系統，提供即時 Log 分析、威脅評估及自動化回應機制。
本專案整合多項開源工具，實現高效能的安全監控與分析。

#### HackMD 筆記：https://hackmd.io/DCzKj59jTO-wrVg7Nu6fEg
## 系統畫面
![image](https://github.com/user-attachments/assets/39022ca7-2b76-4e1c-bcf2-2a8644c9eef2)
![image](https://github.com/user-attachments/assets/f10537d8-c944-4e85-93de-8a56f6d80933)
![image](https://github.com/user-attachments/assets/d79c0a8b-0e1b-4da1-abf2-8455257e30ca)


## 系統功能

- **即時 Log 收集與分析**：自動化收集與處理系統日誌
- **LLM 輔助威脅評估**：運用 LLM 模型進行威脅評估
- **自動化響應機制**：針對檢測到的安全威脅進行自動處理
- **可視化監控介面**：系統監控與資料視覺化儀表板

## 流程圖
![image](https://github.com/user-attachments/assets/1ebb295f-4bae-4631-b4a4-798b0bd18211)


### Step
1. 用三個工具（SQLMaps,dalfox,gobuster）送攻擊 request 去打特定主機A，獲得 web access log。
    -  查看攻擊的 log：`sudo vim /var/log/nginx/access.log`
        >  我們設定好的 Nginx 除了 GET 以外，還可以在 log 看到 POST 的 request body
2. 用 Vector 蒐集 raw log，再 Parse 這些 log
    > 用 [Regex](https://tw.alphacamp.co/blog/regex)（正規表達式）把字串中的欄位切分出來，ex:IP、status code

5. 用寫好的靜態分析規則（白名單＋黑名單）判斷 log 是否為攻擊，若為攻擊則把該 parse 過的 log 標記起來，放到 Prometheus。
7. 也會把一般的未標記的 raw log 放到 Prometheus，讓後端去拿資料並判斷行為模式
    > Prometheus 可用 Promql 查詢 metrics
9. **把靜態分析後判定為攻擊的log** 和 **後端分析 raw log 後判定行為模式異常的 log** ，都**給 LLM 判斷是否為為真正的攻擊行為（想避免 False positive）**。
    > False positive（假陽性）可以想像成實際未患病，但模型預測為患病。
    > 在某些應用領域也被稱為誤報（False Alarm）。
    > False positive 情況
![image](https://hackmd.io/_uploads/r1ENt3NGxx.png)


12. 於 Dashboard 顯示 LLM 的判斷結果
## 系統架構

本系統整合以下工具：

### Vector
- 高效能的資料收集與處理工具
- 處理來自多個來源的 log 和指標數據
- 主要功能：
  - 多來源輸入支援（檔案、網路、Syslog）
  - 即時資料處理
  - 資料轉換與過濾

### Prometheus
- 開源監控和告警系統
- 時間序列資料庫，用於指標存儲
- 核心功能：
  - 主動式指標收集（Pull-based）
  - 靈活的查詢語言（PromQL）
  - 自動服務發現
  - 告警管理
  - Grafana 整合視覺化

### 紅隊工具整合
系統整合常用安全測試工具：

1. **SQLMap**
   - SQL injection 漏洞測試工具
   - 安裝方式：
   ```bash
   git clone https://github.com/sqlmapproject/sqlmap.git
   cd sqlmap
   python3 sqlmap.py -u "http://目標網址" --data="username=admin&password=secret" -p "username,password" --dbs
   ```

2. **Dalfox**
   - XSS 參數分析和掃描工具
   - MacOS 安裝方式：
   ```bash
   brew install dalfox
   dalfox url http://目標網址
   ```

3. **Gobuster**
   - 網站目錄爆破工具
   - 使用方式：
   ```bash
   gobuster dir -u "http://目標網址" -w /字典檔路徑 -b 301,401,403,404,500 -t 20
   ```

## 系統流程

1. **攻擊模擬**
   - 使用紅隊工具生成測試流量
   - 收集目標系統的網頁存取 log
   - Nginx 配置為同時記錄 GET 和 POST 請求內容

2. **日誌處理**
   - Vector 收集原始 log
   - 使用正規表達式解析相關欄位（IP、狀態碼等）
   - 透過靜態分析規則（白名單 + 黑名單）標記潛在攻擊

3. **分析與存儲**
   - 將標記的潛在攻擊和原始日誌存入 Prometheus
   - 後端進行行為模式分析
   - 使用 LLM 驗證潛在威脅




### 後端技術（backend/server.js）
1. **Node.js & Express.js**
   ```javascript
   import express from 'express';
   import cors from 'cors';
   const app = express();
   ```


2. **資料庫操作**
   ```javascript
   const pool = mysql.createPool({
       host: '198.19.249.55',
       user: 'aiioc',
       password: 'aiioc',
       database: 'aiioc',
       waitForConnections: true,
       connectionLimit: 10,
       queueLimit: 0
   });
   ```


3. **LLM 整合**
   ```javascript
   const openai = new OpenAI({
       baseURL: "https://openrouter.ai/api/v1",
       apiKey: "YOUR_API_KEY"
   });
   ```

3. 行為模式分析：request 限流功能 
    ```javascript
    async function checkRequestFrequency(ip) {
        const query = `sum(sum_over_time(nginx_nginx_requests_total_no_filter{ip="${ip}"}[40s]))`;
        const response = await fetchWithTimeout(`${PROMETHEUS_URL}/api/v1/query?query=${encodeURIComponent(query)}`);
        const data = await response.json();
        // 分析請求頻率
    }
    ```

### 監控技術
1. **Vector.yml 配置**
   ```yaml
   sources:
     nginx_logs:
       type: "file"
       include: ["/var/log/nginx/access.log"]
   
   transforms:
     parse_nginx:
       type: "remap"
       inputs: ["nginx_logs"]
   
   sinks:
     prometheus:
       type: "prometheus"
       inputs: ["parse_nginx"]
   ```
   - log 作靜態分析
   - 數據轉換（parse）
   - 指標輸出
   - sink部分添加了 prometheus_exporter sink
    配置了兩種指標：
    http_response_time_seconds：HTTP 響應時間的分布
    http_requests_total：HTTP 請求總數，按方法、狀態碼和端點分類

2. **Prometheus.yml 查詢**
   ```javascript
   const query = `sum(sum_over_time(nginx_nginx_requests_total_no_filter{ip="${ip}"}[40s]))`;
   ```
   - PromQL Query 查詢
   - 可依設定好的時間定期抓取 Vector 的指標。
    ```yaml=
    global:
      scrape_interval: 15s
      evaluation_interval: 15s

    scrape_configs:
      - job_name: 'vector'
        static_configs:
          - targets: ['vector:9090']
    ```    
### 儲存持久性資料技術
#### docker-compose.yml

1. Vector 添加 9090 對映
- Vector 是用來收集和轉換日誌（log）的工具。
- 我們在 Vector 容器裡開放 9090 這個 port，因為這是 Vector 的 Prometheus exporter（將內部指標數據輸出給 Prometheus 抓取）所使用的 port。這樣 Prometheus 就能從這個 port 上來收集 Vector 提供的指標數據。

2. Prometheus 服務（用 9091 port）
- Prometheus 是一個監控系統和時序數據庫，會定期從 Vector 收集指標數據。

3. 設置 volumes 持久化 Prometheus 數據
- Prometheus 收集到的數據需要長期儲存，不能只存在記憶體中。
- 我們透過 docker-compose 中的 volumes 把 Prometheus 的數據儲存在主機上，這樣就算容器重啟，數據也不會消失。
    ```yaml=
    version: "3.8"
    services:
      vector:
        image: timberio/vector:0.46.1-debian
        container_name: vector
        restart: always
        volumes:
          - ./vector.yaml:/etc/vector/vector.yaml:ro
          - /var/log/nginx:/var/log/nginx:ro
        ports:
          - "8686:8686"
          - "9090:9090"
        command: ["vector", "--config", "/etc/vector/vector.yaml"]

      prometheus:
        image: prom/prometheus:latest
        container_name: prometheus
        restart: always
        volumes:
          - ./prometheus.yml:/etc/prometheus/prometheus.yml
          - prometheus_data:/prometheus
        ports:
          - "9091:9090"
        command:
          - '--config.file=/etc/prometheus/prometheus.yml'
          - '--storage.tsdb.path=/prometheus'
          - '--web.console.libraries=/usr/share/prometheus/console_libraries'
          - '--web.console.templates=/usr/share/prometheus/consoles'

    volumes:
      prometheus_data: {}
    ```


## 詳細流程

### 1. Log 收集流程
1. Nginx 產生 log
2. Vector 監控 log 文件變化
3. 解析 log 內容為結構化數據
4. 轉換為 Prometheus 指標
5. 推送到 Prometheus service

### 2. 分析流程
1. 定期檢查請求頻率
   ```javascript
   setInterval(async () => {
       console.log('Checking request frequencies...');
       const activeIPs = await getActiveIPs();
       // 檢查每個 IP 的請求頻率
   }, 20000);
   ```

2. AI 分析可疑行為
   ```javascript
   const analysis = await sendToOpenAI(requestData);
   ```

3. 結果儲存＆通知
   ```javascript
   await saveAnalysisResult(analysisResult, request.logEntry);
   ```


### 部署
#### 要求
- Node.js >= 14
- MySQL >= 8.0
- Vector 配置
- Prometheus 設置
- 告警規則定義

#### 配置步驟
1. 把專案 clone 下來
2. 安裝需要的套件：`npm intstall`
4. 初始化資料庫（建 DB 、建使用者帳號並給權限）
    > 記得 **sudo vi /etc/mysql/mysql.conf.d/mysqld.cnf**， 把bind-address 改成0.0.0.0，資料庫才能給外面連

6. 啟動服務`npm start`
![image](https://hackmd.io/_uploads/ByAxcIrfge.png)


