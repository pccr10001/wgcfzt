# wgcfzt

以 Go 實作的 Cloudflare Zero Trust 裝置註冊工具。透過組織 SSO 建立獨立註冊、選擇 VNET，產生標準 WireGuard profile 或可直接由 usque 載入的 MASQUE JSON。

套件名稱：`github.com/pccr10001/wgcfzt`。

程式管理註冊與設定檔，不會啟動官方 WARP app、安裝 TUN 網卡或修改作業系統路由。連線由 WireGuard client 或 usque 執行。

## 安裝與建置

需要 Go 1.26 或更新版本。

```sh
go install github.com/pccr10001/wgcfzt@latest
```

從原始碼建置：

```sh
git clone https://github.com/pccr10001/wgcfzt.git
cd wgcfzt
go build -o wgcfzt .
```

Windows 可使用 `go build -o wgcfzt.exe .`。後續範例假設 `wgcfzt` 已在 PATH；目前目錄的 Windows 執行檔需寫成 `.\wgcfzt.exe`。

## 第一次使用：WireGuard

以組織 slug `example-team`、VNET `labs` 為例：

```sh
wgcfzt reg --team example-team --profile labs-wg --vnet labs --accept-tos
```

操作順序：

1. 檢查 profile 是否已存在，避免覆寫既有註冊。
2. Windows 嘗試暫時接管 `com.cloudflare.warp://`，保存原有協定資料。
3. 預設使用 Firefox 開啟 `https://example-team.cloudflareaccess.com/warp`。
4. 完成組織 SSO。在成功頁按下開啟 callback 的按鈕；若瀏覽器要求選擇應用程式，選擇暫時的 **wgcfzt**。
5. callback 透過帶隨機 nonce 的 localhost 通道傳回登入結果。
6. **還原原有協定後**，才將公鑰與登入 JWT 送往註冊 API。若還原失敗，停止註冊並要求復原。
7. 保存 Registration Token、裝置 ID、金鑰及 API 回應，選擇並讀回確認 VNET。
8. 產生該 profile 的 `wg-profile.conf`，輸出檔案位置。

私鑰在本機產生；登入 JWT 與 Registration Token 不會列印到終端。程式不保存登入 JWT 供長期使用。

`--accept-tos` 表示同意 https://www.cloudflare.com/application/terms/ 。`--team` 只填 slug，不要填完整 URL。

## 登入方式與協定復原

### Windows 自動 callback

預設使用 Firefox，可改為 `--browser default` 使用系統預設瀏覽器。

自動接管只修改目前使用者的 `HKCU\Software\Classes\com.cloudflare.warp`，不修改 HKLM。如果 Windows 有受保護的 UserChoice，或 Firefox 明確指定另一個應用程式，程式會改用手貼流程，不修改 UserChoice 的驗證資料。

正常完成、逾時或 Ctrl+C 都會執行協定還原。若視窗被強制關閉、程序被終止或系統斷電，使用相同設定目錄復原：

```sh
wgcfzt recover
wgcfzt --config-dir /path/to/custom-config recover
```

備份會保留到還原完成。若另一個程式已接管協定，`recover` 會停止，不直接覆寫外部變更。啟動下一次登入前，需先處理尚未復原的備份。

Linux、macOS 目前使用手貼流程；Windows 無法安全接管時也使用相同流程。

### 手動貼上

```sh
wgcfzt reg --team example-team --profile labs-wg --vnet labs --manual --accept-tos
```

程式接受整段 JWT 或完整的 `com.cloudflare.warp://example-team.cloudflareaccess.com/auth?token=...` URL。

Firefox 可在已有組織登入狀態時開啟下列「檢視原始碼」URL，從成功頁原始碼複製 callback，避免執行頁面的原生應用程式跳轉：

```text
view-source:https://example-team.cloudflareaccess.com/warp
```

手貼模式不會自行接管協定，也不會自行開啟一般 `/warp` 頁；選用 Firefox 時會嘗試開啟上述 source view。若 SSO 已過期，先完成組織登入，再重新讀取成功頁原始碼。不要批准開啟原本 WARP app。

也可從檔案或標準輸入取得 Token：

```sh
wgcfzt reg --team example-team --profile labs-wg --jwt-file /secure/team-jwt.txt --accept-tos
cat /secure/team-jwt.txt | wgcfzt reg --team example-team --profile labs-wg --jwt-file - --accept-tos
```

Windows PowerShell 標準輸入範例：

```powershell
Get-Content -Raw C:\secure\team-jwt.txt | wgcfzt reg --team example-team --profile labs-wg --jwt-file - --accept-tos
```

JWT 檢查包含 issuer、有效期限與 callback 組織。這不是本機驗證 JWT 簽章；最終認證由 Cloudflare 註冊 API 執行。預設登入逾時 5 分鐘，可用 `--timeout 10m` 調整。

## VNET

```sh
wgcfzt --profile labs-wg vnet
wgcfzt --profile labs-wg vnet list
wgcfzt --profile labs-wg vnet labs
wgcfzt --profile labs-wg vnet use <VNET_UUID>
```

星號表示目前選擇。切換時以名稱或 UUID 找到唯一 VNET，送出 PATCH，再 GET 讀回確認。成功後需自行重新連接 WireGuard 或重啟 usque。

VNET 是**伺服器端的裝置註冊狀態**。私鑰不會因切換而改變，WireGuard／usque 設定檔也沒有可獨立指定 VNET 的欄位。WG 設定檔中的 VNET 註解只記錄匯出當時的選擇；切換不需要更換設定檔金鑰。

### 同時使用多個 VNET

每個 VNET 建立一筆獨立註冊：

```sh
wgcfzt reg --team example-team --profile labs-wg --vnet labs --accept-tos
wgcfzt reg --team example-team --profile dev-wg --vnet dev --accept-tos
```

各 profile 有不同的 device ID、Registration Token 與金鑰。複製同一份設定檔仍共用同一筆註冊，不能因此得到兩個獨立 VNET 選擇。數量與可選 VNET 受組織政策限制。

同一台主機並行連線時，仍須分離本機路由與 DNS。重疊目的 IP 可以放在不同 network namespace／容器，或透過不同 usque proxy port 明確選擇隧道。wgcfzt 不會自動配置這些作業系統網路隔離。

## 產生設定檔

```sh
wgcfzt --profile labs-wg generate
wgcfzt --profile labs-wg generate -o ./labs.conf --dns 1.1.1.1 --keepalive 25
wgcfzt --profile labs-wg generate --allowed-ips 10.20.0.0/16,10.30.0.0/16
wgcfzt --profile labs-wg generate --offline
```

預設會刷新遠端註冊與 VNET，確認遠端公鑰、協定仍和本機私鑰相符。`--offline` 只使用上次快取，無法證明註冊仍有效。

WireGuard 預設 MTU 為 1280、keepalive 為 25 秒、AllowedIPs 為 `0.0.0.0/0, ::/0`。`--keepalive 0` 關閉 keepalive。DNS 預設省略，由匯入設定的 client 決定；需要私有 DNS 時請提供適合該組織的 resolver。

這是標準 WG profile，不會自動把官方 WARP policy 的排除 IP／網域轉成系統路由。網域型排除還涉及 DNS 與動態 IP，不能直接等同靜態 AllowedIPs。

## usque / MASQUE

建立獨立的 MASQUE profile：

```sh
wgcfzt reg --team example-team --profile labs-masque --protocol masque --vnet labs --accept-tos
wgcfzt --profile labs-masque generate --format usque
```

輸出為 `profiles/labs-masque/usque.json`。此檔含 usque 所需的 P-256 SEC1 私鑰、peer 公鑰、endpoint、位址、裝置 ID 與 `access_token`。

Windows 使用原版 usque：

```powershell
usque -c "$env:LOCALAPPDATA\wgcfzt\profiles\labs-masque\usque.json" http-proxy -b 127.0.0.1 -p 8000
```

Linux／macOS：

```sh
usque -c ~/.config/wgcfzt/profiles/labs-masque/usque.json http-proxy -b 127.0.0.1 -p 8000
```

若有自訂 XDG_CONFIG_HOME／--config-dir，請使用實際輸出路徑。

usque 目前沒有內建 VNET 參數。先以 `wgcfzt --profile labs-masque vnet <VNET>` 更新該註冊，再重啟使用該 JSON 的 usque。若 usque 自行重新註冊得到另一個裝置 ID，它不會沿用舊註冊的 VNET 選擇。

WireGuard 使用 Curve25519，MASQUE 使用 P-256。兩種私鑰不能互換；工具不會把可用的 WG 註冊直接改成 MASQUE，請建立另一個 profile。

## 裝置管理與狀態

```sh
wgcfzt devices list
wgcfzt devices show labs-wg
wgcfzt --profile labs-wg devices rename my-laptop
wgcfzt --profile labs-wg status
wgcfzt --profile labs-wg status --offline
```

`devices list` 列出此設定目錄保存的註冊，並非整個組織的所有裝置。`show`、`rename` 與線上 `status` 操作本機管理的裝置。

線上 `status` 驗證 Registration API、公鑰／協定與 VNET 狀態，**不代表已建立隧道或能存取私網目的地**。

解除註冊：

```sh
wgcfzt --profile labs-wg dereg
wgcfzt --profile labs-wg dereg --yes
```

DELETE 成功後清除該 profile 的 Token／私鑰與預設輸出設定，保留無憑證的 `deregistered` 紀錄。程式不知道另外複製或以 `-o` 匯出到其他位置的設定檔，不會刪除它們。這不是瀏覽器登出，也不是單純離開某個 VNET。

## 設定位置與儲存

| 系統 | 預設路徑 |
| --- | --- |
| Windows | `%LOCALAPPDATA%\wgcfzt`，即 AppData\Local |
| Linux／macOS | `~/.config/wgcfzt` |
| 設定 XDG_CONFIG_HOME 的 Linux／macOS | `$XDG_CONFIG_HOME/wgcfzt` |
| 所有系統 | 可用 `--config-dir <path>` 覆寫 |

```text
wgcfzt/
  profiles/
    labs-wg/
      account.json
      wg-profile.conf
    labs-masque/
      account.json
      usque.json
  protocol-backup.json       # 只有接管尚未還原時存在
  callback-session.json      # 登入期間的 localhost 位址與 nonce
```

`account.json` 含 Registration Token、隧道私鑰與快取 API 回應。Unix 檔案使用 0600、受管理目錄 0700；Windows 設定目錄與憑證檔採目前使用者的受保護 ACL。這是檔案存取控制，不是磁碟加密。

寫入使用同目錄暫存檔與 rename。檔案鎖會在程序結束時由 OS 釋放，避免同時修改同一個 profile。登入另外鎖定 callback；Windows 也使用每位使用者共用的 named mutex，避免不同 config-dir 同時接管協定。

## 中斷與匯入

```sh
wgcfzt reg --team example-team --profile labs-masque --protocol masque --resume --accept-tos
```

金鑰會先保存，再發出註冊請求；收到註冊資料後立即保存，再進行 MASQUE enrollment 與 VNET 操作。`--resume` 可以續作中斷的 enrollment 或 VNET 設定。

如果 POST 已在伺服器完成，但網路在回應傳回前中斷，本機可能不知道新 device ID。請先確認伺服器端裝置再明確重試；程式不會自動重送建立註冊請求。

也可匯入先前保存的 WireGuard 註冊回應與私鑰：

```sh
wgcfzt --profile imported import --team example-team --registration registration.json --key-file private-key.txt
wgcfzt --profile imported status
wgcfzt --profile imported generate
```

私鑰檔可為純 Base64，或含 `private_key` 欄位的 JSON。匯入會核對公鑰，不會聯絡 API；接著用線上 `status` 驗證現況。既有 profile 不會被覆寫。

## 路由、API 與驗證範圍

- [完整 API、Token 與路由說明](docs/API.md)
- [設計、復原與測試說明](docs/DEVELOPMENT.md)
- [已完成的實測與尚未涵蓋的項目](docs/VALIDATION.md)

參考：[wgcf](https://github.com/ViRb3/wgcf)、[usque](https://github.com/Diniboy1123/usque)、[Cloudflare Virtual Networks](https://developers.cloudflare.com/cloudflare-one/networks/virtual-networks/)。
