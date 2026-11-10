# 開發與復原設計

## 程式結構

| 路徑 | 責任 |
| --- | --- |
| `main.go` | Ctrl+C context 與程序退出碼 |
| `internal/cli` | Cobra 指令、輸入與不含憑證的輸出 |
| `internal/auth` | JWT/callback 解析、loopback IPC、Windows 接管與復原 |
| `internal/api` | WARP API HTTP、JSON 型別、錯誤遮蔽 |
| `internal/store` | profile JSON、原子寫入、檔案權限與鎖 |
| `internal/app` | 註冊生命週期、VNET、匯出與解除註冊 |

模組為 `github.com/pccr10001/wgcfzt`。使用 Go 標準密碼學套件產生金鑰，Cobra 處理 CLI，`x/sys` 處理平台權限、registry 與鎖。

## Callback 的先後順序

`auth.Login` 必須先執行還原再返回 JWT。註冊 HTTP 請求在呼叫者取得 JWT 後才會發出；還原失敗時 JWT 不會交給註冊流程。

自動登入保存的狀態只有 localhost callback 位址、組織 slug、隨機 nonce 及 registry 備份，不把 JWT 存入 callback session。callback helper 的 HTTP transport 不使用代理、不跟隨 redirect，只允許 `http://127.0.0.1:<port>/callback`。

Windows 的 command association 指向目前 executable 的隱藏 `callback` 子命令。它接收 native URL，驗證組織與 Token 格式後，使用 nonce 將結果送回父程序。localhost server 驗證 nonce、方法與輸入長度。

瀏覽器與 OS 會短暫處理 callback URL，Token 可能出現在 callback helper 的程序參數；程式不將其印入 log。若採檔案輸入，使用 `--jwt-file`，不把 JWT 直接寫進 shell 指令。

## 接管與還原

接管前保存 HKCU 協定樹的原始值型別、raw bytes 與子鍵；HKLM 不變。既有子鍵在同步還原時盡可能保留，避免不必要地重建原有 registry security。

安裝後使用 Windows 有效 association 查詢確認 command；不符合時回滾並切換手貼。Windows UserChoice 與 Firefox 自訂 handler 不被改寫。

還原前核對 association 是否仍屬於本次工具，避免覆寫另一個應用程式的新設定。還原中會保存 checkpoint，使中斷後可以再次執行 `recover`。若 registry 已等於原備份，只需清除備份。

正常成功、逾時與 Ctrl+C 會自動清理。強制終止／斷電無法保證程式執行 defer，因此備份保留在設定目錄，需由使用者執行 `recover`。

## Profile 生命週期

```text
pending
  → registered（已保存 device ID / Token）
  → MASQUE enrollment（只有 masque profile）
  → ready
  → deregistered（清除本機憑證）
```

`pending` 私鑰在 POST 前保存。POST 不自動重試，避免回應遺失時重複建立裝置。`--resume` 是使用者明確選擇的續作；收到過 device ID 的 profile 不會再走新註冊 POST。

VNET API 失敗不會刪除已成功的註冊。profile 保留可供後續 `vnet` 或 `reg --resume` 使用。匯出前核對註冊公鑰與本機私鑰。

`dereg` 只有 API 成功後才清除本機憑證。遠端已刪除但本機存檔失敗時會明確報錯，不宣稱本機清理完成。

## 自動測試

```sh
go test ./...
go test -race ./...
go vet ./...
```

測試涵蓋 mock HTTP 註冊／MASQUE enrollment／VNET 讀回／解除註冊、WG 與 usque key encoding、CLI 匯入與憑證遮蔽、callback 收到 Token 後先還原、逾時及還原失敗、手貼 fallback、profile traversal、原子取代與跨 writer 鎖。

一般 Windows 測試只操作獨立測試 registry key，不改真實 WARP association。實際 association 測試必須明確 opt in：

```powershell
go build -o dist\wgcfzt.exe .
$env:WGCFZT_PROTOCOL_TEST_EXE = (Resolve-Path .\dist\wgcfzt.exe).Path
$env:WGCFZT_PROTOCOL_TEST_DIR = "$env:LOCALAPPDATA\wgcfzt-callback-test"
go test ./internal/auth -run TestWindowsNativeCallbackRoundtrip -v
Remove-Item Env:WGCFZT_PROTOCOL_TEST_EXE
Remove-Item Env:WGCFZT_PROTOCOL_TEST_DIR
```

這個測試以合成 JWT 與 localhost listener 執行真正的 native URL dispatch，不向 Cloudflare 註冊、不啟動官方 app，最後比對協定樹及有效 association 是否完全還原。

若測試在還原步驟失敗，備份會留在 `WGCFZT_PROTOCOL_TEST_DIR`，使用該設定目錄執行 `recover`。不要在尚未復原前刪除這個目錄。

## 跨平台建置

```sh
GOOS=linux GOARCH=amd64 go build -o dist/wgcfzt-linux-amd64 .
GOOS=darwin GOARCH=arm64 go build -o dist/wgcfzt-darwin-arm64 .
GOOS=windows GOARCH=amd64 go build -o dist/wgcfzt.exe .
```

PowerShell 以 `$env:GOOS`／`$env:GOARCH` 設定環境變數，完成後刪除這兩個環境變數即可。

CI 會在 Windows、Linux、macOS 建置與執行一般測試，不會登入真實組織或修改真實 WARP association。
