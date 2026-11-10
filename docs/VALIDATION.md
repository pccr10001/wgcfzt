# 驗證紀錄

實測日期：2026-11-10。測試識別碼、組織名稱與憑證不放入版本庫。

## 已完成

| 項目 | 證據 |
| --- | --- |
| Windows 原生 callback dispatch | 以真正 `com.cloudflare.warp://` dispatch 將合成 JWT 傳入 executable，再透過 localhost 回到測試程序 |
| 協定還原 | 測試比對接管前後 HKCU registry 樹，以及 OS 有效 handler command |
| 逾時／還原失敗 | 自動測試證明逾時執行還原，還原失敗不回傳 JWT 給註冊流程 |
| 原有註冊匯入 | 實際匯入既有 WG 金鑰與註冊回應，成功線上 GET 狀態及 VNET |
| 新 WireGuard 註冊 | 透過 Go CLI 建立一次性測試裝置，回應公鑰與本機相符 |
| 真實登入 JWT callback | 從授權的瀏覽器 session 取得成功頁結果，透過暫時 native handler 送回 Go CLI 並完成註冊 |
| WireGuard 握手 | 以不建立 OS 網卡的 userspace netstack 對回傳 peer 完成 authenticated handshake |
| VNET | Go CLI 以名稱切換非預設 VNET，GET 讀回正確 UUID，之後可切回預設 |
| 裝置改名 | PATCH 改名後，GET 註冊回應確認新名稱 |
| 解除註冊 | Go CLI 對一次性測試裝置執行 DELETE 成功，清除其本機金鑰／Token／預設 profile |
| MASQUE 註冊與匯出 | 新建獨立 P-256 MASQUE 註冊，匯出 usque JSON |
| 原版 usque 可直接使用 | 未修改的 usque 載入 JSON，成功連上 MASQUE；經 localhost HTTP proxy 的公開 trace 請求回傳 HTTP 200、`warp=on`、`gateway=on` |
| usque 與非預設 VNET | 使用 Go CLI 將 MASQUE 註冊切換到非預設 VNET並讀回，重開 usque 後公開 trace 同樣成功；測試後還原預設 VNET |

測試過程不啟動官方 WARP app 的註冊登入，也不啟用 OS 全通路由。

## 驗證範圍

瀏覽器可能要求使用者按下成功頁 callback 按鈕、確認開啟 wgcfzt，或因瀏覽器 handler 設定而需要手貼。原生 dispatch 成功不代表每種瀏覽器政策都會允許無提示跳轉。曾觀察到瀏覽器未送出 callback 而正常逾時，工具完成協定還原。

WireGuard／MASQUE 握手與公開 HTTP 請求不能證明某個 VNET 私網服務可達。尚待使用者指定私網 IP／主機／port，驗證私網路由、組織 DNS、Gateway 政策與重疊 IP 的 VNET 隔離。

尚未驗證保留同一 device ID 的 Registration Token refresh／rotation、既有隧道即時套用 VNET 的時間、所有組織的裝置數量限制，以及 Windows 以外的自動協定接管。非 Windows 平台目前走手貼。
