## **檔案加解密**

這是一個基於 PyQt6 的檔案加解密工具，使用 `cryptography` 庫實現對稱加密（Fernet）。程式提供圖形化介面，支援手動輸入密碼或使用檔案作為密鑰，適用於 Windows 系統，並遵循個人化主題設定。

### **功能特點**

1. **加密與解密**
   - **方法**：使用 Fernet 對稱加密，生成隨機 salt 和 IV。
   - **檔案處理**：支援任意檔案格式，加密後不自動添加副檔名，儲存路徑由使用者指定。
   - **流程**：選擇密鑰（密碼或檔案），選擇檔案，點擊「開始加密/解密」。

2. **密鑰來源**
   - **手動輸入密碼**：
     - 使用 `QLineEdit` 輸入，設置為密碼模式（顯示為點點）。
     - 即時生效，無需額外確認按鈕。
   - **密鑰檔案**：
     - 支援任意檔案類型（如 TXT、JPG、PDF），大小限制 10MB。
     - 可通過拖曳或檔案對話框選擇。
   - **混合使用**：
     - 密碼與檔案內容串聯生成金鑰，增加安全性。

3. **使用者介面**
   - **視窗大小**：預設 350x450 像素。
   - **佈局**：
     - **密鑰區**：包含檔案選擇標籤、「選擇密鑰檔案」與「清除密鑰檔案」按鈕、密碼輸入框。
     - **加密區**：檔案選擇標籤與「開始加密」按鈕。
     - **解密區**：檔案選擇標籤與「開始解密」按鈕。
     - 分隔線分隔三個區域。
   - **主題**：移除自訂樣式，套用 Windows 個人化設定（淺色/深色模式）。

4. **操作便捷性**
   - **拖曳支援**：可將檔案拖曳至密鑰、加密或解密區域。
   - **清除功能**：新增「清除密鑰檔案」按鈕，重置已選檔案。
   - **狀態更新**：密碼輸入或檔案選擇後，標籤與按鈕狀態即時更新。

5. **限制與錯誤處理**
   - **檔案大小**：密鑰檔案超過 10MB 時提示「密鑰檔案大小超過10MB限制！」。
   - **密鑰要求**：無密碼且無檔案時，加密/解密按鈕禁用並顯示警告。
   - **日誌**：使用 `logging` 記錄操作細節（DEBUG 模式）。

### **使用方法**

- **加密檔案**
  1. 在密碼輸入框輸入密碼（可選，顯示為點點）或拖曳/選擇 ≤10MB 檔案至密鑰區。
  2. 拖曳或選擇要加密的檔案至加密區。
  3. 點擊「開始加密」，選擇儲存路徑。
- **解密檔案**
  1. 使用與加密時相同的密碼和/或密鑰檔案。
  2. 拖曳或選擇要解密的檔案至解密區。
  3. 點擊「開始解密」，選擇儲存路徑。
- **清除密鑰檔案**
  - 點擊「清除密鑰檔案」按鈕，重置已選檔案，保留密碼（如有）。

### **技術細節**

- **加密流程**：
  - 使用 PBKDF2（SHA256，100,000 次迭代）從密碼和/或檔案內容生成 32 位元組金鑰。
  - 附加 16 位元組隨機 salt 和 IV，儲存於加密檔案。
- **依賴庫**：
  - `PyQt6`：圖形化介面。
  - `cryptography`：加密與金鑰生成。
  - `os`：檔案操作。
- **程式結構**：
  - `FileCryptoTool` 類：包含 UI 初始化與所有功能邏輯。
  - 方法如 `generate_key`、`encrypt_file`、`decrypt_file` 等實現核心功能。

### **測試建議**

1. **密碼輸入**：
   - 輸入 "test123"，確認顯示為點點，加密後用相同密碼解密。
2. **密鑰檔案**：
   - 拖曳 <10MB 檔案（如 5MB JPG），加密並解密。
   - 拖曳 >10MB 檔案，確認提示錯誤。
3. **清除功能**：
   - 選擇檔案後點擊「清除密鑰檔案」，確認標籤與按鈕狀態更新。
4. **混合使用**：
   - 輸入密碼並選擇檔案，加密後用相同組合解密。