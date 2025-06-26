# Microsoft Sentinel Workbook – Unauthorized AnyDesk Usage Threat Hunt

This workbook helps identify unauthorized installation and use of AnyDesk as a potential Remote Access Trojan (RAT) or insider threat.

## 🧭 Use Case
- Detect AnyDesk downloads and silent installations
- Monitor outbound traffic from AnyDesk.exe
- Investigate file activity and clipboard use during remote sessions

## 📊 Workbook Features
- Installation events visualization
- Process launch with persistence flags
- Outbound IP connections from AnyDesk
- Suspicious ZIP file creation
- Analyst investigation checklist

## 📥 Import Instructions
1. Open Microsoft Sentinel
2. Go to "Workbooks" > "New"
3. Select "Advanced Editor"
4. Copy contents from `AnyDesk_Workbook.json` into editor
5. Save and pin as needed

## 📁 Repo Contents
| File | Description |
|------|-------------|
| `AnyDesk_Workbook.json` | Complete Sentinel workbook definition |
| `KQL-Queries.md` | All KQL queries used in the workbook |
| `README.md` | Documentation and context |
| `Sample-Alerts.md` | Sample incidents/alerts for lab or demo use |
