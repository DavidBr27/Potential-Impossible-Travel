# 🚨 Incident Report: Create Alert Rule (Potential Impossible Travel) 🚨

![image](https://github.com/user-attachments/assets/1619d03b-412c-4b5c-9b7a-5aee6e1f4fb7)


## 📝 **Explanation**  
Corporations often have strict policies prohibiting:  
- 🌍 Logging in from multiple geographic regions outside designated areas.  
- 🔄 Account sharing (a standard security measure).  
- 🛡️ Using non-corporate VPNs.  

This scenario detects unusual activity, such as logins from **multiple geographic regions** within a short time frame.  

Whenever a user logs into Azure or authenticates with their main Azure account, logs are created in the **"SigninLogs"** table and forwarded to the **Log Analytics workspace** used by Microsoft Sentinel (our SIEM).  

### **Detection Objective:**  
Trigger an alert in Sentinel if a user logs into more than **three locations** within a 7-day time period. Not all alerts will indicate malicious activity, as some may be false positives.  

---

## 🚦 **Creating the Alert Rule (Potential Impossible Travel)**  
**Objective:**  
Set up a Sentinel **Scheduled Query Rule** in Log Analytics to detect users logging into multiple geographic regions.  

### **Rule Configuration Details:**  
1. **Trigger Conditions:**  
   - A user logs into two or more distinct locations within 7 days.  

2. **KQL Query:**

```kql
DeviceFileEvents
| top 20 by TimeGenerated desc
```
```kql
DeviceNetworkEvents
| top 20 by TimeGenerated desc
```
```kql
DeviceProcessEvents
| top 20 by TimeGenerated desc
``` 
```kql
let TimePeriodThreshold = timespan(7d);
let NumberOfDifferentLocationAllowed = 3;
SigninLogs
| where TimeGenerated > ago(TimePeriodThreshold)
| summarize count() by UserPrincipalName, City = tostring(parse_json(LocationDetails).city), State = tostring(parse_json(LocationDetails).state), Country = tostring(parse_json(LocationDetails).countryOrRegion)
| project UserPrincipalName, City, State, Country
| summarize PotentialImpossibleTravelInstances = count() by UserPrincipalName
| where PotentialImpossibleTravelInstances > NumberOfDifferentLocationAllowed
| order by PotentialImpossibleTravelInstances desc
```
![image](https://github.com/user-attachments/assets/028db60d-0a62-4436-8341-2bd96b4a7a0f)

3. **Analytics Rule Settings:**  
   - **Name:** Potential Impossible Travel Alert  
   - **Description:** Detects logins from multiple geographic regions.  
   - ✅ Enable the Rule.  
   - 🔄 Run Query Every 4 Hours.  
   - 📅 Lookup Data for the Last 7 Days.  
   - ❌ Stop Running Query After Alert is Generated.  

4. **Entity Mappings:**  
   - **Account ID:** AadUserId → `UserId`  
   - **Display Name:** UserPrincipalName → `Value`  

---

## 🔍 **Detection and Analysis**  

1. **Steps to Validate Incident:**  
   - ✅ Assign the incident to yourself and set the status to **Active**.  
   - 🔄 Use **Investigate** to review entities (may take time).  
   - 📊 Examine output from the analytics rule to identify flagged accounts.  

2. **Account Analysis:**  
   **Example Query:**  
   ```kql
   let TimePeriodThreshold = timespan(7d);
   SigninLogs
   | where TimeGenerated > ago(TimePeriodThreshold)
   | where UserPrincipalName == "username@domain.com"
   | project TimeGenerated, UserPrincipalName, UserId, City, State, Country
   | order by TimeGenerated desc
   ```

![image](https://github.com/user-attachments/assets/42a967ab-080e-4661-9d8b-b4dec9a6b7de)


   **Observed Findings:**  
   - **Account 1:** Logins from 7 nearby locations within 7 days. No unusual behavior.  
   - **Account 2:** Logins from 6 locations within 7 days. All locations were within a 3-hour train ride.  

---

## 🛠️ **Containment, Eradication, and Recovery**  

- **Outcome:**  
   The alert was determined to be **True Benign**:  
   - Account activity aligned with expected behavior.  
   - Users logged into locations within reasonable proximity and timeframes.  

- **Next Steps:**  
   - 🔍 Pivot to analyze additional activity for these accounts using:  
     ```kql
     AzureActivity
     | where tostring(parse_json(Claims)["http://schemas.microsoft.com/identity/claims/objectidentifier"]) == "AzureADObjectID"
     ```  
   - **If suspicious behavior is detected**, disable the account and escalate.  

---

## 🔄 **Post-Incident Activities**  
1. **Policy Updates:**  
   - Implement a **geo-fencing policy** in Azure to restrict logins outside specific regions.  
2. **Documentation:**  
   - Record all findings and lessons learned in the incident management system.  

---

## ✅ **Closure**  
1. **Review Incident:**  
   - Confirm resolution and update notes.  
   - Mark the incident as a **Benign Positive** or **False Positive** (based on findings).  
2. **Finalize Report:**  
   - Submit the report and close the case in Sentinel.  

📌 **Status:** Closed as **Benign Positive**.  

---

**✨ Lessons Learned:**  
- Better geographic restrictions can enhance security.  
- Not all triggers are threats; careful analysis prevents unnecessary escalations.  

📈 **Always stay vigilant!** 🛡️
