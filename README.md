# 🔐 CyberSec Internship - Weekly Reporting

This repository is used to manage, track, and review weekly progress reports for all internship members.

---

## 🎯 Objectives

- Ensure consistent **weekly reporting**
- Track individual progress via **GitHub**
- Build structured content that can be combined into a final report

---

## 📌 General Rules

- Each member must submit **exactly ONE report per week**
- All submissions must be pushed to **GitHub**
- Follow **naming conventions strictly**
- Each report should be written in a **clear and reusable format**

---

## 🌿 Branch Management

Each member must work on their **own branch**

### 📛 Naming Convention
```
<full-name-no-accent>
```

### ✅ Examples
```
tran-van-a
nguyen-duc-minh
```

### ❗ Rules
- Use lowercase
- Replace spaces with `-`
- Do NOT use Vietnamese accents
- Do NOT commit directly to `main`

---

## 📅 Weekly Folder Structure

### 📛 Format
```
week<week_number>_<dd-mm-yyyy>
```

### ✅ Example
```
week1_27-03-2026
```

---

## 📄 Report Naming Convention

### 📛 Format
```
week<week>_<topic>_<tool>.pdf
```

### ✅ Examples
```
week1_api-testing_crapi.pdf
week2_ids_wazuh.pdf
week3_rag_qwen.pdf
```

---

## 📂 Required Contents

Each weekly folder MUST include:

- `report.pdf` (main report - required)
- `report_<topic>.pdf` (optional readable version)
- `source_code/` (code, configs, scripts)
- `notes.md` (optional)

---

## 🧠 Structured Reporting (IMPORTANT)

Each weekly report should be written in a way that:

- Can stand alone as a weekly progress report
- Can be **combined later into a final report/document**

👉 This means:
- Write clearly and formally
- Avoid personal/journal-style writing
- Focus on reusable technical content

---

## 📘 Weekly Report Template (MUST FOLLOW)

### 1. Contribution Scope
- What part of the project this week contributes to

### 2. Objective of This Week
- ...

### 3. Detailed Work
#### 3.1 Description
#### 3.2 Design / Method
#### 3.3 Implementation

### 4. Results / Output

### 5. Analysis

### 6. Issues & Fixes

### 7. Reusable Content ⭐ (REQUIRED)
- Write 1–2 pages in clear, formal style
- This section should be reusable in final documentation

### 8. Next Step

---

## 🐙 GitHub Issue Workflow (REQUIRED)

To ensure clear communication and tracking, all tasks must be managed via **GitHub Issues**.

### 📌 1. Each Task = One Issue

Every task must be created as a separate issue.

#### Naming format:
```
[Week X] <topic> - <short description>
```

#### Examples:
```
[Week 2] IDS - Setup Wazuh agent
[Week 3] API Testing - Scan crAPI
```

---

### 📄 2. Issue Template

Each issue must follow this structure:

```
## 📌 Description
What is this task about?

## 🎯 Objective
-

## 📂 Expected Output
-

## 🛠 Tools / Tech
-

## ⏱ Deadline
-

## 🔗 Related
- Report folder:
- PR:

## 📝 Notes
-
```

---

### 👤 3. Assignment & Labels

- Assign the issue to the responsible person
- Use labels such as:
  - `week1`, `week2`
  - `api`, `ids`, `nginx`
  - `review`, `urgent`

---

### 🔄 4. Workflow

#### Intern:

- Update progress via comments:
```
Day 1: ...
Day 2: ...
```

- When done:
```
- Done
- PR: #<number>
- Report: <folder>
```

- Close the issue

---

### 🔗 5. Linking (IMPORTANT)

#### In commit:
```
git commit -m "week X: <task> (#issue_number)"
```

#### In PR:
```
Closes #issue_number
```

---

## 🔄 Workflow (Git)

```
git checkout main
git pull origin main
git checkout <your-branch>
git add .
git commit -m "week X: report"
git push origin <your-branch>
```

---

## 🚀 Submission Process

- Create Pull Request → main
- Title:
```
[Week X] Full Name - Topic
```

---

## ⚠️ Important Notes

- ❌ No direct commit to main
- ❌ Missing report → reject
- ❌ Wrong format → reject
- ❌ No issue tracking → reject

- ✅ Must include "Reusable Content"
- ✅ Must link issue ↔ PR ↔ report

---

## ✅ Checklist

- [ ] Correct branch
- [ ] Correct folder name
- [ ] Report file named correctly
- [ ] Contains reusable content section
- [ ] Issue created and updated
- [ ] PR linked to issue
- [ ] Pushed & PR created

---

## 🏁 Final Note

Weekly reports are building blocks.

If written properly:
👉 They can be combined later into a complete final document

---

Happy coding 🚀
