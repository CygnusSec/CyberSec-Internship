# 🔐 CyberSec Internship - Weekly Reporting

This repository is used to manage, track, and review weekly progress reports for all internship members.

---

## 🎯 Objectives

- Ensure consistent **weekly reporting**
- Track individual progress via **GitHub**
- Maintain structured and reviewable work history

---

## 📌 General Rules

- Each member must submit **exactly ONE report per week**
- All submissions must be pushed to **GitHub**
- Follow **naming conventions strictly**
- Late or incorrectly formatted submissions may be **rejected**

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
```

### ❗ Rules

- Use lowercase
- Replace spaces with `-`
- Do NOT use Vietnamese accents
- Do NOT commit directly to `main`

---

## 📅 Weekly Folder Structure

Each report must be stored in a separate folder.

### 📛 Format

```
week<week_number>_<dd-mm-yyyy>
```

### ✅ Examples

```
week1_27-03-2026
week2_03-04-2026
```

---

## 📂 Required Contents

Each weekly folder MUST include:

### 1. 📄 Report (PDF)

File name:
```
report_<topic>_<keyword>.pdf
```

Content must include:

- Work completed
- Tasks in progress
- Issues encountered
- Solutions / learnings
- References (if any)

---

### 2. 💻 Source Code / Artifacts

Folder:
```
source_code/
```

Includes:

- Code
- Scripts
- Config files
- Logs (if relevant)

---

### 3. 📝 Notes (Optional but Recommended)

File:
```
notes.md
```

Used for:

- Quick notes
- Debug logs
- Extra explanations

---

## 📁 Example Repository Structure

```
repository/
│
├── tran-van-a/
│   ├── week1_27-03-2026/
│   │   ├── report.pdf
│   │   ├── source_code/
│   │   └── notes.md
│   │
│   ├── week2_03-04-2026/
│       ├── report.pdf
│       ├── source_code/
│       └── notes.md
```

---

## 🔄 Workflow

### Step 1: Update repository

```
git checkout main
git pull origin main
```

### Step 2: Switch to your branch

```
git checkout <your-branch>
```

### Step 3: Add your work

```
git add .
```

### Step 4: Commit

```
git commit -m "week X: add report"
```

### Step 5: Push

```
git push origin <your-branch>
```

---

## 🚀 Submission Process (Recommended)

- Create a **Pull Request (PR)** from your branch → `main`
- Title format:
```
[Week X] Full Name Report
```

Example:
```
[Week 1] Tran Van A Report
```

---

## ⚠️ Important Notes

- ❌ No direct commits to `main`
- ❌ No missing report files
- ❌ No wrong folder naming
- ❌ No empty source_code folder

- ✅ Keep commits clean
- ✅ Follow structure strictly
- ✅ Submit before deadline

---

## ✅ Submission Checklist

- [ ] Correct branch name
- [ ] Correct week folder name
- [ ] Added `report.pdf`
- [ ] Added `source_code/`
- [ ] Pushed to GitHub
- [ ] Created Pull Request

---

## 📬 Support

If you encounter issues:

- Contact your supervisor
- Or open an issue in this repository

---

## 🏁 Final Notes

This repository reflects your **learning progress and discipline**.

Make sure your work is:
- Clear
- Organized
- Reproducible

---

Happy coding 🚀
