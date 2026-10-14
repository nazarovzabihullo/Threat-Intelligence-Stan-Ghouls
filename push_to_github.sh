#!/bin/bash
# Push CTI Repository to GitHub
# Usage: ./push_to_github.sh <YOUR_GITHUB_REPO_URL>
# Example: ./push_to_github.sh https://github.com/nazarov-zabihullo/stan-ghouls-cti-report.git

set -e

if [ -z "$1" ]; then
    echo "================================================================="
    echo "❌ Xatolik: GitHub repozitoriy havolasini kiritmadingiz!"
    echo "Foydalanish: ./push_to_github.sh <GITHUB_REPO_URL>"
    echo "Misol: ./push_to_github.sh https://github.com/username/cti-report.git"
    echo "================================================================="
    exit 1
fi

REPO_URL="$1"

echo "🚀 GitHub'ga yuklash boshlanmoqda..."
echo "📍 Repo URL: $REPO_URL"

# Masofaviy repo mavjudligini tekshirish
if git remote | grep -q "^origin$"; then
    git remote set-url origin "$REPO_URL"
else
    git remote add origin "$REPO_URL"
fi

git branch -M main

echo "📤 Fayllar yuborilmoqda..."
git push -u origin main

echo ""
echo "================================================================="
echo "✅ MUVAFFAQIN QILINDI! Repozitoriy GitHub'ga muvaffaqiyatli yuklandi!"
echo "Ko'rish uchun: ${REPO_URL%.git}"
echo "================================================================="
