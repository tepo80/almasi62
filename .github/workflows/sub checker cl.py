name: Sub Checker cl-

on:
  workflow_dispatch:
  schedule:
    - cron: "0 */2 * * *"   # اجرای cl.py هر ۲ ساعت یک‌بار

permissions:
  contents: write

jobs:
  cl-job:
    runs-on: ubuntu-latest
    timeout-minutes: 5
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: 3.11
      - run: pip install requests psutil retrying PyYaml || echo "skip install"
      - run: |
          rm -f almasi.txt test.txt
          timeout 180s python cl.py || echo "❌ cl.py failed or skipped"
      - run: |
          if [[ -s almasi.txt || -s test.txt ]]; then
            git config user.name "github-actions[bot]"
            git config user.email "41898282+github-actions[bot]@users.noreply.github.com"
            git add almasi.txt test.txt
            git commit -m "auto update from cl.py [skip ci]" || echo "No changes"
            git push || echo "skip push"
          else
            echo "⚠️ almasi.txt یا test.txt خالی یا موجود نیست، commit نشد"
          fi
