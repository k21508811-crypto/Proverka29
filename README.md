# Proverka29

PHP 8.1+ single-file website for REG.RU shared hosting.

## Installation
1. Upload `index.php` to the domain's document root (for example, `www/proverka29.ru/`).
2. Open `index.php` in a text editor and replace `ADMIN_SETUP_KEY` with a long random secret. Do not publish or share that secret.
3. Ensure PHP can create the `storage/` directory next to `index.php`.
4. Open `https://proverka29.ru/?page=setup`, create the administrator, then sign in.
5. Enable HTTPS in the hosting control panel.

The application stores JSON data and uploads under `storage/`. The included scanner is heuristic only; it is not an antivirus and cannot guarantee that a file is safe. Do not use it as the sole security control for uploaded files.

Requires PHP 8.1+, `json`, `fileinfo`, and `mbstring` extensions.
