<?php
declare(strict_types=1);

/*
 * PROVERKA29 — single-file PHP application
 * Requires PHP 8.1+, sessions, json, fileinfo.
 * Before public launch, change ADMIN_SETUP_KEY below to a long random value.
 */
const APP_NAME = 'Proverka29';
const ADMIN_SETUP_KEY = 'CHANGE-THIS-TO-A-LONG-RANDOM-SECRET';
const MAX_UPLOAD_BYTES = 5 * 1024 * 1024;

$base = __DIR__ . '/storage';
$uploadDir = $base . '/uploads';
foreach ([$base, $uploadDir] as $dir) {
    if (!is_dir($dir)) { @mkdir($dir, 0750, true); }
}
if (!file_exists($base . '/.htaccess')) {
    @file_put_contents($base . '/.htaccess', "Require all denied\nDeny from all\n");
}
if (session_status() !== PHP_SESSION_ACTIVE) {
    session_set_cookie_params([
        'lifetime' => 0, 'path' => '/', 'secure' => !empty($_SERVER['HTTPS']),
        'httponly' => true, 'samesite' => 'Lax'
    ]);
    session_start();
}
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: strict-origin-when-cross-origin');
header("Content-Security-Policy: default-src 'self' 'unsafe-inline'; img-src 'self' data:; form-action 'self'; frame-ancestors 'none'");

function e(string $v): string { return htmlspecialchars($v, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }
function db(string $name, array $default = []): array {
    global $base;
    $path = $base . '/' . $name . '.json';
    if (!file_exists($path)) { file_put_contents($path, json_encode($default, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE), LOCK_EX); }
    $raw = file_get_contents($path);
    $data = json_decode($raw ?: '', true);
    return is_array($data) ? $data : $default;
}
function save_db(string $name, array $data): void {
    global $base;
    $path = $base . '/' . $name . '.json';
    $tmp = $path . '.tmp';
    file_put_contents($tmp, json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES), LOCK_EX);
    rename($tmp, $path);
}
function csrf(): string {
    if (empty($_SESSION['csrf'])) { $_SESSION['csrf'] = bin2hex(random_bytes(32)); }
    return $_SESSION['csrf'];
}
function verify_csrf(): void {
    if (!hash_equals($_SESSION['csrf'] ?? '', $_POST['csrf'] ?? '')) { http_response_code(419); exit('Сессия формы истекла. Обновите страницу.'); }
}
function current_user(): ?array {
    if (empty($_SESSION['uid'])) return null;
    foreach (db('users') as $u) if (($u['id'] ?? '') === $_SESSION['uid']) return $u;
    return null;
}
function notice(string $type, string $message): void { $_SESSION['notice'] = [$type, $message]; }
function go(string $page = 'home'): never { header('Location: ?page=' . rawurlencode($page)); exit; }
function make_id(): string { return strtoupper(bin2hex(random_bytes(4))); }

$users = db('users');
$apps = db('applications');
$reports = db('reports');
$scans = db('scans');
$settings = db('settings', ['site_title' => APP_NAME, 'maintenance' => false]);
$user = current_user();
$page = (string)($_GET['page'] ?? 'home');

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    verify_csrf();
    $action = (string)($_POST['action'] ?? '');
    if ($action === 'register') {
        $name = trim((string)($_POST['name'] ?? ''));
        $email = mb_strtolower(trim((string)($_POST['email'] ?? '')));
        $password = (string)($_POST['password'] ?? '');
        if (mb_strlen($name) < 2 || !filter_var($email, FILTER_VALIDATE_EMAIL) || strlen($password) < 8) {
            notice('error', 'Проверьте имя, email и пароль (не менее 8 символов).'); go('register');
        }
        foreach ($users as $u) if (mb_strtolower($u['email']) === $email) { notice('error', 'Этот email уже зарегистрирован.'); go('register'); }
        $users[] = ['id'=>bin2hex(random_bytes(16)), 'name'=>$name, 'email'=>$email, 'password'=>password_hash($password, PASSWORD_DEFAULT), 'role'=>'user', 'created'=>date(DATE_ATOM)];
        save_db('users', $users); notice('success', 'Аккаунт создан. Теперь войдите.'); go('login');
    }
    if ($action === 'login') {
        $email = mb_strtolower(trim((string)($_POST['email'] ?? '')));
        $password = (string)($_POST['password'] ?? '');
        foreach ($users as $u) {
            if (mb_strtolower($u['email']) === $email && password_verify($password, $u['password'])) {
                session_regenerate_id(true); $_SESSION['uid'] = $u['id']; notice('success', 'Вы вошли в аккаунт.'); go('account');
            }
        }
        notice('error', 'Неверный email или пароль.'); go('login');
    }
    if ($action === 'logout') { $_SESSION = []; session_regenerate_id(true); notice('success', 'Вы вышли из аккаунта.'); go(); }
    if ($action === 'application' && $user) {
        $topic = trim((string)($_POST['topic'] ?? ''));
        $body = trim((string)($_POST['body'] ?? ''));
        if (mb_strlen($topic) < 3 || mb_strlen($body) < 10) { notice('error', 'Заполните тему и подробное описание.'); go('account'); }
        $apps[] = ['id'=>make_id(), 'user_id'=>$user['id'], 'name'=>$user['name'], 'email'=>$user['email'], 'topic'=>$topic, 'body'=>$body, 'status'=>'Новая', 'created'=>date(DATE_ATOM), 'answer'=>''];
        save_db('applications', $apps); notice('success', 'Заявка отправлена.'); go('account');
    }
    if ($action === 'admin_setup') {
        $key = (string)($_POST['setup_key'] ?? '');
        if (ADMIN_SETUP_KEY === 'CHANGE-THIS-TO-A-LONG-RANDOM-SECRET' || !hash_equals(ADMIN_SETUP_KEY, $key)) {
            notice('error', 'Сначала измените ADMIN_SETUP_KEY в index.php на свой секретный ключ.'); go('setup');
        }
        $email = mb_strtolower(trim((string)($_POST['email'] ?? '')));
        $password = (string)($_POST['password'] ?? '');
        if (!filter_var($email, FILTER_VALIDATE_EMAIL) || strlen($password) < 12) { notice('error', 'Нужен корректный email и пароль от 12 символов.'); go('setup'); }
        foreach ($users as &$u) if (($u['role'] ?? '') === 'admin') { notice('error', 'Администратор уже создан.'); go('login'); }
        unset($u);
        $users[] = ['id'=>bin2hex(random_bytes(16)), 'name'=>'Администратор', 'email'=>$email, 'password'=>password_hash($password, PASSWORD_DEFAULT), 'role'=>'admin', 'created'=>date(DATE_ATOM)];
        save_db('users', $users); notice('success', 'Администратор создан. Войдите в систему.'); go('login');
    }
    if ($action === 'admin_update' && $user && $user['role'] === 'admin') {
        $id = (string)($_POST['id'] ?? '');
        foreach ($apps as &$a) if ($a['id'] === $id) {
            $a['status'] = trim((string)($_POST['status'] ?? 'В работе'));
            $a['answer'] = trim((string)($_POST['answer'] ?? ''));
        }
        unset($a); save_db('applications', $apps); notice('success', 'Заявка обновлена.'); go('admin');
    }
    if ($action === 'report' && $user && $user['role'] === 'admin') {
        $title = trim((string)($_POST['title'] ?? ''));
        $description = trim((string)($_POST['description'] ?? ''));
        if ($title !== '' && $description !== '') {
            $reports[] = ['id'=>make_id(), 'title'=>$title, 'description'=>$description, 'status'=>'Опубликован', 'created'=>date(DATE_ATOM)];
            save_db('reports', $reports); notice('success', 'Запись добавлена в реестр.'); 
        }
        go('admin');
    }
    if ($action === 'scan' && $user) {
        if (empty($_FILES['file']) || $_FILES['file']['error'] !== UPLOAD_ERR_OK) { notice('error', 'Не удалось загрузить файл.'); go('scanner'); }
        $f = $_FILES['file'];
        if ($f['size'] > MAX_UPLOAD_BYTES || $f['size'] < 1 || !is_uploaded_file($f['tmp_name'])) { notice('error', 'Файл пустой или превышает лимит 5 МБ.'); go('scanner'); }
        $original = basename((string)$f['name']);
        $mime = (new finfo(FILEINFO_MIME_TYPE))->file($f['tmp_name']) ?: 'unknown';
        $hash = hash_file('sha256', $f['tmp_name']);
        $contents = file_get_contents($f['tmp_name'], false, null, 0, 2 * 1024 * 1024);
        $signals = [];
        if (preg_match('/<\?php|<script\b|eval\s*\(|base64_decode\s*\(|shell_exec\s*\(/i', $contents ?: '')) $signals[] = 'Обнаружены подозрительные фрагменты кода';
        $ext = strtolower(pathinfo($original, PATHINFO_EXTENSION));
        if (in_array($ext, ['php','phtml','phar','exe','bat','cmd','scr','js'], true)) $signals[] = 'Потенциально исполняемый тип файла';
        $result = $signals ? 'Требует проверки' : 'Явных признаков не найдено';
        $scan = ['id'=>make_id(), 'user_id'=>$user['id'], 'filename'=>$original, 'mime'=>$mime, 'size'=>(int)$f['size'], 'sha256'=>$hash, 'signals'=>$signals, 'result'=>$result, 'created'=>date(DATE_ATOM)];
        $scans[] = $scan; save_db('scans', $scans);
        notice('success', 'Проверка завершена: ' . $result . '. Это базовая эвристическая проверка, не гарантия безопасности.');
        go('scanner');
    }
}
$user = current_user();
$isAdmin = $user && ($user['role'] ?? '') === 'admin';
$flash = $_SESSION['notice'] ?? null; unset($_SESSION['notice']);
function header_html(string $title, ?array $user, ?array $flash): void {
    echo '<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>'.e($title).' — '.APP_NAME.'</title><style>
    *{box-sizing:border-box}body{margin:0;background:#0b0b0f;color:#eee;font:16px/1.55 Arial,sans-serif}a{color:#ff5a5a;text-decoration:none}.wrap{max-width:1000px;margin:auto;padding:22px}.top{background:#15151c;border-bottom:1px solid #292932}.nav{display:flex;gap:16px;align-items:center;flex-wrap:wrap}.brand{font-weight:900;font-size:22px;color:#fff;margin-right:auto}.brand b{color:#f33}.hero{padding:45px 0}.hero h1{font-size:clamp(30px,6vw,54px);line-height:1.05;margin:0 0 16px}.muted{color:#aaa}.card{background:#15151c;border:1px solid #292932;border-radius:14px;padding:20px;margin:16px 0}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:14px}.btn,button{display:inline-block;background:#e32636;color:white;border:0;border-radius:9px;padding:11px 16px;font-weight:bold;cursor:pointer}.btn.secondary{background:#292932;color:#eee}input,textarea,select{width:100%;padding:12px;margin:6px 0 14px;background:#0e0e13;border:1px solid #383843;border-radius:8px;color:#fff}textarea{min-height:120px}label{font-weight:bold}.flash{padding:12px;border-radius:8px;background:#20202a;margin:14px 0}.error{border-left:4px solid #f44}.success{border-left:4px solid #3b7}.row{display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap}.small{font-size:13px;color:#aaa}table{width:100%;border-collapse:collapse}td,th{text-align:left;padding:10px;border-bottom:1px solid #333;vertical-align:top}footer{border-top:1px solid #292932;margin-top:40px;color:#888}.pill{background:#292932;padding:3px 8px;border-radius:20px;font-size:12px}
    </style></head><body><div class="top"><div class="wrap nav"><a class="brand" href="?">PROVERKA<b>29</b></a><a href="?page=registry">Реестр</a><a href="?page=scanner">Сканер</a>';
    if ($user) { echo '<a href="?page=account">Кабинет</a>'; if (($user['role']??'')==='admin') echo '<a href="?page=admin">Админ-панель</a>'; echo '<form method="post" style="margin:0"><input type="hidden" name="csrf" value="'.e(csrf()).'"><input type="hidden" name="action" value="logout"><button class="secondary">Выйти</button></form>'; }
    else echo '<a href="?page=login">Войти</a><a href="?page=register">Регистрация</a>';
    echo '</div></div><main class="wrap">';
    if ($flash) echo '<div class="flash '.e($flash[0]).'">'.e($flash[1]).'</div>';
}
function footer_html(): void { echo '</main><footer><div class="wrap small">© '.date('Y').' Proverka29. Сервис проверки и обработки обращений. Результаты автоматического сканирования не являются гарантией безопасности.</div></footer></body></html>'; }
header_html(APP_NAME, $user, $flash);

switch ($page) {
case 'register':
    echo '<div class="card"><h1>Регистрация</h1><form method="post"><input type="hidden" name="csrf" value="'.e(csrf()).'"><input type="hidden" name="action" value="register"><label>Имя</label><input name="name" required minlength="2"><label>Email</label><input type="email" name="email" required><label>Пароль (от 8 символов)</label><input type="password" name="password" required minlength="8"><button>Создать аккаунт</button></form></div>'; break;
case 'login':
    echo '<div class="card"><h1>Вход</h1><form method="post"><input type="hidden" name="csrf" value="'.e(csrf()).'"><input type="hidden" name="action" value="login"><label>Email</label><input type="email" name="email" required><label>Пароль</label><input type="password" name="password" required><button>Войти</button></form></div>'; break;
case 'setup':
    echo '<div class="card"><h1>Первичная настройка администратора</h1><p class="muted">Сначала откройте index.php и замените ADMIN_SETUP_KEY на длинный случайный секрет. После этого заполните форму.</p><form method="post"><input type="hidden" name="csrf" value="'.e(csrf()).'"><input type="hidden" name="action" value="admin_setup"><label>Секретный ключ настройки</label><input type="password" name="setup_key" required><label>Email администратора</label><input type="email" name="email" required><label>Пароль (не менее 12 символов)</label><input type="password" name="password" minlength="12" required><button>Создать администратора</button></form></div>'; break;
case 'account':
    if (!$user) { echo '<div class="card"><h1>Войдите в аккаунт</h1><a class="btn" href="?page=login">Войти</a></div>'; break; }
    echo '<h1>Личный кабинет</h1><div class="card"><p>Здравствуйте, '.e($user['name']).'.</p><h2>Новая заявка</h2><form method="post"><input type="hidden" name="csrf" value="'.e(csrf()).'"><input type="hidden" name="action" value="application"><label>Тема</label><input name="topic" required minlength="3"><label>Описание</label><textarea name="body" required minlength="10"></textarea><button>Отправить заявку</button></form></div><h2>Мои заявки</h2>';
    foreach ($apps as $a) if ($a['user_id']===$user['id']) echo '<div class="card"><div class="row"><b>'.e($a['topic']).'</b><span class="pill">'.e($a['status']).'</span></div><p>'.nl2br(e($a['body'])).'</p><p class="small">'.e($a['created']).'</p>'.(!empty($a['answer'])?'<p><b>Ответ:</b> '.nl2br(e($a['answer'])).'</p>':'').'</div>';
    break;
case 'scanner':
    echo '<h1>Проверка файла</h1><div class="card"><p>Загрузите файл размером до 5 МБ. Содержимое не публикуется. Сканер ищет отдельные подозрительные признаки и не заменяет антивирус.</p>';
    if ($user) echo '<form method="post" enctype="multipart/form-data"><input type="hidden" name="csrf" value="'.e(csrf()).'"><input type="hidden" name="action" value="scan"><input type="file" name="file" required><button>Проверить файл</button></form>';
    else echo '<a class="btn" href="?page=login">Войдите, чтобы проверить файл</a>';
    echo '</div>';
    if ($user) foreach (array_reverse($scans) as $s) if ($s['user_id']===$user['id']) echo '<div class="card"><b>'.e($s['filename']).'</b> — '.e($s['result']).'<p class="small">SHA-256: '.e($s['sha256']).' · '.e($s['created']).'</p>'.(!empty($s['signals'])?'<p>'.e(implode('; ',$s['signals'])).'</p>':'').'</div>';
    break;
case 'registry':
    echo '<h1>Публичный реестр</h1><p class="muted">Опубликованные записи проверок и уведомления сервиса.</p>';
    foreach (array_reverse($reports) as $r) echo '<div class="card"><div class="row"><b>'.e($r['title']).'</b><span class="pill">'.e($r['status']).'</span></div><p>'.nl2br(e($r['description'])).'</p><p class="small">'.e($r['created']).' · №'.e($r['id']).'</p></div>';
    if (!$reports) echo '<div class="card muted">Пока нет опубликованных записей.</div>'; break;
case 'admin':
    if (!$isAdmin) { echo '<div class="card"><h1>Доступ запрещён</h1><p>Раздел доступен только администратору.</p><a href="?page=login">Войти</a></div>'; break; }
    echo '<h1>Админ-панель</h1><div class="card"><h2>Заявки пользователей</h2>';
    foreach (array_reverse($apps) as $a) echo '<form method="post" class="card"><input type="hidden" name="csrf" value="'.e(csrf()).'"><input type="hidden" name="action" value="admin_update"><input type="hidden" name="id" value="'.e($a['id']).'"><b>'.e($a['topic']).'</b><p class="small">'.e($a['name']).' · '.e($a['email']).' · '.e($a['created']).'</p><p>'.nl2br(e($a['body'])).'</p><label>Статус</label><select name="status">'.implode('',array_map(fn($v)=>'<option '.($a['status']===$v?'selected':'').' value="'.e($v).'">'.e($v).'</option>', ['Новая','В работе','Ожидает ответа','Решена','Отклонена'])).'</select><label>Ответ</label><textarea name="answer">'.e($a['answer']).'</textarea><button>Сохранить</button></form>';
    echo '</div><div class="card"><h2>Добавить запись в реестр</h2><form method="post"><input type="hidden" name="csrf" value="'.e(csrf()).'"><input type="hidden" name="action" value="report"><label>Заголовок</label><input name="title" required><label>Описание</label><textarea name="description" required></textarea><button>Опубликовать</button></form></div><div class="card"><h2>Статистика</h2><p>Пользователей: '.count($users).' · Заявок: '.count($apps).' · Проверок файлов: '.count($scans).' · Записей реестра: '.count($reports).'</p></div>'; break;
default:
    echo '<section class="hero"><p class="muted">ПРОВЕРКА · ОБРАЩЕНИЯ · РЕЕСТР</p><h1>Proverka<span style="color:#f33">29</span></h1><p class="muted">Сервис для подачи обращений, отслеживания статуса заявок и базовой проверки файлов.</p><a class="btn" href="?page=register">Начать работу</a> <a class="btn secondary" href="?page=registry">Открыть реестр</a></section><div class="grid"><div class="card"><h2>Личный кабинет</h2><p class="muted">Создавайте обращения и следите за ответами.</p><a href="?page=account">Перейти →</a></div><div class="card"><h2>Проверка файлов</h2><p class="muted">Базовый поиск подозрительных признаков в файлах.</p><a href="?page=scanner">Открыть сканер →</a></div><div class="card"><h2>Публичный реестр</h2><p class="muted">Просматривайте опубликованные записи.</p><a href="?page=registry">Смотреть реестр →</a></div></div>';
    if (!$users) echo '<div class="card"><b>Первый запуск:</b> <a href="?page=setup">создать администратора</a>. Перед этим измените секрет ADMIN_SETUP_KEY в исходном файле.</div>';
}
footer_html();
