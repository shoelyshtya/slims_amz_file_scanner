<?php
defined('INDEX_AUTH') OR die('Direct access not allowed');

define('AMZSCANNER_PLUGIN_DIR', __DIR__);
define('AMZSCANNER_VERSION', '2.0.0');

// ── CSRF Protection ────────────────────────────────────────────────────────
function amzscannerGetCsrfToken(): string {
    if (empty($_SESSION['amzscanner_csrf'])) {
        $_SESSION['amzscanner_csrf'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['amzscanner_csrf'];
}

function amzscannerValidateCsrf(): bool {
    $token = $_POST['csrf_token'] ?? '';
    return hash_equals($_SESSION['amzscanner_csrf'] ?? '', $token);
}

// ── Admin URL Helpers ──────────────────────────────────────────────────────
function amzscannerAdminUrl(array $params = []): string {
    $base = defined('AWB') ? AWB . 'plugin_container.php' : 'plugin_container.php';
    $defaults = [
        'mod' => $_GET['mod'] ?? 'system',
        'id'  => $_GET['id'] ?? ''
    ];
    return $base . '?' . http_build_query(array_merge($defaults, $params));
}

function amzscannerRedirect(string $view = '', array $extra = []): string {
    $params = [];
    if ($view !== '') {
        $params['view'] = $view;
    }
    return amzscannerAdminUrl(array_merge($params, $extra));
}

// ── Zero-Migration Settings (JSON Based) ───────────────────────────────────
function amzscannerLoadSettings(): array {
    $path = __DIR__ . '/settings.json';
    $defaults = [
        // General
        'target_dir'                  => 'images/docs',
        'extra_patterns'              => '',
        'corrective_mode'             => 'quarantine', // quarantine | delete | report_only
        'notify_email'                => '',
        // Feature Toggles
        'enable_realtime_scan'        => '0',
        'enable_obfuscation_detect'   => '1',
        'enable_entropy_analysis'     => '1',
        'entropy_threshold'           => '6.5',
        'enable_magic_bytes'          => '1',
        'enable_polyglot_detect'      => '1',
        'enable_steganography_hint'   => '0',
        'enable_heuristic'            => '1',
    ];
    if (file_exists($path)) {
        $content = @file_get_contents($path);
        if ($content) {
            $data = json_decode($content, true);
            if (is_array($data)) {
                return array_merge($defaults, $data);
            }
        }
    }
    return $defaults;
}

function amzscannerSaveSetting(string $key, string $value): void {
    $path = __DIR__ . '/settings.json';
    $settings = amzscannerLoadSettings();
    $settings[$key] = $value;
    @file_put_contents($path, json_encode($settings, JSON_PRETTY_PRINT));
}

function amzscannerSaveAllSettings(array $newSettings): void {
    $path = __DIR__ . '/settings.json';
    $settings = amzscannerLoadSettings();
    $settings = array_merge($settings, $newSettings);
    @file_put_contents($path, json_encode($settings, JSON_PRETTY_PRINT));
}

// ── Path Resolution & Whitelists ───────────────────────────────────────────
function amzscannerAllowedDirs(): array {
    return [
        'images/docs',
        'images/persons',
        'repository',
        'images',
        'files'
    ];
}

function amzscannerIsStrictImageDir(string $dir): bool {
    return in_array($dir, ['images/docs', 'images/persons', 'images'], true);
}

function amzscannerResolvePhysicalPath(string $filePath, string $targetDir): string {
    if ($targetDir === 'all') {
        return SB . $filePath;
    } else {
        return SB . $targetDir . DIRECTORY_SEPARATOR . $filePath;
    }
}

function amzscannerIsValidDeletePath(string $physicalPath): bool {
    $realPath = realpath($physicalPath);
    if ($realPath === false) return false;

    $docRoot = realpath(SB);
    if ($docRoot === false) return false;

    $allowedDirs = amzscannerAllowedDirs();
    foreach ($allowedDirs as $dirKey) {
        $allowedRealPath = realpath(SB . $dirKey);
        if ($allowedRealPath !== false) {
            if (strpos($realPath, $allowedRealPath . DIRECTORY_SEPARATOR) === 0 || $realPath === $allowedRealPath) {
                return true;
            }
        }
    }
    return false;
}

// ── Quarantine System ──────────────────────────────────────────────────────
function amzscannerGetQuarantineDir(): string {
    return __DIR__ . DIRECTORY_SEPARATOR . 'quarantine';
}

function amzscannerEnsureQuarantineDir(): void {
    $dir = amzscannerGetQuarantineDir();
    if (!is_dir($dir)) {
        @mkdir($dir, 0755, true);
    }
    $htaccess = $dir . DIRECTORY_SEPARATOR . '.htaccess';
    if (!file_exists($htaccess)) {
        @file_put_contents($htaccess, "Order Deny,Allow\nDeny from all\nRemoveHandler .php .phtml .php3 .php4 .php5 .php7 .phar\n");
    }
    $indexHtml = $dir . DIRECTORY_SEPARATOR . 'index.html';
    if (!file_exists($indexHtml)) {
        @file_put_contents($indexHtml, '');
    }
}

function amzscannerLoadQuarantineIndex(): array {
    $path = __DIR__ . '/quarantine_index.json';
    if (!file_exists($path)) return [];
    $data = json_decode(@file_get_contents($path), true);
    return is_array($data) ? $data : [];
}

function amzscannerSaveQuarantineIndex(array $index): void {
    $path = __DIR__ . '/quarantine_index.json';
    @file_put_contents($path, json_encode($index, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
}

function amzscannerQuarantineFile(string $physicalPath, array $scanResult): bool {
    amzscannerEnsureQuarantineDir();
    $quarantineDir = amzscannerGetQuarantineDir();

    $uniqueName = date('YmdHis') . '_' . md5($physicalPath) . '.quarantine';
    $destPath    = $quarantineDir . DIRECTORY_SEPARATOR . $uniqueName;

    if (!@rename($physicalPath, $destPath)) {
        if (!@copy($physicalPath, $destPath)) return false;
        @unlink($physicalPath);
    }

    $index = amzscannerLoadQuarantineIndex();
    $index[$uniqueName] = [
        'original_path'  => $physicalPath,
        'quarantine_name'=> $uniqueName,
        'quarantine_at'  => date('Y-m-d H:i:s'),
        'mime'           => $scanResult['mime'] ?? '',
        'score'          => $scanResult['score'] ?? 0,
        'msgs'           => $scanResult['msgs'] ?? [],
        'layers'         => $scanResult['layers_triggered'] ?? [],
        'quarantined_by' => $_SESSION['realname'] ?? ($_SESSION['username'] ?? 'system'),
    ];
    amzscannerSaveQuarantineIndex($index);
    return true;
}

function amzscannerRestoreFromQuarantine(string $quarantineName): array {
    $index = amzscannerLoadQuarantineIndex();
    if (!isset($index[$quarantineName])) {
        return ['success' => false, 'msg' => 'Data karantina tidak ditemukan.'];
    }
    $entry       = $index[$quarantineName];
    $srcPath     = amzscannerGetQuarantineDir() . DIRECTORY_SEPARATOR . $quarantineName;
    $destPath    = $entry['original_path'];

    if (!file_exists($srcPath)) {
        return ['success' => false, 'msg' => 'Berkas karantina tidak ditemukan di folder karantina.'];
    }
    $destDir = dirname($destPath);
    if (!is_dir($destDir)) @mkdir($destDir, 0755, true);

    if (!@rename($srcPath, $destPath)) {
        return ['success' => false, 'msg' => 'Gagal memulihkan berkas (izin ditolak).'];
    }

    unset($index[$quarantineName]);
    amzscannerSaveQuarantineIndex($index);
    amzscannerWriteLog('restore', basename($destPath), $destPath, $entry['score'] ?? 0, ['Dipulihkan dari karantina'], []);
    return ['success' => true, 'msg' => 'Berkas berhasil dipulihkan ke: ' . $destPath];
}

function amzscannerDeleteFromQuarantine(string $quarantineName): array {
    $index = amzscannerLoadQuarantineIndex();
    $srcPath = amzscannerGetQuarantineDir() . DIRECTORY_SEPARATOR . $quarantineName;
    if (file_exists($srcPath)) @unlink($srcPath);
    if (isset($index[$quarantineName])) {
        $entry = $index[$quarantineName];
        amzscannerWriteLog('delete_permanent', basename($entry['original_path'] ?? $quarantineName), $entry['original_path'] ?? '', $entry['score'] ?? 0, ['Dihapus permanen dari karantina'], []);
        unset($index[$quarantineName]);
        amzscannerSaveQuarantineIndex($index);
    }
    return ['success' => true, 'msg' => 'Berkas berhasil dihapus permanen.'];
}

// ── Security Audit Log ─────────────────────────────────────────────────────
function amzscannerWriteLog(string $action, string $filename, string $path, int $score, array $msgs, array $layers): void {
    $logPath = __DIR__ . '/security_log.json';
    $log     = [];
    if (file_exists($logPath)) {
        $existing = json_decode(@file_get_contents($logPath), true);
        if (is_array($existing)) $log = $existing;
    }

    $log[] = [
        'timestamp' => date('Y-m-d H:i:s'),
        'action'    => $action,
        'filename'  => $filename,
        'path'      => $path,
        'score'     => $score,
        'msgs'      => $msgs,
        'layers'    => $layers,
        'actor'     => $_SESSION['realname'] ?? ($_SESSION['username'] ?? 'system'),
        'ip'        => $_SERVER['REMOTE_ADDR'] ?? '',
    ];

    // Trim log jika lebih dari 2000 entri
    if (count($log) > 2000) {
        $log = array_slice($log, -2000);
    }
    @file_put_contents($logPath, json_encode($log, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
}

function amzscannerLoadLogs(): array {
    $logPath = __DIR__ . '/security_log.json';
    if (!file_exists($logPath)) return [];
    $data = json_decode(@file_get_contents($logPath), true);
    return is_array($data) ? array_reverse($data) : [];
}

function amzscannerPruneLogs(int $daysOld = 90): int {
    $logPath  = __DIR__ . '/security_log.json';
    if (!file_exists($logPath)) return 0;
    $log      = json_decode(@file_get_contents($logPath), true);
    if (!is_array($log)) return 0;
    $cutoff   = strtotime("-{$daysOld} days");
    $filtered = array_filter($log, fn($e) => strtotime($e['timestamp'] ?? '2000-01-01') >= $cutoff);
    $pruned   = count($log) - count($filtered);
    @file_put_contents($logPath, json_encode(array_values($filtered), JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
    return $pruned;
}

// ── Core Scanner — Layer Definitions ──────────────────────────────────────

function amzscannerAllowedTypes(): array {
    return ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
}

/**
 * Layer 1: Extended Pattern Signatures
 */
function amzscannerForbiddenPatterns(string $extra = ''): array {
    $base = [
        // PHP Tag & Execution
        '<?php', '<?=', '?><script',
        // Command Execution
        'system(', 'shell_exec(', 'passthru(', 'exec(', 'popen(',
        'proc_open(', 'pcntl_exec(', 'assert(',
        // Dangerous Eval
        'eval(', 'preg_replace',
        // Web Shell Keywords
        'c99shell', 'r57shell', 'FilesMan', 'WSO Shell', 'b374k',
        'webshell', 'backdoor', 'hackers', 'hacked by',
        // Superglobals
        '$_POST', '$_GET', '$_REQUEST', '$_COOKIE', '$_SERVER', '$_FILES',
        // File Manipulation
        'file_put_contents(', 'move_uploaded_file(', 'fwrite(',
        'base64_decode(',
        // Remote Inclusion
        'file_get_contents("http', 'file_get_contents(\'http',
        'include("http', 'require("http',
        'fsockopen(', 'curl_exec(',
        // SQL Injection hints in files
        'UNION SELECT', 'DROP TABLE', 'LOAD_FILE(', 'INTO OUTFILE',
        // XSS / HTML Injection
        '<script', 'javascript:', 'vbscript:', 'data:text/html',
        'document.cookie', 'document.write(', 'innerHTML',
        'iframe', 'onload=', 'onerror=',
    ];
    if ($extra !== '') {
        foreach (explode(',', $extra) as $p) {
            $p = trim($p);
            if ($p !== '') $base[] = $p;
        }
    }
    return array_unique($base);
}

/**
 * Layer 2: Obfuscation & Encoding Patterns
 */
function amzscannerObfuscationPatterns(): array {
    return [
        // Base64 execution chains
        'eval(base64_decode'    => 8,
        'eval(gzinflate'        => 8,
        'eval(gzuncompress'     => 8,
        'eval(gzdecode'         => 8,
        'eval(str_rot13'        => 7,
        'eval(strrev'           => 7,
        // Dynamic function calls
        'call_user_func('       => 5,
        'call_user_func_array(' => 5,
        'create_function('      => 7,
        '${' . '{'              => 6,   // Variable variables $$
        'str_rot13('            => 4,
        'gzinflate('            => 4,
        'gzuncompress('         => 4,
        'gzdecode('             => 4,
        'hex2bin('              => 4,
        'convert_hex('          => 4,
        // String construction for obfuscation
        'chr(ord('              => 5,
        'implode(\'\',array(chr' => 7,
        // PHP wrapper streams
        'php://input'           => 6,
        'php://filter'          => 5,
        'data://text/plain'     => 6,
        'expect://'             => 8,
    ];
}

/**
 * Layer 3: Shannon Entropy Analysis
 * Returns float 0.0–8.0
 */
function amzscannerShannonEntropy(string $data): float {
    if (strlen($data) === 0) return 0.0;
    $freq = array_count_values(str_split($data));
    $len  = strlen($data);
    $entropy = 0.0;
    foreach ($freq as $count) {
        $p = $count / $len;
        $entropy -= $p * log($p, 2);
    }
    return round($entropy, 4);
}

/**
 * Layer 4: Magic Bytes Verification
 * Returns the expected type or false if mismatch
 */
function amzscannerCheckMagicBytes(string $fullPath): array {
    $handle = @fopen($fullPath, 'rb');
    if (!$handle) return ['ok' => true, 'msg' => ''];

    $header = fread($handle, 12);
    fclose($handle);

    $signatures = [
        "\xFF\xD8\xFF"             => 'image/jpeg',
        "\x89PNG\r\n\x1a\n"       => 'image/png',
        "GIF87a"                   => 'image/gif',
        "GIF89a"                   => 'image/gif',
        "RIFF"                     => 'image/webp', // RIFF....WEBP
        "%PDF"                     => 'application/pdf',
        "PK\x03\x04"              => 'application/zip',
        "\x7fELF"                  => 'application/elf',
        "\x4D\x5A"                 => 'application/exe', // MZ - Windows exe
        "<?php"                    => 'text/x-php',
        "<?"                       => 'text/x-php',
    ];

    $ext = strtolower(pathinfo($fullPath, PATHINFO_EXTENSION));
    $imageExts = ['jpg', 'jpeg', 'png', 'gif', 'webp'];

    foreach ($signatures as $magic => $type) {
        if (strncmp($header, $magic, strlen($magic)) === 0) {
            // Special check: is this an executable or PHP in an image extension?
            if (in_array($ext, $imageExts) && in_array($type, ['application/elf', 'application/exe', 'text/x-php', 'application/zip'])) {
                return ['ok' => false, 'msg' => "Magic bytes menunjukkan tipe '{$type}' meski berekstensi '.{$ext}'", 'score' => 9];
            }
            // Check: PHP file disguised with image extension
            if ($type === 'text/x-php' && in_array($ext, $imageExts)) {
                return ['ok' => false, 'msg' => "File PHP disamarkan sebagai gambar ('.{$ext}')", 'score' => 10];
            }
            return ['ok' => true, 'msg' => ''];
        }
    }
    return ['ok' => true, 'msg' => ''];
}

/**
 * Layer 5: Polyglot File Detection
 * Checks if a valid image ALSO contains PHP/script code after image data ends
 */
function amzscannerCheckPolyglot(string $fullPath, string $mimeType): array {
    $allowedTypes = amzscannerAllowedTypes();
    if (!in_array($mimeType, $allowedTypes, true)) {
        return ['ok' => true, 'msg' => ''];
    }

    $contents = @file_get_contents($fullPath);
    if ($contents === false) return ['ok' => true, 'msg' => ''];

    // Check for PHP opening tags anywhere in file
    $phpPatterns = ['<?php', '<?=', '<? ', "\x00<?php", "\xff<?php"];
    foreach ($phpPatterns as $pat) {
        if (stripos($contents, $pat) !== false) {
            return [
                'ok'    => false,
                'msg'   => 'Polyglot File: Gambar valid yang menyisipkan kode PHP di dalamnya',
                'score' => 10,
            ];
        }
    }

    // Check for eval/exec patterns (obfuscated may not have <?php)
    $dangerousInBinary = ['eval(', 'base64_decode(', 'system(', 'shell_exec('];
    foreach ($dangerousInBinary as $pat) {
        if (stripos($contents, $pat) !== false) {
            return [
                'ok'    => false,
                'msg'   => 'Polyglot File: Ditemukan payload kode berbahaya tertanam dalam gambar',
                'score' => 9,
            ];
        }
    }

    return ['ok' => true, 'msg' => ''];
}

/**
 * Layer 6: Steganography Hints
 */
function amzscannerCheckSteganography(string $fullPath, string $mimeType): array {
    $msgs = [];
    $score = 0;
    $allowedTypes = amzscannerAllowedTypes();

    if (!in_array($mimeType, $allowedTypes, true)) {
        return ['ok' => true, 'msgs' => [], 'score' => 0];
    }

    // Check suspicious EXIF metadata
    if (function_exists('exif_read_data') && in_array($mimeType, ['image/jpeg', 'image/tiff'], true)) {
        $exif = @exif_read_data($fullPath, 'ANY_TAG', true);
        if ($exif) {
            $exifStr = json_encode($exif);
            $suspiciousExif = ['<?php', 'eval(', 'base64_decode', 'system(', 'http://', 'https://'];
            foreach ($suspiciousExif as $sus) {
                if (stripos($exifStr, $sus) !== false) {
                    $msgs[] = 'Metadata EXIF mengandung string mencurigakan: "' . htmlspecialchars($sus, ENT_QUOTES, 'UTF-8') . '"';
                    $score += 6;
                }
            }
        }
    }

    // Check for abnormally large file size vs. image dimensions
    if (function_exists('getimagesize')) {
        $imgInfo = @getimagesize($fullPath);
        if ($imgInfo && isset($imgInfo[0], $imgInfo[1])) {
            $width    = $imgInfo[0];
            $height   = $imgInfo[1];
            $filesize = filesize($fullPath);
            // Rough threshold: if file is more than 10x larger than max expected raw pixels
            $maxExpected = $width * $height * 4 * 2; // RGBA * 2x safety margin
            if ($filesize > $maxExpected && $filesize > 102400) { // only flag if > 100KB
                $msgs[] = "Ukuran file ({$filesize} byte) tidak wajar untuk dimensi gambar {$width}x{$height}px — kemungkinan data tersembunyi";
                $score += 3;
            }
        }
    }

    return ['ok' => empty($msgs), 'msgs' => $msgs, 'score' => $score];
}

/**
 * Layer 7: Heuristic Scoring — threat level categories
 */
function amzscannerGetThreatLevel(int $score): string {
    if ($score === 0) return 'safe';
    if ($score <= 3)  return 'notice';   // Perhatian — tampilkan saja
    if ($score <= 7)  return 'danger';   // Bahaya — karantina/bersihkan
    return 'critical';                    // Kritis — hapus permanen
}

function amzscannerGetThreatLabel(string $level): string {
    return match($level) {
        'safe'     => '✅ Aman',
        'notice'   => '⚠️ Perhatian',
        'danger'   => '🚨 Bahaya',
        'critical' => '💀 Kritis',
        default    => '❓ Tidak Diketahui',
    };
}

// ── File Traversal ─────────────────────────────────────────────────────────
function amzscannerGetFilesRecursive(string $dirPath): array {
    $results = [];
    if (!is_dir($dirPath)) return [];
    $items = scandir($dirPath);
    if (!$items) return [];
    foreach ($items as $item) {
        if ($item === '.' || $item === '..') continue;
        $fullPath = $dirPath . DIRECTORY_SEPARATOR . $item;
        if (is_dir($fullPath)) {
            $results = array_merge($results, amzscannerGetFilesRecursive($fullPath));
        } else {
            $results[] = $fullPath;
        }
    }
    return $results;
}

// ── Master Scan Engine ─────────────────────────────────────────────────────

/**
 * Scan a single file with all enabled detection layers.
 * Returns a rich result array.
 */
function amzscannerScanSingleFile(string $fullPath, string $dirKey, array $settings): array {
    @set_time_limit(30);

    $excluded      = ['.', '..', 'index.php', 'index.html', '.htaccess', '.quarantine'];
    $filename      = basename($fullPath);
    $ext           = strtolower(pathinfo($fullPath, PATHINFO_EXTENSION));

    if (in_array($filename, $excluded, true) || $ext === 'quarantine') {
        return null; // Skip
    }

    $finfo    = new \finfo(FILEINFO_MIME_TYPE);
    $mimeType = $finfo->file($fullPath);
    $isStrict = amzscannerIsStrictImageDir($dirKey);
    $allowedTypes = amzscannerAllowedTypes();

    $score           = 0;
    $msgs            = [];
    $layersTriggered = [];
    $illegal         = false;

    $dangerousExts = ['php', 'phtml', 'php3', 'php4', 'php5', 'php7', 'phps', 'phar', 'sh', 'pl', 'py', 'asp', 'aspx', 'jsp', 'cgi'];
    $webXssExts    = ['html', 'htm', 'js', 'svg', 'xml'];

    // ── Extension Check ──
    if (in_array($ext, $dangerousExts, true)) {
        $msgs[]          = 'Ekstensi executable berbahaya (.' . $ext . ')';
        $layersTriggered[] = 'Ekstensi';
        $score          += 5;
    } elseif (in_array($ext, $webXssExts, true)) {
        $msgs[]          = 'Ekstensi skrip web (.' . $ext . ')';
        $layersTriggered[] = 'Ekstensi';
        $score          += 3;
    }

    // ── Layer 4: Magic Bytes ──
    if ($settings['enable_magic_bytes'] === '1') {
        $magic = amzscannerCheckMagicBytes($fullPath);
        if (!$magic['ok']) {
            $msgs[]          = '[Layer 4] ' . $magic['msg'];
            $layersTriggered[] = 'Magic Bytes';
            $score          += $magic['score'] ?? 7;
        }
    }

    // ── MIME Validation (Strict Image Dirs) ──
    if ($isStrict) {
        if (!in_array($mimeType, $allowedTypes, true)) {
            $msgs[]          = 'Bukan gambar valid (MIME: ' . htmlspecialchars($mimeType, ENT_QUOTES, 'UTF-8') . ')';
            $layersTriggered[] = 'MIME Validation';
            $score          += 6;
            $illegal         = true;
        }
    }

    // Read file contents for text-based analysis
    $contents = false;
    $scannableExts = array_merge($dangerousExts, $webXssExts, ['jpg', 'jpeg', 'png', 'gif', 'webp', 'txt', 'log', 'pdf']);
    if (in_array($ext, $scannableExts, true) || $isStrict) {
        $contents = @file_get_contents($fullPath);
    }

    if ($contents !== false) {
        // ── Layer 1: Pattern Signatures ──
        $forbiddenPatterns = amzscannerForbiddenPatterns($settings['extra_patterns'] ?? '');
        foreach ($forbiddenPatterns as $pattern) {
            if (stripos($contents, $pattern) !== false) {
                $msgs[]          = '[Layer 1] Pola "' . htmlspecialchars($pattern, ENT_QUOTES, 'UTF-8') . '" terdeteksi';
                $layersTriggered[] = 'Pattern Signature';
                $score          += 3;
                break; // One hit from layer 1 is enough to flag, avoid message spam
            }
        }
        // Count all pattern hits for score
        $patternHits = 0;
        foreach ($forbiddenPatterns as $pattern) {
            if (stripos($contents, $pattern) !== false) $patternHits++;
        }
        if ($patternHits > 1) $score += min($patternHits - 1, 5); // Extra score for multiple hits

        // ── Layer 2: Obfuscation Detection ──
        if ($settings['enable_obfuscation_detect'] === '1') {
            $obfPatterns = amzscannerObfuscationPatterns();
            foreach ($obfPatterns as $pattern => $obfScore) {
                if (stripos($contents, $pattern) !== false) {
                    $msgs[]          = '[Layer 2] Pola obfuscation "' . htmlspecialchars($pattern, ENT_QUOTES, 'UTF-8') . '" terdeteksi';
                    $layersTriggered[] = 'Obfuscation';
                    $score          += $obfScore;
                }
            }
        }

        // ── Layer 3: Entropy Analysis ──
        if ($settings['enable_entropy_analysis'] === '1') {
            $threshold = (float)($settings['entropy_threshold'] ?? 6.5);
            $entropy   = amzscannerShannonEntropy($contents);
            if ($entropy >= $threshold && strlen($contents) > 512) {
                $msgs[]          = '[Layer 3] Entropi Shannon tinggi (' . $entropy . ') — kemungkinan kode terenkripsi/di-pack';
                $layersTriggered[] = 'Entropy Analysis';
                $score          += 4;
            }
        }

        // ── Layer 5: Polyglot Detection ──
        if ($settings['enable_polyglot_detect'] === '1') {
            $polyglot = amzscannerCheckPolyglot($fullPath, $mimeType);
            if (!$polyglot['ok']) {
                $msgs[]          = '[Layer 5] ' . $polyglot['msg'];
                $layersTriggered[] = 'Polyglot';
                $score          += $polyglot['score'] ?? 9;
            }
        }
    }

    // ── Layer 6: Steganography Hints ──
    if ($settings['enable_steganography_hint'] === '1') {
        $stega = amzscannerCheckSteganography($fullPath, $mimeType);
        if (!$stega['ok']) {
            foreach ($stega['msgs'] as $sm) {
                $msgs[]          = '[Layer 6] ' . $sm;
            }
            $layersTriggered[] = 'Steganography';
            $score            += $stega['score'];
        }
    }

    // ── Layer 7: Heuristic — Combination Check ──
    if ($settings['enable_heuristic'] === '1' && $contents !== false) {
        $hasSuperGlobal  = (stripos($contents, '$_POST') !== false || stripos($contents, '$_GET') !== false || stripos($contents, '$_REQUEST') !== false);
        $hasEval         = (stripos($contents, 'eval(') !== false);
        $hasExec         = (stripos($contents, 'system(') !== false || stripos($contents, 'shell_exec(') !== false || stripos($contents, 'exec(') !== false);
        $hasBase64       = (stripos($contents, 'base64_decode(') !== false);

        if ($hasSuperGlobal && $hasEval) {
            $msgs[]          = '[Layer 7] Kombinasi berbahaya: superglobal + eval() — pola web shell klasik';
            $layersTriggered[] = 'Heuristic';
            $score          += 8;
        }
        if ($hasSuperGlobal && $hasExec) {
            $msgs[]          = '[Layer 7] Kombinasi berbahaya: superglobal + eksekusi perintah OS';
            $layersTriggered[] = 'Heuristic';
            $score          += 9;
        }
        if ($hasEval && $hasBase64 && $hasSuperGlobal) {
            $msgs[]          = '[Layer 7] Kombinasi KRITIS: eval + base64_decode + superglobal — web shell tersamar';
            $layersTriggered[] = 'Heuristic';
            $score          += 10;
        }
    }

    // Deduplicate layers
    $layersTriggered = array_unique($layersTriggered);

    $threatLevel = amzscannerGetThreatLevel($score);

    return [
        'file'             => $fullPath,
        'mime'             => $mimeType,
        'score'            => $score,
        'threat_level'     => $threatLevel,
        'status'           => ($score === 0) ? 'safe' : (($score <= 3) ? 'notice' : 'danger'),
        'msgs'             => array_unique($msgs),
        'layers_triggered' => $layersTriggered,
        'illegal'          => $illegal,
        'action_done'      => '',
    ];
}

/**
 * Scan an entire directory.
 * Returns array of results.
 */
function amzscannerScanDir(string $dirPath, string $dirKey, array $forbiddenPatterns, bool $corrective, array $settings = []): array {
    if (empty($settings)) $settings = amzscannerLoadSettings();

    $results = [];
    if (!is_dir($dirPath)) {
        return [['file' => $dirPath, 'status' => 'error', 'score' => 0, 'msgs' => ['Direktori tidak ditemukan.'], 'layers_triggered' => [], 'action_done' => '']];
    }

    $allFiles = amzscannerGetFilesRecursive($dirPath);
    $corrective_mode = $settings['corrective_mode'] ?? 'quarantine';
    $allowedTypes = amzscannerAllowedTypes();

    foreach ($allFiles as $fullPath) {
        $result = amzscannerScanSingleFile($fullPath, $dirKey, $settings);
        if ($result === null) continue;

        // Determine relative path for display
        $result['file'] = ltrim(str_replace($dirPath, '', $fullPath), DIRECTORY_SEPARATOR);

        // Corrective action
        if ($corrective && $result['score'] > 0 && empty($result['action_done'])) {
            $finfo    = new \finfo(FILEINFO_MIME_TYPE);
            $mimeType = $finfo->file($fullPath);
            $rewrote  = false;

            if ($corrective_mode === 'report_only') {
                $result['action_done'] = 'Dilaporkan saja (Report Only Mode)';
            } elseif ($corrective_mode === 'delete') {
                if (@unlink($fullPath)) {
                    $result['action_done'] = 'Dihapus Permanen';
                    amzscannerWriteLog('delete', basename($fullPath), $fullPath, $result['score'], $result['msgs'], $result['layers_triggered']);
                } else {
                    $result['action_done'] = 'Gagal dihapus (Izin ditolak)';
                }
            } else {
                // Default: quarantine — but first try to clean images via GD
                if (in_array($mimeType, $allowedTypes, true)) {
                    if ($mimeType === 'image/jpeg') {
                        $img = @imagecreatefromjpeg($fullPath);
                        if ($img) { $rewrote = @imagejpeg($img, $fullPath, 90); imagedestroy($img); }
                    } elseif ($mimeType === 'image/png') {
                        $img = @imagecreatefrompng($fullPath);
                        if ($img) { $rewrote = @imagepng($img, $fullPath, 9); imagedestroy($img); }
                    } elseif ($mimeType === 'image/gif') {
                        $img = @imagecreatefromgif($fullPath);
                        if ($img) { $rewrote = @imagegif($img, $fullPath); imagedestroy($img); }
                    } elseif ($mimeType === 'image/webp') {
                        $img = @imagecreatefromwebp($fullPath);
                        if ($img) { $rewrote = @imagewebp($img, $fullPath, 80); imagedestroy($img); }
                    }
                }

                if ($rewrote) {
                    $result['action_done'] = 'Gambar Dibersihkan (GD Library)';
                    amzscannerWriteLog('clean', basename($fullPath), $fullPath, $result['score'], $result['msgs'], $result['layers_triggered']);
                } else {
                    if (amzscannerQuarantineFile($fullPath, $result)) {
                        $result['action_done'] = 'Dipindahkan ke Karantina';
                        amzscannerWriteLog('quarantine', basename($fullPath), $fullPath, $result['score'], $result['msgs'], $result['layers_triggered']);
                    } else {
                        $result['action_done'] = 'Gagal dikarantina (Izin ditolak)';
                    }
                }
            }
        }

        $results[] = $result;
    }
    return $results;
}

/**
 * Quick scan of a single tmp file (for real-time upload interception).
 * Returns array with 'safe' boolean and 'msgs' array.
 */
function amzscannerScanUploadedFile(string $tmpPath, string $originalName, array $settings = []): array {
    if (empty($settings)) $settings = amzscannerLoadSettings();

    $ext     = strtolower(pathinfo($originalName, PATHINFO_EXTENSION));
    $dirKey  = 'images/docs'; // default context for upload check

    $result  = amzscannerScanSingleFile($tmpPath, $dirKey, $settings);
    if ($result === null) {
        return ['safe' => true, 'msgs' => [], 'score' => 0];
    }

    if ($result['score'] > 0) {
        amzscannerWriteLog(
            'upload_blocked',
            $originalName,
            $tmpPath,
            $result['score'],
            $result['msgs'],
            $result['layers_triggered']
        );
    }

    return [
        'safe'   => $result['score'] === 0,
        'msgs'   => $result['msgs'],
        'score'  => $result['score'],
        'layers' => $result['layers_triggered'],
    ];
}
