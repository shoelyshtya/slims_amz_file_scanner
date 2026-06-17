<?php
defined('INDEX_AUTH') OR die('Direct access not allowed');

$quarantineIndex = amzscannerLoadQuarantineIndex();
$qTotal = count($quarantineIndex);
?>

<div class="d-flex justify-content-between align-items-center mb-3">
    <h5 class="font-weight-bold mb-0">🔒 Manajemen Karantina</h5>
    <span class="badge badge-secondary" style="font-size:11pt;"><?= $qTotal ?> Berkas</span>
</div>

<?php if (empty($quarantineIndex)): ?>
    <div class="alert alert-success text-center py-4">
        <h5 class="alert-heading mb-1">✅ Folder Karantina Kosong</h5>
        <p class="mb-0 text-muted">Tidak ada berkas yang sedang dikarantina. Sistem bersih.</p>
    </div>
<?php else: ?>

    <div class="alert alert-warning d-flex align-items-start mb-3">
        <span style="font-size:20px; margin-right:10px;">⚠️</span>
        <div>
            <strong>Perhatian:</strong> Berkas di bawah ini telah diisolasi dan <em>tidak dapat dieksekusi</em> dari web.
            Gunakan <strong>Pulihkan</strong> jika yakin ini adalah <em>false positive</em>, atau <strong>Hapus Permanen</strong> untuk menghapus selamanya.
        </div>
    </div>

    <div class="amz-card">
        <div class="card-body" style="padding:12px;">
            <div class="table-responsive">
                <table class="table table-bordered table-hover table-striped table-sm amz-table">
                    <thead class="thead-dark">
                        <tr>
                            <th width="4%">#</th>
                            <th width="16%">Nama Berkas</th>
                            <th width="20%">Lokasi Asal</th>
                            <th width="6%" class="text-center">Skor</th>
                            <th width="14%">Layer Terdeteksi</th>
                            <th width="22%">Alasan</th>
                            <th width="10%">Tanggal</th>
                            <th width="8%">Admin</th>
                            <th width="10%" class="text-center">Tindakan</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php $i = 1; foreach (array_reverse($quarantineIndex) as $qname => $entry):
                            $score = (int)($entry['score'] ?? 0);
                            $scoreCls = $score === 0 ? 'score-0' : ($score <= 3 ? 'score-lo' : ($score <= 7 ? 'score-hi' : 'score-cr'));
                            $originalName = basename($entry['original_path'] ?? $qname);
                        ?>
                            <tr class="<?= $score >= 8 ? 'q-row-critical' : '' ?>">
                                <td><?= $i++ ?></td>
                                <td>
                                    <code class="small" style="font-size:8.5pt;word-break:break-all;"><?= htmlspecialchars($originalName, ENT_QUOTES, 'UTF-8') ?></code>
                                    <br><small class="text-muted"><?= htmlspecialchars($entry['mime'] ?? '', ENT_QUOTES, 'UTF-8') ?></small>
                                </td>
                                <td><small class="text-muted" style="word-break:break-all;font-size:8pt;"><?= htmlspecialchars($entry['original_path'] ?? '—', ENT_QUOTES, 'UTF-8') ?></small></td>
                                <td class="text-center"><span class="score-circle <?= $scoreCls ?>"><?= $score ?></span></td>
                                <td>
                                    <?php foreach ($entry['layers'] ?? [] as $lyr): ?>
                                        <span class="layer-badge"><?= htmlspecialchars($lyr, ENT_QUOTES, 'UTF-8') ?></span>
                                    <?php endforeach; ?>
                                </td>
                                <td>
                                    <?php if (!empty($entry['msgs'])): ?>
                                        <ul class="mb-0 pl-3 small" style="font-size:8.5pt;">
                                            <?php foreach (array_slice($entry['msgs'], 0, 3) as $msg): ?>
                                                <li><?= htmlspecialchars($msg, ENT_QUOTES, 'UTF-8') ?></li>
                                            <?php endforeach; ?>
                                            <?php if (count($entry['msgs']) > 3): ?>
                                                <li class="text-muted">+<?= count($entry['msgs']) - 3 ?> lainnya</li>
                                            <?php endif; ?>
                                        </ul>
                                    <?php else: ?><span class="text-muted">—</span><?php endif; ?>
                                </td>
                                <td><small><?= htmlspecialchars($entry['quarantine_at'] ?? '—', ENT_QUOTES, 'UTF-8') ?></small></td>
                                <td><small class="text-muted"><?= htmlspecialchars($entry['quarantined_by'] ?? '—', ENT_QUOTES, 'UTF-8') ?></small></td>
                                <td class="text-center">
                                    <?php if ($can_write): ?>
                                        <form method="post" action="<?= amzscannerAdminUrl(['tab' => 'quarantine']) ?>" class="d-inline mb-1">
                                            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(amzscannerGetCsrfToken(), ENT_QUOTES, 'UTF-8') ?>">
                                            <input type="hidden" name="action" value="quarantine_restore">
                                            <input type="hidden" name="quarantine_name" value="<?= htmlspecialchars($qname, ENT_QUOTES, 'UTF-8') ?>">
                                            <button type="submit" class="btn btn-sm btn-outline-success font-weight-bold"
                                                onclick="return confirm('Pulihkan berkas ke lokasi asal?\n<?= addslashes(htmlspecialchars($entry['original_path'] ?? '', ENT_QUOTES, 'UTF-8')) ?>')">
                                                ♻️
                                            </button>
                                        </form>
                                        <form method="post" action="<?= amzscannerAdminUrl(['tab' => 'quarantine']) ?>" class="d-inline">
                                            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(amzscannerGetCsrfToken(), ENT_QUOTES, 'UTF-8') ?>">
                                            <input type="hidden" name="action" value="quarantine_delete">
                                            <input type="hidden" name="quarantine_name" value="<?= htmlspecialchars($qname, ENT_QUOTES, 'UTF-8') ?>">
                                            <button type="submit" class="btn btn-sm btn-outline-danger font-weight-bold"
                                                onclick="return confirm('⚠️ HAPUS PERMANEN? Tindakan ini tidak dapat dibatalkan!')">
                                                🗑️
                                            </button>
                                        </form>
                                    <?php else: ?><span class="text-muted">—</span><?php endif; ?>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <div class="text-muted small mt-1">
        📁 Lokasi karantina: <code><?= htmlspecialchars(amzscannerGetQuarantineDir(), ENT_QUOTES, 'UTF-8') ?></code>
        &nbsp;|&nbsp; Dilindungi <code>.htaccess</code> — tidak dapat dieksekusi dari web.
    </div>

<?php endif; ?>
