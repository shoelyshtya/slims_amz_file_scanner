# 🛡️ AMZ File Scanner & Sanitizer — v2.0

Plugin keamanan **multi-lapis (7-Layer Security Engine)** untuk SLiMS yang dirancang untuk memindai, mendeteksi, dan membersihkan berkas-berkas berbahaya dari folder unggahan — termasuk PHP web shell tersamar (*obfuscated*), polyglot files, file terenkripsi, dan malware tersembunyi di dalam gambar.

> **Versi 2.0** adalah peningkatan besar dari v1.0. Plugin ini kini memiliki mesin deteksi berlapis, sistem karantina aman, log audit keamanan, dan intersepsi upload real-time.

---

## 🏛️ Arsitektur — Mesin Deteksi 7 Lapis

| Layer | Nama | Deskripsi |
|---|---|---|
| 🔴 **Layer 1** | **Pattern Signature** | 40+ pola tanda tangan: web shell (c99, r57), eksekusi perintah, injeksi SQL, XSS lanjutan. Selalu aktif. |
| 🟠 **Layer 2** | **Obfuscation Detection** | Deteksi `eval(base64_decode...)`, hex/octal encoding, `str_rot13`, `gzinflate`, variabel dinamis `$$`, dan `create_function()`. |
| 🟡 **Layer 3** | **Entropy Analysis** | Analisis matematis Shannon Entropy untuk mendeteksi kode terenkripsi atau di-*pack*. Threshold dapat dikonfigurasi. |
| 🟢 **Layer 4** | **Magic Bytes Verification** | Verifikasi "sidik jari" byte pertama file. Mendeteksi PHP yang disamarkan sebagai `.jpg`/`.png`, binary ELF, dan ZIP tersembunyi. |
| 🔵 **Layer 5** | **Polyglot Detection** | Mendeteksi file yang sah sebagai 2 format sekaligus (JPEG valid + PHP). Teknik bypass scanner yang paling licik. |
| 🟣 **Layer 6** | **Steganography Hints** | Mendeteksi metadata EXIF mencurigakan dan ukuran file yang tidak wajar terhadap dimensi gambar. |
| ⚫ **Layer 7** | **Heuristic Scoring** | Skor bahaya kumulatif (0–10+) berdasarkan kombinasi pola. Mendeteksi pola web shell klasik: `$_POST + eval() + base64_decode`. |

---

## 📊 Tingkat Ancaman (Threat Level)

| Skor | Level | Ikon | Tindakan Default |
|---|---|---|---|
| 0 | Aman | ✅ | — |
| 1–3 | Perhatian | ⚠️ | Dilaporkan ke log |
| 4–7 | Bahaya | 🚨 | Karantina / Bersihkan GD |
| ≥ 8 | Kritis | 💀 | Karantina / Hapus Permanen |

---

## ✨ Fitur Utama v2.0

### 🔍 Pemindaian Multi-Lapis (7 Layer)
- Setiap lapisan dapat diaktifkan/dinonaktifkan secara independen
- Setiap deteksi menghasilkan **skor bahaya kumulatif**
- Tampilan kolom baru: Skor, Layer Terdeteksi, Keterangan per layer

### ⚡ Intersepsi Upload Real-time
- Memblokir berkas berbahaya **sebelum** berhasil disimpan di server
- Terintegrasi dengan SLiMS Hooks: Bibliografi & Keanggotaan
- Dapat diaktifkan/dinonaktifkan dengan sakelar di halaman pengaturan

### 🚀 AJAX Chunked Scanner
- Pemindaian bertahap 50 file/batch via AJAX (tidak ada timeout)
- Progress bar real-time dengan nama berkas yang sedang dipindai
- Aman untuk folder dengan ribuan berkas

### 🔒 Sistem Karantina Aman
- Berkas berbahaya dipindahkan ke folder `quarantine/` yang dilindungi `.htaccess`
- Tidak bisa dieksekusi dari web
- **Dasbor karantina** untuk melihat, memulihkan, atau menghapus permanen

### 📋 Log Audit Keamanan
- Setiap event dicatat: waktu, tindakan, nama file, skor, layer, admin, IP
- Filter berdasarkan tindakan & tanggal
- Export ke **CSV** untuk keperluan audit
- Pembersihan log lama (1 bulan / 3 bulan / 6 bulan / 1 tahun)

### ⚙️ Panel Pengaturan Lengkap
- Toggle On/Off per fitur
- Slider threshold entropi (3.0–8.0)
- Mode tindakan korektif: Karantina / Hapus / Laporkan Saja
- Notifikasi email saat ancaman kritis terdeteksi

---

## 📁 Folder Target Pemindaian

| Folder | Isi |
|---|---|
| `images/docs` | Sampul Bibliografi / Cover Buku |
| `images/persons` | Foto Profil Anggota |
| `repository` | Lampiran Dokumen (PDF, DOCX, dll.) |
| `images` | Semua Gambar |
| `files` | Berkas Umum |

---

## 🚀 Cara Instalasi & Aktivasi

1. Salin folder plugin ke direktori plugins SLiMS:
   ```
   slims/plugins/slims_amz_file_scanner-slims/
   ```
2. Masuk ke halaman **Admin SLiMS**.
3. Buka **System → Plugins → Aktifkan** plugin **AMZ File Scanner**.
4. Menu **🛡️ AMZ File Scanner** akan muncul di modul System.

---

## 🗂️ Struktur File

```
slims_amz_file_scanner-slims/
├── amz-file-scanner.plugin.php    ← Bootstrapper + Hook real-time
├── helper.php                      ← Mesin deteksi 7 lapis + Karantina + Log
├── admin_menu.php                  ← Navigasi tab utama
├── settings.json                   ← Konfigurasi (auto-generated)
├── quarantine_index.json           ← Metadata karantina (auto-generated)
├── security_log.json               ← Log audit (auto-generated)
├── quarantine/
│   └── .htaccess                   ← Proteksi (auto-generated)
└── inc/
    ├── admin_scan.inc.php          ← Tab Pemindaian (AJAX Chunked)
    ├── admin_settings.inc.php      ← Tab Pengaturan (Sakelar per layer)
    ├── admin_quarantine.inc.php    ← Tab Karantina (Manajemen karantina)
    ├── admin_actions.inc.php       ← AJAX endpoints + Aksi korektif
    └── admin_logs.inc.php          ← Tab Log Audit
```

---

## ⚠️ Disclaimer

Plugin ini memproses pembersihan berkas gambar menggunakan **PHP GD Library**. Meskipun aman, pastikan Anda **selalu melakukan backup berkas secara berkala** sebelum menjalankan tindakan korektif. Sistem karantina disediakan untuk meminimalkan risiko kehilangan data akibat *false positive*.

---

## 📝 Changelog

### v2.0.0 (2026)
- **NEW**: Mesin deteksi 7 lapis (Obfuscation, Entropy, Magic Bytes, Polyglot, Steganography, Heuristic)
- **NEW**: Intersepsi upload real-time via SLiMS Hooks (Bibliography & Membership)
- **NEW**: AJAX Chunked Scanner dengan progress bar real-time
- **NEW**: Sistem Karantina aman + Dasbor manajemen karantina
- **NEW**: Log Audit Keamanan + Filter + Export CSV
- **NEW**: Panel Pengaturan lengkap dengan sakelar per-fitur
- **NEW**: Skor bahaya kumulatif dan tingkatan ancaman (Aman/Perhatian/Bahaya/Kritis)
- **IMPROVED**: Pattern signature diperluas dari 20 → 40+ pola
- **IMPROVED**: Deteksi ekstensi berbahaya ditambah: `.asp`, `.aspx`, `.jsp`, `.cgi`, `.svg`

### v1.0.0
- Rilis perdana: Pemindaian folder, deteksi pola dasar, tindakan korektif, ekspor Excel & cetak laporan.

---

## 👤 Kredit

- **Author**: Ade Ismail Siregar
- **Plugin URI**: https://github.com/adeism/slims_amz_file_scanner
- **Terinspirasi dari**: Postingan Pak Hendro Wicaksono di WhatsApp Group SLiMS — [slims-clean-image](https://github.com/hendrowicaksono/slims-clean-image/blob/master/clean-image.php)
