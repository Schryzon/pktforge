# pktforge

🇺🇸 [English](README.md) | 🇮🇩 [Bahasa Indonesia](README_ID.md)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.12](https://img.shields.io/badge/Python-3.12-3776AB.svg?logo=python&logoColor=white)](https://www.python.org/)
[![Scoop](https://img.shields.io/badge/Scoop-python312-4285F4.svg)](https://scoop.sh/)
[![Packet Tracer](https://img.shields.io/badge/Cisco%20Packet%20Tracer-7.0%20--%207.3.0%2B-008080.svg?logo=cisco&logoColor=white)](https://www.netacad.com/)
[![Speed](https://img.shields.io/badge/Speed-10ms%20Decompile-success.svg)](#tolok-ukur-kinerja)
[![Sponsor Schryzon](https://img.shields.io/badge/Sponsor-Schryzon-ea4aaa.svg?logo=github-sponsors&logoColor=white)](https://github.com/sponsors/Schryzon)

`pktforge` adalah perangkat dekompilasi, kompilasi, dan otomatisasi tantangan (challenge authoring) luring (offline) berkecepatan tinggi untuk file Cisco Packet Tracer 7.x (.pkt dan .pka).

Perangkat ini sepenuhnya meniadakan kebutuhan untuk menjalankan aplikasi Cisco Packet Tracer dalam proses inspeksi file, pembuatan soal tantangan, maupun ekstraksi konfigurasi perangkat. Dengan mengimplementasikan pipeline kriptografi bawaan Packet Tracer secara langsung (Twofish-128 dalam mode EAX serta dua tahap obfuskasi posisi), `pktforge` mendekompilasi dan mengompilasi ulang topologi jaringan kompleks secara tepat dan tanpa kehilangan data dalam waktu sub-frame (10 hingga 50 milidetik).

## Fitur Utama

- Operasi Sepenuhnya Luring (Offline): Tidak membutuhkan proses `packettracer7.exe`, antarmuka grafis (GUI), ataupun pemindaian memori (memory scraping).
- Performa Sub-Frame: Dilengkapi akselerator native C yang dikompilasi otomatis pada eksekusi pertama menggunakan GCC `-O3`, menghasilkan kecepatan dekripsi 10-15 ms untuk topologi XML sebesar 3+ MB.
- Cadangan Python Murni (Pure Python Fallback): Dapat langsung dijalankan pada lingkungan Python 3.8+ tanpa compiler eksternal bila diperlukan.
- Mesin Pengubah Narasi dan Aturan Tantangan: Membaca, menyunting, dan menambahkan catatan kanvas, instruksi skenario, serta aturan penilaian Activity Wizard secara langsung tanpa penataan posisi manual di GUI.
- Otomatisasi Konfigurasi Perangkat: Mengekstraksi, memeriksa, dan mengekspor running-config Cisco IOS dari ratusan perangkat sekaligus.
- AI & Agentic Native: Menyuapkan struktur data XML dan JSON perangkat yang deterministik dan bersih ke agen AI atau prompt LLM untuk merancang, mengaudit, dan merevisi narasi soal secara instan tanpa halusinasi.
- 7 Jam Kebebasan dalam 2 Menit: Menggantikan kebiasaan melelahkan mengklik jendela GUI ratusan perangkat menjadi alur kerja otomatis yang hemat token.
- Kompilasi Dua Arah yang Utuh (Lossless Roundtrips): Mengompilasi kembali XML yang telah diubah menjadi file `.pkt` valid yang dapat dibuka langsung oleh Cisco Packet Tracer 7.3.0.

## Kebutuhan Sistem dan Dependensi

| Komponen | Spesifikasi Rekomendasi | Tingkat Kebutuhan | Tujuan | Perintah / Metode Instalasi |
| :--- | :--- | :--- | :--- | :--- |
| Runtime Python | Python 3.12 (via Scoop `python312`) | Wajib | Menjalankan CLI, manipulasi DOM XML, dan mesin kriptografi fallback | `scoop bucket add versions; scoop install python312` |
| Kompiler C | GCC 13+ (MSYS2 UCRT64 atau MinGW) | Opsional (Disarankan) | Mengompilasi DLL akselerasi C Twofish-EAX untuk performa sub-frame (10 ms) | `scoop install gcc` atau installer MSYS2 |
| Terminal / Shell | PowerShell 7+ (pwsh) | Disarankan | Lingkungan terminal modern untuk eksekusi perintah dan automasi | `scoop install pwsh` |
| Paket Python | Standard Library (`ctypes`, `zlib`, `struct`, `xml`) | Bawaan | Nol dependensi eksternal pip | Sudah terpasang bersama Python |
| Format Didukung | Cisco Packet Tracer 7.0 - 7.3.0+ (`.pkt`, `.pka`) | Target Input/Output | Dekompilasi, modifikasi, dan kompilasi file save Packet Tracer | N/A |

## Instalasi & Konfigurasi

Sangat disarankan untuk menggunakan Python 3.12 yang dipasang melalui bucket `versions` pada pengelola paket Scoop demi jalur interpreter yang terisolasi dan konsisten:

```powershell
# 1. Pasang Python 3.12 via Scoop (Rekomendasi)
scoop bucket add versions
scoop install python312

# 2. Gandakan (clone) repositori ini
git clone https://github.com/Schryzon/pktforge.git
cd pktforge

# 3. Verifikasi instalasi dan akses CLI
python312 pktforge.py --help
```

Apabila GCC terdeteksi pada PATH sistem Anda (misalnya dari MSYS2 atau Scoop), `pktforge` akan otomatis mengompilasi akselerator native C (`pkt_fast_crypto.dll`) saat pertama kali dijalankan. Jika tidak terdapat kompiler C, `pktforge` akan beralih ke mesin kriptografi Python murni secara mulus dan transparan.

## Panduan Penggunaan

### 1. Dekompilasi .pkt ke XML
```powershell
python312 pktforge.py decompile input.pkt -o topologi.xml
```

Mendekompilasi sekaligus mengekspor seluruh konfigurasi Cisco IOS perangkat ke direktori tujuan:
```powershell
python312 pktforge.py decompile input.pkt -o topologi.xml --dump-configs ./configs
```

### 2. Kompilasi XML ke .pkt
```powershell
python312 pktforge.py compile topologi.xml -o output.pkt
```

### 3. Memeriksa Catatan Kanvas dan Aturan Tantangan
```powershell
python312 pktforge.py challenge list input.pkt
```

### 4. Menyunting Aturan Tantangan Secara Instan
Menyunting catatan aturan utama secara langsung dan menghasilkan file `.pkt` baru:
```powershell
python312 pktforge.py challenge edit input.pkt -o challenge_baru.pkt --text "RULE SET: 1. Wajib konfigurasi DHCP pool. 2. Subnetting 69.67.10.0/28"
```

Atau memuat teks aturan dari file eksternal:
```powershell
python312 pktforge.py challenge edit input.pkt -o challenge_baru.pkt --file aturan_baru.txt
```

### 5. Menambahkan Catatan Baru pada Kanvas
```powershell
python312 pktforge.py challenge add input.pkt -o challenge_baru.pkt --text "Petunjuk: Periksa tagging VLAN 10" --x 2200 --y 1800
```

### 6. Memeriksa Inventaris Perangkat dan Alokasi IP
```powershell
python312 pktforge.py devices input.pkt
```

### Kompatibilitas Perintah Lama
Opsi CLI lama `-d` dan `-e` tetap didukung demi kompatibilitas ke belakang:
```powershell
python312 pktforge.py -d input.pkt hasil.xml
python312 pktforge.py -e hasil.xml output.pkt
```

## Contoh Output (Disamarkan / Masked)

### 1. Output Dekompilasi
Perintah:
```powershell
python312 pktforge.py decompile topologi_lab.pkt -o topologi.xml
```

Keluaran konsol:
```text
[*] Reading 'topologi_lab.pkt' (207,550 bytes)...
[*] Decrypting with C-Accelerator (Sub-frame)...
[+] Decrypted in 10.74 ms! XML size: 3,009,125 bytes
[+] Written XML to 'topologi.xml'
```

Cuplikan DOM XML yang dihasilkan (`topologi.xml`):
```xml
<PACKETTRACER5>
  <VERSION>7.3.0.0838</VERSION>
  <NETWORK>
    <DEVICES>
      <DEVICE>
        <ENGINE>
          <TYPE model="Router-PT-Empty">Router</TYPE>
          <NAME>CORE-ROUTER-01</NAME>
          <RUNNINGCONFIG>
            <LINE>hostname CORE-ROUTER-01</LINE>
            <LINE>interface FastEthernet0/0</LINE>
            <LINE> ip address 10.10.x.1 255.255.255.240</LINE>
            <LINE> duplex auto</LINE>
            <LINE> speed auto</LINE>
            <LINE>!</LINE>
          </RUNNINGCONFIG>
        </ENGINE>
      </DEVICE>
    </DEVICES>
  </NETWORK>
</PACKETTRACER5>
```

### 2. Output Pemeriksaan Catatan Kanvas & Storyboard
Perintah:
```powershell
python312 pktforge.py challenge list topologi_lab.pkt
```

Keluaran konsol:
```text
=== Canvas Notes & Storyboard (123 items) ===
[01] UUID: {69b3b427-xxxx-xxxx-xxxx-73cd79fcadc0} | Pos: (2321.0, 2189.0)
     Text: RULE SET: 1. Semua access point harus punya DHCP pool...

[02] UUID: {327ef44c-xxxx-xxxx-xxxx-4a22fce8ea41} | Pos: (3497.0, 2060.0)
     Text: 10.10.x.x/28

[03] UUID: {dfcb94ec-xxxx-xxxx-xxxx-00101fe9c256} | Pos: (2221.0, 1826.0)
     Text: CLIENT MODE
```

### 3. Output Inventaris Perangkat & Konfigurasi
Perintah:
```powershell
python312 pktforge.py devices topologi_lab.pkt
```

Keluaran konsol:
```text
=== Network Device Inventory (103 devices) ===
• [Router] CORE-ROUTER-01 (Router-PT-Empty) | IOS Config: 132 lines
    Interfaces: FastEthernet0/0: 10.10.x.1/255.255.255.240, FastEthernet1/0: 10.10.x.17/255.255.255.240
• [Router] EDGE-ROUTER-02 (Router-PT-Empty) | IOS Config: 112 lines
    Interfaces: FastEthernet0/0: 10.10.x.33/255.255.255.240, FastEthernet1/0: 10.10.x.49/255.255.255.240
• [Switch] SW-DISTRIBUTION-01 (2950-24) | IOS Config: 84 lines
... and 100 more devices
```

### 4. Output Modifikasi Aturan Soal secara Instan
Perintah:
```powershell
python312 pktforge.py challenge edit topologi_lab.pkt -o topologi_revisi.pkt --text "RULE SET: 1. Wajib OSPF area 0. 2. Subnetting 10.10.x.0/28"
```

Keluaran konsol:
```text
[*] Auto-detected rule note UUID: {69b3b427-xxxx-xxxx-xxxx-73cd79fcadc0}
[+] Successfully edited challenge note and saved to 'topologi_revisi.pkt' in 49.20 ms!
```

## Tolok Ukur Kinerja

Diuji pada prosesor AMD Ryzen 7 6800H menggunakan file `conflict-modul-4.pkt` (ukuran 207 KB `.pkt` yang menghasilkan 3.01 MB XML, 80.676 baris, 103 perangkat jaringan):

- Dekompilasi (Akselerator C): 10.32 ms
- Parsing XML dan Pencarian Catatan: 2.10 ms
- Modifikasi Aturan dan Enkripsi Ulang: 49.20 ms
- Total Waktu Roundtrip: < 65 ms

## Struktur Proyek

- `pktforge.py`: Titik masuk utama antarmuka baris perintah (CLI).
- `pktcore/crypto/`: Pipeline kriptografi, Twofish cipher, mode EAX, CMAC, dan bridge C.
- `pktcore/c_src/`: Implementasi C berkinerja tinggi untuk algoritma Twofish dan rutin obfuskasi.
- `pktcore/model/`: Model data untuk catatan kanvas, manajemen tantangan, dan topologi jaringan.
- `AGENTS.md`: Dokumentasi arsitektur dan referensi teknis lengkap bagi agen kecerdasan buatan (AI).
- `README.md`: Dokumentasi panduan pengguna dalam bahasa Inggris.
- `README_ID.md`: Dokumentasi panduan pengguna dalam bahasa Indonesia.

## Dukungan & Donasi (Sponsors)

Jika `pktforge` telah menghemat waktu praktikum Anda, mempermudah tugas asisten laboratorium, atau mempercepat riset Anda, pertimbangkan untuk mendukung kelanjutan pengembangan proyek ini:

- Sponsor via GitHub: [github.com/sponsors/Schryzon](https://github.com/sponsors/Schryzon)
- Pengembang: [Schryzon](https://github.com/Schryzon)
- Saweria: [saweria.co/Schryzon](https://saweria.co/schryzon)
- Buy me a coffee: [ko-fi.com/Schryzon](https://ko-fi.com/schryzon)

---

## Dedikasi untuk Asisten Laboratorium Jaringan Komputer

Kepada rekan-rekan asisten laboratorium jaringan komputer (aslab jarkom), di mana pun kalian berada, kapan pun kalian mengabdi, dan dari angkatan berapa pun kalian berasal:

Proyek ini kami dedikasikan seutuhnya untuk kalian.

Kami memahami perjuangan malam-malam panjang di laboratorium: berjam-jam mengklik dialog GUI Packet Tracer satu per satu hanya untuk melihat nama interface dan konfigurasi setelah sebelumnya benar-benar menguras tenaga dan pikiran merancang topologi tantangan yang rumit. Merancang dan merevisi modul praktikum berulang kali, menghadapi aplikasi yang macet sesaat sebelum ujian dimulai, hingga mengoreksi tumpukan file tugas praktikan satu per satu hingga larut malam.

Di era baru ini, menghabiskan waktu berjam-jam hanya untuk mengklik jendela GUI ratusan perangkat demi menuliskan narasi soal atau storyboard skenario adalah pemborosan energi yang melelahkan. Jika menyisihkan sedikit token dan beberapa menit bersama agen AI dapat memberikan Anda 7 jam kebebasan kembali, maka pktforge diciptakan untuk Anda.

Kalian adalah garda terdepan pendidikan jaringan komputer. Kalian yang menjembatani konsep teori OSI layer yang abstrak menjadi alur paket nyata. Kalian yang mendiagnosis subnet mask yang salah dan routing protocol yang buntu agar generasi penerus teknisi dan insinyur jaringan dapat belajar, berkarya, dan menghubungkan dunia.

Biarkan AI menangani penyusunan narasi cerita dan revisi aturan yang repetitif. Anda yang merancang keindahan arsitektur topologinya; biarkan automasi mesin yang menyelesaikan sisanya. Teruslah menginspirasi, pantang menyerah dalam memecahkan masalah, dan rawat terus api dedikasi kalian pada ilmu jaringan komputer.

---

## Kontribusi (Contributing)

Kontribusi, pelaporan kendala (issues), dan usulan fitur baru sangat kami sambut dengan tangan terbuka. Baik Anda seorang insinyur jaringan, peneliti keamanan siber, dosen, asisten laboratorium, maupun mahasiswa, kontribusi Anda sangat berarti dalam mengembangkan `pktforge`.

### Cara Berkontribusi
- Penambahan Fitur: Mengembangkan parser untuk subsistem Packet Tracer lainnya (seperti perangkat IoT, inspeksi PDU lanjutan, atau profil versi Packet Tracer terbaru).
- Optimasi Performa: Meningkatkan efisiensi algoritma kriptografi native maupun jalur cadangan Python murni.
- Dokumentasi & Templat Soal: Menambahkan templat tantangan praktikum, pola prompt AI untuk pembuatan narasi, maupun perbaikan dokumentasi.
- Pelaporan Bug: Mengirimkan laporan kendala disertai sampel file `.pkt` minimal yang memicu kegagalan dekompilasi.

### Alur Kontribusi
1. Lakukan Fork pada repositori ini.
2. Buat branch fitur baru Anda (`git checkout -b feature/fitur-keren`).
3. Lakukan commit perubahan Anda (`git commit -m "Menambahkan fitur keren"`).
4. Dorong branch ke remote (`git push origin feature/fitur-keren`).
5. Buka sebuah Pull Request (PR).

---

## Penafian (Disclaimers)

- Merek Dagang: Cisco, Cisco Packet Tracer, Cisco IOS, serta merek terkait lainnya merupakan merek dagang terdaftar milik Cisco Systems, Inc. `pktforge` adalah proyek riset edukasi dan rekayasa balik (reverse-engineering) independen berbasis komunitas yang tidak berafiliasi dengan, didukung oleh, maupun disponsori oleh Cisco Systems, Inc.
- Etika Akademik & Tujuan Penggunaan: Perangkat lunak ini dibuat murni untuk otomatisasi pendidikan yang sah, penyusunan kurikulum laboratorium, pembuatan tantangan luring, dan riset format file. Pengguna, tenaga pendidik, dan mahasiswa bertanggung jawab penuh untuk mematuhi kode integritas akademik di institusi masing-masing. Pengembang tidak mentolerir dan tidak mendukung penggunaan perangkat ini untuk kecurangan ujian atau manipulasi penilaian yang tidak sah.
- Batasan Tanggung Jawab (Warranty): Perangkat lunak ini disediakan "SEBAGAIMANA ADANYA" (AS IS), tanpa jaminan apa pun, baik tersurat maupun tersirat, termasuk namun tidak terbatas pada jaminan kelayakan jual, kesesuaian untuk tujuan tertentu, dan ketiadaan pelanggaran hak pihak ketiga.
