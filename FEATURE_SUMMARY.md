# Fitur Baru: External Scanner Plugins & Real-time Progress

## Ringkasan Fitur

Fitur baru yang ditambahkan ke Vulnerability Scanner:

### 1. External Scanner Plugins (`modules/external_scanners.py`)

Plugin untuk mengintegrasikan scanner keamanan eksternal:

- **Nuclei Plugin**: Template-based vulnerability scanner
  - Support custom templates
  - Severity filtering (critical, high, medium, low, info)
  - JSON output parsing
  - Real-time progress tracking

- **Nikto Plugin**: Web server scanner
  - Tuning options configuration
  - Plugin selection
  - OSVDB reference integration
  - Comprehensive web vulnerability detection

- **Plugin Manager**: 
  - Auto-detection of installed scanners
  - Unified interface for running multiple scanners
  - Aggregated results from all scanners
  - Standardized output format

### 2. Real-time Scanning Progress (`tasks.py`, `app.py`)

Sistem pelacakan progres scanning secara real-time:

- **Progress Callback System**: 
  - Setiap tahap scanning mengirim update progress
  - Persentase completion (0-100%)
  - Activity description untuk setiap tahap

- **Real-time Log**:
  - Menyimpan log aktivitas scanning
  - Timestamp untuk setiap event
  - Maximum 100 entries per scan (auto-rotate)

- **WebSocket Integration**:
  - Client subscription ke scan job tertentu
  - Broadcast progress ke semua subscribed clients
  - Rooms-based isolation per scan job

### 3. Database Enhancement (`models.py`)

Tambahan field pada model `ScanJob`:

```python
external_scanners_used = db.Column(db.JSON, default=list)
realtime_log = db.Column(db.JSON, default=list)
```

### 4. API Enhancement (`app.py`)

New endpoint parameter:
```json
POST /api/scan/start
{
  "url": "https://target.com",
  "mode": "safe",
  "use_external_scanners": true  // NEW
}
```

WebSocket events:
- `subscribe_scan` - Subscribe to scan progress
- `unsubscribe_scan` - Unsubscribe from scan
- `scan_progress` - Real-time progress broadcast

## Cara Penggunaan

### Mengaktifkan External Scanners

```javascript
// Frontend example
fetch('/api/scan/start', {
  method: 'POST',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({
    url: 'https://example.com',
    mode: 'safe',
    use_external_scanners: true  // Enable Nuclei & Nikto
  })
});
```

### Real-time Progress via WebSocket

```javascript
// Connect to WebSocket
const socket = io();

// Subscribe to scan progress
socket.emit('subscribe_scan', {job_id: 'scan-123'});

// Listen for progress updates
socket.on('scan_progress', (data) => {
  console.log(`Progress: ${data.progress.percentage}%`);
  console.log(`Activity: ${data.progress.activity}`);
  
  // Update UI
  document.getElementById('progress-bar').style.width = 
    data.progress.percentage + '%';
  document.getElementById('activity-log').innerHTML += 
    `<p>${data.progress.timestamp}: ${data.progress.activity}</p>`;
});
```

### Manual Plugin Usage

```python
from modules.external_scanners import get_plugin_manager

# Get plugin manager
pm = get_plugin_manager()

# Check available scanners
print(pm.get_available_plugins())  # ['Nuclei', 'Nikto']

# Run specific plugin
nuclei = pm.get_plugin('Nuclei')
nuclei.set_severity_filter(['critical', 'high'])
results = nuclei.scan('https://target.com', '/tmp/scan_output')

# Run all scanners
all_results = pm.run_all_scanners(
    target_url='https://target.com',
    output_dir='/tmp/scan_output',
    progress_callback=lambda data: print(data)
)
```

## Arsitektur

```
┌─────────────┐     ┌──────────────┐     ┌─────────────────┐
│   Frontend  │────▶│  Flask App   │────▶│   Celery Task   │
│  (WebSocket)│◀────│  (SocketIO)  │◀────│  (Background)   │
└─────────────┘     └──────────────┘     └─────────────────┘
                                                │
                          ┌─────────────────────┼─────────────────────┐
                          │                     │                     │
                   ┌──────▼──────┐      ┌──────▼──────┐      ┌──────▼──────┐
                   │   Internal  │      │   Nuclei    │      │    Nikto    │
                   │   Scanner   │      │   Plugin    │      │   Plugin    │
                   └─────────────┘      └─────────────┘      └─────────────┘
```

## Requirements Tambahan

Untuk menggunakan external scanners:

```bash
# Install Nuclei
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Install Nikto
git clone https://github.com/sullo/nikto.git
cd nikto/program && perl nikto.pl -Version
```

## File yang Dimodifikasi/Ditambahkan

| File | Status | Deskripsi |
|------|--------|-----------|
| `modules/external_scanners.py` | NEW | External scanner plugins |
| `modules/__init__.py` | NEW | Package initialization |
| `models.py` | MODIFIED | Added external_scanners_used, realtime_log fields |
| `tasks.py` | MODIFIED | External scanner integration, real-time logging |
| `app.py` | MODIFIED | WebSocket handlers, broadcast function |
| `modules/scanner.py` | MODIFIED | Progress callback support |

## Testing

```bash
# Test module imports
python -c "from modules.external_scanners import PluginManager; print('OK')"

# Test app initialization
python -c "from app import app; print('OK')"

# Run full application
python app.py
```

## Keamanan

- External scanners hanya dijalankan jika di-enable via API parameter
- Output scanner disimpan di temporary directory dan di-cleanup setelah selesai
- Real-time log dibatasi 100 entries untuk mencegah memory bloat
- WebSocket rooms memastikan isolasi antar scan job

## Future Enhancements

Potensi pengembangan selanjutnya:
- [ ] Support lebih banyak scanner (Burp Suite, OWASP ZAP)
- [ ] Custom template upload untuk Nuclei
- [ ] Scan scheduling dengan cron-like syntax
- [ ] Notification integration (Slack, Discord, Email)
- [ ] Comparative analysis between scanners
- [ ] Machine learning-based false positive reduction
