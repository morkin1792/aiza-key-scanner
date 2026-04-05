# 🔍 aiza-key-scanner
![Go Version](https://img.shields.io/badge/go-1.26+-00ADD8.svg?style=flat-square)
![License](https://img.shields.io/badge/license-MIT-green.svg?style=flat-square)

Check leaked Google API keys (`AIzaSy...`) and determine which Google APIs they can access. Collects non-destructive proof-of-concept data to demonstrate impact during bug bounty engagements.

## ✨ Checks

85 service checks across 7 categories:

| Category | Services |
|----------|----------|
| **GCP** | Resource Manager, Storage, Compute, SQL, DNS, Functions, Run, GKE, Pub/Sub, Spanner, Bigtable, Secret Manager, Logging, Monitoring, Tasks, Scheduler, Build, Artifact Registry, Firestore, BigQuery, Memorystore, Filestore, VPC Networks, Cloud Endpoints, Cloud Workflows, Source Repositories, Cloud KMS, Dataflow, Cloud Retail |
| **Firebase** | Auth Signup, Auth Providers, Realtime DB, Remote Config, Cloud Messaging, Hosting |
| **Maps & Geo** | Maps JS, Geocoding, Places, Directions, Distance Matrix, Elevation, Static Maps, Street View, Time Zone, Roads, Places Autocomplete, Places Details, Map Tiles, Embed, Solar, Air Quality, Address Validation, Routes API v2, Route Matrix, Pollen, Find Place |
| **AI & ML** | Gemini, Gemini Models, Gemini Files, Gemini Embeddings, Translation, Language Detection, Vision, NLP, Speech-to-Text, Text-to-Speech, Vertex AI, AutoML, Video Intelligence, Document AI |
| **Media** | YouTube Search/Channels/Analytics, Books, Fonts, Calendar, Drive, Sheets |
| **Search** | Custom Search |
| **Identity** | People API, reCAPTCHA Enterprise, IAP, Service Usage, IAM, Firebase App Check |

## 📦 Installation

```
go install github.com/morkin1792/aiza-key-scanner@latest
```

Or:

```
git clone https://github.com/morkin1792/aiza-key-scanner && cd aiza-key-scanner && go build -o aiza-key-scanner .
```

## 🛠️ Usage

```bash
cat gcp_keys.txt | aiza-key-scanner -s -o aiza.output.txt
```

### 🚩 Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-k` | | Single API key |
| `-f` | | File of newline-separated keys |
| `-p` | | Fallback GCP project ID |
| `-o` | | Output file — saves only key + vulnerable services (appends) |
| `-j` | | Full output file (JSONL format) |
| `-s` | `false` | Silent: print only the summary (nothing if `-o`/`-j` set) |
| `-categories` | | Comma-separated categories to check (e.g. `Maps,AI`) |
| `-v` | `false` | Print full raw JSON responses |
| `-w` | `5` | Worker pool size for concurrent key processing |
| `-timeout` | `10` | Per-request HTTP timeout in seconds |


## 📝 Output

```
══════════════════════════════════════════════════
KEY      : AIzaSyD9ab...mqKG8
PROJECT  : 
VULNERABLE SERVICES: 1

Maps     / Maps JavaScript API       | Maps JS loads successfully (billing abuse potential)
══════════════════════════════════════════════════

══════════════════════════════════════════════════
KEY      : AIzaSyCdRU...hf2Gk
PROJECT  : 
VULNERABLE SERVICES: 3

Maps     / Maps JavaScript API       | Maps JS loads successfully (billing abuse potential)
AI       / Gemini Models             | 50 models accessible: gemini-2.5-flash, gemini-2.5-pro, gemini-2.0-flash, gemini-2.0-flash-001, gemini-2.0-flash-lite-001, ...
AI       / Gemini Files API          | 0 uploaded files accessible (potential data leak)
══════════════════════════════════════════════════
```

