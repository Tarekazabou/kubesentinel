# KubeSentinel AI Server Architecture & Decision-Making Logic

## Executive Summary

The AI server uses a **hybrid decision-making architecture** combining:
1. **Isolation Forest ML model** for behavioral anomaly detection
2. **Rule-based fallback** when AI service is unavailable
3. **Incremental learning** through baseline training on normal events
4. **Gemini LLM enrichment** for incident explanation and recommendations

---

## 1. HIGH-LEVEL DATA FLOW

```
┌──────────────────┐
│   Falco Events   │ (Runtime security events from kernel)
└────────┬─────────┘
         │
         ▼
┌──────────────────────────────────┐
│ Go Monitor (Webhook Receiver)   │
│ - Listens on :8080               │
│ - Filters events by namespace   │
└────────┬─────────────────────────┘
         │
         ▼
┌────────────────────────────────────────┐
│ Event Processor (Go)                   │
│ - Feature Extraction                   │
│ - Worker Pool (4 goroutines)           │
│ - Decides: Normal vs Anomaly           │
└────────┬──────────────┬────────────────┘
         │              │
    Normal             Anomaly
      │                  │
      ▼                  ▼
┌──────────────┐    ┌─────────────────────┐
│ Buffer for   │    │ Store to Forensics  │
│ Model       │    │ Vault               │
│ Training     │    │ (JSON files)        │
└──────────────┘    └────────┬────────────┘
                             │
                             ▼
                    ┌──────────────────────┐
                    │ Dashboard            │
                    │ (Polls every 15 sec) │
                    │ Displays incidents   │
                    └──────────────────────┘
```

---

## 2. AI DECISION-MAKING PIPELINE

### Phase 1: Warm-up (First N Minutes)

**Duration**: Configured via `WARMUP_THRESHOLD` (default: 50 samples or 1 minute in Go)

**Behavior**:
- All events treated as **normal** (risk_score = 0.0)
- Features collected into a buffer
- Model retrains every 50 normal events
- Goal: Build accurate baseline of normal behavior

**Code Location**: `internal/runtime/processor.go` (lines 284-310)

```go
if !ep.warmupComplete.Load() {
    // All events treated as normal during warm-up
    aiVec := ep.toAIFeatureVector(features, event)
    ep.bufferMu.Lock()
    if len(ep.normalBuffer) < 200 {
        ep.normalBuffer = append(ep.normalBuffer, aiVec)
    }
    ep.bufferMu.Unlock()
    return ProcessedEvent{Anomaly: false, RiskScore: 0.0}
}
```

### Phase 2: Active Detection (After Warm-up)

**Trigger**: Warm-up timer expires OR 50+ samples collected

**Process**:
```
Event → Feature Extraction → AI Client Call → Risk Score Calculation
                                    ↓
                            ┌─────────┴─────────┐
                            │                   │
                        AI Available      AI Unavailable
                            │                   │
                            ▼                   ▼
                   ┌────────────────┐    ┌──────────────┐
                   │ Isolation      │    │ Rule-Based   │
                   │ Forest Score   │    │ Fallback     │
                   │ (0.0 - 1.0)    │    │ Scoring      │
                   └────────┬───────┘    └──────┬───────┘
                            │                   │
                            └─────────┬─────────┘
                                      ▼
                            ┌──────────────────┐
                            │ Risk Score >= 0.5│ (is_anomaly)
                            └──────────────────┘
```

---

## 3. FEATURE EXTRACTION

### Extracted Features (8 total)

| Feature | Type | Description | Source |
|---------|------|-------------|--------|
| `process_frequency` | int | How many processes spawned | Falco event analysis |
| `file_access_count` | int | Number of file operations | Syscall counting |
| `network_count` | int | Network connections made | Socket events |
| `sensitive_files` | int | Access to /etc, /root, etc | Path matching |
| `time_of_day` | int | Hour (0-23) | Event timestamp |
| `day_of_week` | int | Day (0-6) | Event timestamp |
| `container_age` | int | Minutes since container start | Metadata |
| `unique_syscalls` | int | Count of unique system calls | Syscall tracking |

**Code**: `internal/runtime/processor.go` → `FeatureExtractor.Extract()`

### Behavioral Features (Extended Context)

```go
type BehavioralFeatures struct {
    ProcessName       string          // e.g., "bash", "nginx"
    ProcessFrequency  int             // # processes in window
    SyscallCount      map[string]int  // {"open": 45, "read": 120}
    FileAccessCount   int             // # file operations
    NetworkConnCount  int             // # network connections
    SensitiveFiles    []string        // ["/etc/shadow", "/root/.ssh"]
    CommandLine       string          // Full command execution
    ParentProcess     string          // Parent process name
    UserID            string          // UID running process
    TimeOfDay         int             // Hour (0-23)
    DayOfWeek         int             // Day of week (0-6)
    ContainerID       string          // Container identifier
    Namespace         string          // K8s namespace
    PodName           string          // Pod name
    ContainerAge      int             // Minutes since start
}
```

---

## 4. AI SERVICE ARCHITECTURE (Python Flask)

### Components

```
┌────────────────────────────────────┐
│ Flask Application                  │
│ (ai-module/server.py)              │
├────────────────────────────────────┤
│ ┌──────────────────────────────────┤
│ │ AnomalyDetector Class            │
│ ├──────────────────────────────────┤
│ │ • IsolationForest model          │
│ │ • StandardScaler (normalization) │
│ │ • Warm-up phase management       │
│ │ • Incremental training           │
│ └──────────────────────────────────┤
├────────────────────────────────────┤
│ ┌──────────────────────────────────┤
│ │ Endpoints                        │
│ ├──────────────────────────────────┤
│ │ POST   /predict        (predict) │
│ │ POST   /train          (retrain) │
│ │ GET    /health         (health)  │
│ │ GET    /warmup/status  (status)  │
│ │ GET    /api/incidents  (display) │
│ └──────────────────────────────────┤
├────────────────────────────────────┤
│ ┌──────────────────────────────────┤
│ │ Enrichment Layer                 │
│ ├──────────────────────────────────┤
│ │ • Gemini LLM integration         │
│ │ • Rate limiting (25/min)         │
│ │ • Explanation generation         │
│ │ • Recommendation generation      │
│ └──────────────────────────────────┤
└────────────────────────────────────┘
```

### API Endpoints

#### 1. `/predict` (POST) - Core Decision Endpoint

**Purpose**: Anomaly detection for a single event

**Request**:
```json
{
  "features": {
    "process_frequency": 2,
    "file_access_count": 45,
    "network_count": 3,
    "sensitive_files": 0,
    "time_of_day": 14,
    "day_of_week": 2,
    "container_age": 120,
    "unique_syscalls": 52
  }
}
```

**Response**:
```json
{
  "is_anomaly": false,
  "score": 0.28,
  "confidence": 0.15,
  "reason": "Behavior matches normal baseline patterns",
  "suggestions": []
}
```

**Decision Logic**:
- Score is normalized to [0.0, 1.0]
- `is_anomaly = score >= 0.5` (configurable threshold)
- Confidence = distance from decision boundary

**Code**: `ai-module/server.py` lines 425-446

#### 2. `/train` (POST) - Model Retraining

**Purpose**: Update model with new normal baseline data

**Request**:
```json
{
  "training_data": [
    {
      "process_frequency": 1,
      "file_access_count": 30,
      ...
    },
    ...
  ]
}
```

**Response**:
```json
{
  "status": "success",
  "samples": 50,
  "timestamp": "2026-05-05T10:30:00Z"
}
```

**Code**: `ai-module/server.py` lines 500-515

#### 3. `/api/incidents` (GET) - Retrieve Stored Incidents

**Purpose**: Dashboard data source

**Response**:
```json
{
  "incidents": [
    {
      "id": "incident_abc123",
      "timestamp": "2026-05-05T10:30:00Z",
      "incident_type": "Suspicious Process",
      "severity": "high",
      "risk_score": 85,
      "description": "Unexpected bash process in nginx container",
      "container_name": "nginx",
      "pod_name": "web-server-1",
      "ai_analysis": "Access to /etc/shadow detected from nginx container",
      "related_events": 5
    }
  ],
  "total": 42,
  "using_gemini_enrichment": true
}
```

**Data Source**: Reads from `forensics/*.json` files

**Code**: `ai-module/server.py` lines 560-620

---

## 5. ANOMALY DETECTION MODEL

### Algorithm: Isolation Forest

**Why Isolation Forest?**
- Unsupervised (no labeled anomalies needed)
- Efficient (sub-linear complexity)
- Effective for high-dimensional data
- Scalable to streaming data

**Model Configuration**:
```python
IsolationForest(
    contamination=0.1,        # Expect ~10% anomalies
    random_state=42,          # Reproducible
    n_estimators=100,         # 100 decision trees
    max_samples='auto',       # Auto sample size
    max_features=1.0          # Use all features
)
```

### Training Pipeline

**1. Initialization**:
- Try loading from `ai-module/models/baseline.pkl`
- If not found or degenerate:
  - Load `ai-module/models/normal_baseline.csv` (real normal data)
  - OR create synthetic bootstrap data if CSV unavailable

**2. Cold-Start Bootstrap Data**:
```python
# Generate synthetic but realistic normal behavior
process_frequency ~ Poisson(λ=8)
file_access_count ~ Normal(μ=35, σ=15)
network_count ~ Poisson(λ=6)
sensitive_files ~ Binomial(n=2, p=0.05)
time_of_day ~ Uniform(0, 24)
day_of_week ~ Uniform(0, 7)
container_age ~ Exponential(λ=48)
unique_syscalls ~ Poisson(λ=50)
```

**3. Incremental Learning**:
- Warm-up phase: collect first 50+ normal events
- Every 2 minutes: retrain on buffered normal events
- Events with score < 0.3 added to training buffer

**Code**: `ai-module/server.py` lines 82-200

### Scoring

**Raw Score** (from Isolation Forest):
- Negative scores indicate anomalies
- Range: typically [-1.0, 0.1]

**Normalized Score** (0.0 - 1.0):
```python
normalized_score = np.clip(-raw_score * 2, 0.0, 1.0)
```

**Examples**:
- Raw: -0.5 → Normalized: 1.0 (strong anomaly)
- Raw: -0.1 → Normalized: 0.2 (slight anomaly)
- Raw: 0.0 → Normalized: 0.0 (normal)

---

## 6. RULE-BASED FALLBACK

When AI service is unavailable, uses deterministic rules:

```go
func (p *EventProcessor) calculateRisk(event SecurityEvent, features BehavioralFeatures) float64 {
    score := 0.0

    // Rule 1: Explicit malicious commands
    if strings.Contains(features.CommandLine, "cat /etc/shadow") {
        score += 0.8
    }

    // Rule 2: Access to sensitive files
    if len(features.SensitiveFiles) > 0 {
        score += 0.5
    }

    // Rule 3: Root user in system namespaces
    if features.UserID == "0" && event.Container.Namespace == "kube-system" {
        score += 0.2
    }

    if score > 1.0 {
        score = 1.0
    }
    return score
}
```

---

## 7. FORENSIC STORAGE

### Incident JSON Format

When an anomaly is detected (risk_score >= 0.5), stored as:

```json
{
  "id": "incident_1234567890_timestamp",
  "timestamp": "2026-05-05T10:30:45Z",
  "incident_type": "Suspicious Process Execution",
  "severity": "high",
  "risk_score": 0.85,
  "description": "Suspicious bash invocation",
  "container": {
    "id": "abc123def456",
    "name": "nginx-container",
    "pod_name": "web-server-1",
    "namespace": "production"
  },
  "metadata": {
    "process_name": "bash",
    "process_frequency": 2,
    "file_access_count": 45,
    "network_count": 3,
    "sensitive_files": 1,
    "time_of_day": 14,
    "day_of_week": 2,
    "container_age": 120,
    "unique_syscalls": 52,
    "gemini_reason": "Unauthorized shell access detected..."
  },
  "events": [
    {
      "timestamp": "2026-05-05T10:30:45Z",
      "rule": "Unauthorized Privileged Container",
      "output": "Spawned shell in unprivileged container"
    }
  ]
}
```

**Storage Path**: `/app/forensics/` (mounted in containers)

**File Naming**: `incident_<container_id>_<timestamp>.json`

---

## 8. GEMINI LLM ENRICHMENT (Optional)

### Purpose
Generate human-readable explanations and recommendations

### Workflow
```
Incident Detected
       ↓
   Check ENRICH_WITH_GEMINI env var
       ↓
   ┌─────────────────────────────┐
   │ Is Gemini API available?    │
   └──────┬──────────────────────┘
          │
    ┌─────┴─────┐
   YES          NO
    │            └→ Use default explanation
    ▼
Rate Limit Check (25 calls/min)
    │
    ├→ Under limit: Call Gemini
    │              ↓
    │         Generate explanation
    │              ↓
    │         Store in incident["ai_analysis"]
    │
    └→ Over limit: Skip enrichment
```

### Rate Limiting
- 25 calls per minute (sliding window)
- Deque-based tracking
- Thread-safe with lock

**Code**: `ai-module/server.py` lines 72-90

---

## 9. DECISION THRESHOLDS

| Threshold | Value | Meaning |
|-----------|-------|---------|
| Anomaly Detection | score >= 0.5 | Mark as anomaly |
| Normal Baseline Buffer | score < 0.3 | Add to training |
| Model Degenerate | >70% anomalies | Rebuild model |
| Contamination Rate | 10% | Expected anomaly ratio |
| Warm-up Complete | 50 samples collected | OR 1 minute passed |

---

## 10. CONCURRENCY & PERFORMANCE

### Go Service (Event Processing)

**Worker Pool Model**:
- 4 worker goroutines (default, configurable)
- Non-blocking event channel (10k buffer)
- Lock-free metrics using atomic operations
- Feature extraction happens per-worker

**Performance**:
- ~50,000 events/second throughput
- <2 second AI latency (with retry logic)
- Fallback to rule-based scoring on AI timeout

**Concurrency Safe**:
```go
atomic.AddInt64(&ep.Metrics.AnomaliesDetected, 1)  // Lock-free counter
```

### Python Service (Flask)

**Thread Safety**:
- Detector lock for model access
- Rate limiter lock for Gemini calls
- Pickle-based model serialization

**Scaling**:
- Single threaded by default
- Can deploy behind Gunicorn for multi-process
- Docker: 1 container per pod

---

## 11. ERROR HANDLING & FALLBACKS

### When AI Service Fails

```go
// Go Service → AI Client → Flask Service
    ↓ (timeout or error)
  Retry 3 times with exponential backoff (200ms, 400ms, 600ms)
    ↓ (all retries failed)
  Fall back to calculateRisk() (rule-based)
    ↓
  Log error metrics
```

**Retry Logic**:
```go
const maxRetries = 3
for attempt := 0; attempt < maxRetries; attempt++ {
    if attempt > 0 {
        time.Sleep(time.Duration(attempt*200) * time.Millisecond)
    }
    resp, err := c.HTTPClient.Do(req)
    if err == nil {
        return resp, nil
    }
}
```

---

## 12. METRICS & MONITORING

### ProcessorMetrics (Go)

```go
type ProcessorMetrics struct {
    TotalEvents       int64  // All events received
    ProcessedEvents   int64  // Successfully processed
    AnomaliesDetected int64  // Marked as anomalous
    ErrorCount        int64  // Processing errors
    AICalls           int64  // Successful AI calls
}
```

### Available Endpoints

- `/health` - Service health
- `/warmup/status` - Model warm-up progress
- `/api/diagnostics` - Deployment diagnostics
- `/model/info` - Model configuration

---

## 13. DECISION FLOW SUMMARY

```
┌─────────────────────────────────────────────────────────────┐
│ 1. Event arrives from Falco                                 │
└────────────────────┬────────────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────────────┐
│ 2. Extract 8 behavioral features                            │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ├─────────────────┬─────────────────┐
                     │                 │                 │
           ┌─────────▼────────┐  ┌────▼─────────┐  ┌───▼──────────┐
           │ Warm-up Phase?   │  │ AI Available?│  │ Rule-Based?  │
           └──────┬───────────┘  └───┬──────────┘  └────┬─────────┘
                  │                  │                  │
            YES   │ NO              YES│ NO             │
                  │ │                   │                │
                  │ │    ┌──────────────┘                │
                  │ │    │                               │
         ┌─────────▼─▼────▼──┐     ┌────────────────────▼──┐
         │ Isolation Forest   │     │ Rule-Based Scoring   │
         │ Model              │     │ - Sensitive files    │
         │ Score: [0.0-1.0]   │     │ - Malicious commands │
         │                    │     │ - Root in sys ns     │
         └────────┬───────────┘     └────────┬─────────────┘
                  │                          │
                  │    ┌─────────────────────┘
                  │    │
                  ▼    ▼
            ┌──────────────────┐
            │ Risk Score >= 0.5?│
            └─────┬────────┬───┘
                  │        │
              YES │        │ NO
                  │        │
           ┌──────▼─┐  ┌───▼──────┐
           │ANOMALY │  │ NORMAL   │
           └────┬───┘  └────┬─────┘
                │           │
                │           └─→ Buffer for training
                │
                └─→ Store forensic record
                    │
                    ├─→ Gemini enrichment (if enabled)
                    │
                    └─→ Display in dashboard
```

---

## 14. CONFIGURATION PARAMETERS

### Go Service (Monitor Webhook)

```yaml
ai:
  endpoint: "http://localhost:5000"
```

### Python AI Service

**Environment Variables**:
```bash
CORS_ALLOWED_ORIGINS=http://localhost:5000,http://127.0.0.1:5000
ENRICH_WITH_GEMINI=true                    # Enable LLM enrichment
GEMINI_API_KEY=<your-key>                 # Gemini API key
GEMINI_RATE_LIMIT_PER_MINUTE=25           # Rate limiting
WARMUP_THRESHOLD=50                        # Warm-up sample count
TRAINING_API_TOKEN=<token>                 # Protected endpoints
```

---

## 15. CURRENT LIMITATIONS & DESIGN NOTES

### Limitations

1. **Single-Model Approach**: One global model for all containers
   - Doesn't account for different container behaviors
   - False positives on long-running containers

2. **File-Based Storage**: No database persistence
   - All forensics stored as JSON files
   - Queries require loading all files into memory
   - No indexing, poor query performance

3. **Polling Dashboard**: Not real-time
   - Refreshes every 15 seconds
   - Delays in incident visibility

4. **No Model Versioning**: Single baseline model
   - Can't A/B test new models
   - No rollback capability

5. **Memory-Bound Training**: 200-sample buffer limit
   - Limited historical context for retraining

### Design Decisions

1. **Isolation Forest over Neural Networks**: 
   - Faster inference, simpler deployments, better for anomaly detection

2. **Warm-up Phase**: 
   - Prevents false positives on cold-start

3. **Fallback Rules**: 
   - Guarantees decisions even if AI service fails

4. **Gemini Integration Optional**: 
   - Can run without LLM enrichment

---

## 16. RECOMMENDED CHANGES FOR YOUR REDESIGN

Based on the current architecture, here are areas ripe for enhancement:

### High Priority
1. **Database Persistence** (SQLite or PostgreSQL)
   - Store incidents with indexing
   - Enable historical trend analysis
   - Support complex queries

2. **Per-Container Models**
   - Different models for different deployment types
   - Container-specific baselines

3. **Real-Time WebSocket**
   - Replace polling with push notifications
   - Instant incident visibility

### Medium Priority
4. **Model Versioning & A/B Testing**
   - Compare multiple models
   - Gradual rollouts

5. **Advanced Feature Engineering**
   - Time-series features
   - Contextual features (labels, annotations)
   - Custom business rules

### Low Priority
6. **Ensemble Voting**
   - Multiple model types (Isolation Forest + LOF + Autoencoder)
   - Consensus-based decisions

7. **Federated Learning**
   - Distributed model training
   - Privacy-preserving analysis

---

This architecture overview should give you a solid foundation for redesigning the AI decision-making pipeline. Do you want me to elaborate on any specific component or help with the redesign?
