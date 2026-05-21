package audit

import (
	"fmt"
	"sync"
	"time"

	"github.com/kenchrcum/s3-encryption-gateway/internal/config"
)

// EventType represents the type of audit event.
type EventType string

const (
	// EventTypeEncrypt represents an encryption operation.
	EventTypeEncrypt EventType = "encrypt"
	// EventTypeDecrypt represents a decryption operation.
	EventTypeDecrypt EventType = "decrypt"
	// EventTypeKeyRotation represents a key rotation operation.
	EventTypeKeyRotation EventType = "key_rotation"
	// EventTypeAccess represents an access operation.
	EventTypeAccess EventType = "access"

	// V0.6-SEC-3 MPU audit event types.
	EventTypeMPUCreate         EventType = "mpu.create"
	EventTypeMPUPart           EventType = "mpu.part"
	EventTypeMPUComplete       EventType = "mpu.complete"
	EventTypeMPUAbort          EventType = "mpu.abort"
	EventTypeMPUTamperDetected EventType = "mpu.tamper_detected"
	EventTypeMPUValkeyUnavail  EventType = "mpu.valkey_unavailable"

	// V0.6-PERF-2 — backend retry audit event type (ADR 0010).
	// Emitted when a data-plane write operation exhausts all retry attempts.
	// Read-path give-ups are counter-only (too chatty under normal backend hiccups).
	EventTypeBackendRetryGiveUp EventType = "backend.retry_give_up"

	// V0.6-OBS-1 — pprof audit event type.
	// Emitted on every profile fetch via the admin /debug/pprof/* endpoints.
	// Satisfies Adkins et al., BSRS Ch. 15 "auditable debug interface" mandate.
	EventTypePprofFetch EventType = "pprof_fetch"
)

// AuditEvent represents a single audit log event.
type AuditEvent struct {
	Timestamp  time.Time              `json:"timestamp"`
	EventType  EventType              `json:"event_type"`
	Operation  string                 `json:"operation"`
	Bucket     string                 `json:"bucket,omitempty"`
	Key        string                 `json:"key,omitempty"`
	ClientIP   string                 `json:"client_ip,omitempty"`
	UserAgent  string                 `json:"user_agent,omitempty"`
	RequestID  string                 `json:"request_id,omitempty"`
	Algorithm  string                 `json:"algorithm,omitempty"`
	KeyVersion int                    `json:"key_version,omitempty"`
	Success    bool                   `json:"success"`
	Error      string                 `json:"error,omitempty"`
	Duration   time.Duration          `json:"duration_ms"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
}

// Logger is the interface for audit logging.
type Logger interface {
	// Log logs an audit event.
	Log(event *AuditEvent) error

	// LogEncrypt logs an encryption operation.
	LogEncrypt(bucket, key, algorithm string, keyVersion int, success bool, err error, duration time.Duration, metadata map[string]interface{})

	// LogDecrypt logs a decryption operation.
	LogDecrypt(bucket, key, algorithm string, keyVersion int, success bool, err error, duration time.Duration, metadata map[string]interface{})

	// LogKeyRotation logs a key rotation operation.
	LogKeyRotation(keyVersion int, success bool, err error)

	// LogAccess logs a general access operation.
	LogAccess(eventType, bucket, key, clientIP, userAgent, requestID string, success bool, err error, duration time.Duration)

	// LogAccessWithMetadata logs a general access operation including a
	// structured metadata map (e.g. source bucket/key/mode for copy
	// operations). The metadata is subject to the logger's redaction list.
	LogAccessWithMetadata(eventType, bucket, key, clientIP, userAgent, requestID string, success bool, err error, duration time.Duration, metadata map[string]interface{})

	// GetEvents returns all audit events (for testing/querying).
	GetEvents() []*AuditEvent

	// Close closes the logger and its underlying writer.
	Close() error
}

// auditLogger implements the Logger interface.
type auditLogger struct {
	mu         sync.Mutex
	events     []*AuditEvent
	maxEvents  int
	writer     EventWriter
	redactKeys []string
}

// EventWriter is an interface for writing audit events.
type EventWriter interface {
	WriteEvent(event *AuditEvent) error
}

// NewLogger creates a new audit logger.
func NewLogger(maxEvents int, writer EventWriter) Logger {
	return NewLoggerWithRedaction(maxEvents, writer, nil)
}

// NewLoggerWithRedaction creates a new audit logger with redaction keys.
func NewLoggerWithRedaction(maxEvents int, writer EventWriter, redactKeys []string) Logger {
	if writer == nil {
		writer = &StdoutSink{}
	}

	return &auditLogger{
		events:     make([]*AuditEvent, 0, maxEvents),
		maxEvents:  maxEvents,
		writer:     writer,
		redactKeys: redactKeys,
	}
}

// NewLoggerFromConfig creates a new audit logger from configuration.
func NewLoggerFromConfig(cfg config.AuditConfig) (Logger, error) {
	var writer EventWriter

	if !cfg.Enabled {
		// If disabled, we still return a logger but maybe with a dummy writer or handle it upstream.
		// For now, create default writer if enabled is false but this function is called?
		// Or rely on caller.
	}

	switch cfg.Sink.Type {
	case "http":
		// V1.0-SEC-8 — use hardened HTTP sink with configurable transport settings
		writer = NewHTTPSinkWithConfig(cfg.Sink.Endpoint, cfg.Sink.Headers, cfg.Sink.HTTP, cfg.Sink.TLS)
	case "file":
		// V1.0-SEC-26: default to 0600; honour operator-supplied FileMode when non-zero.
		if cfg.Sink.FileMode != 0 {
			writer = NewFileSinkWithMode(cfg.Sink.FilePath, cfg.Sink.FileMode)
		} else {
			writer = NewFileSink(cfg.Sink.FilePath)
		}
	case "stdout", "":
		writer = &StdoutSink{}
	default:
		return nil, fmt.Errorf("unknown sink type: %s", cfg.Sink.Type)
	}

	// Wrap with batch sink if configured
	if cfg.Sink.BatchSize > 0 || cfg.Sink.FlushInterval > 0 {
		// Default values handled in NewBatchSink if 0
		writer = NewBatchSink(writer, cfg.Sink.BatchSize, cfg.Sink.FlushInterval, cfg.Sink.RetryCount, cfg.Sink.RetryBackoff, cfg.Sink.MaxConcurrentFlushes)
	}

	return NewLoggerWithRedaction(cfg.MaxEvents, writer, cfg.RedactMetadataKeys), nil
}

// Log logs an audit event.
func (l *auditLogger) Log(event *AuditEvent) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Redact sensitive metadata before persisting or dispatching.
	// This ensures every path — including direct Log(event) calls —
	// honours the configured redaction list. V1.0-SEC-C01.
	event.Metadata = l.redactMetadata(event.Metadata)

	// Write to external writer if available
	if l.writer != nil {
		if err := l.writer.WriteEvent(event); err != nil {
			// Log error but don't fail
			// In production, you might want to handle this differently
		}
	}

	// Store in memory buffer
	l.events = append(l.events, event)

	// Maintain max events limit
	if len(l.events) > l.maxEvents {
		l.events = l.events[len(l.events)-l.maxEvents:]
	}

	return nil
}

// Close closes the logger and its underlying writer.
func (l *auditLogger) Close() error {
	if closer, ok := l.writer.(interface{ Close() error }); ok {
		return closer.Close()
	}
	return nil
}

// redactMetadata removes sensitive keys from metadata.
func (l *auditLogger) redactMetadata(metadata map[string]interface{}) map[string]interface{} {
	if len(l.redactKeys) == 0 || len(metadata) == 0 {
		return metadata
	}

	// Check if any key needs redaction
	needsRedaction := false
	for _, k := range l.redactKeys {
		if _, ok := metadata[k]; ok {
			needsRedaction = true
			break
		}
	}

	if !needsRedaction {
		return metadata
	}

	// Shallow copy
	clone := make(map[string]interface{}, len(metadata))
	for k, v := range metadata {
		clone[k] = v
	}

	for _, key := range l.redactKeys {
		if _, ok := clone[key]; ok {
			clone[key] = "[REDACTED]"
		}
	}
	return clone
}

// LogEncrypt logs an encryption operation.
func (l *auditLogger) LogEncrypt(bucket, key, algorithm string, keyVersion int, success bool, err error, duration time.Duration, metadata map[string]interface{}) {
	event := &AuditEvent{
		Timestamp:  time.Now(),
		EventType:  EventTypeEncrypt,
		Operation:  "encrypt",
		Bucket:     bucket,
		Key:        key,
		Algorithm:  algorithm,
		KeyVersion: keyVersion,
		Success:    success,
		Duration:   duration,
		Metadata:   l.redactMetadata(metadata),
	}

	if err != nil {
		event.Error = err.Error()
	}

	l.Log(event)
}

// LogDecrypt logs a decryption operation.
func (l *auditLogger) LogDecrypt(bucket, key, algorithm string, keyVersion int, success bool, err error, duration time.Duration, metadata map[string]interface{}) {
	event := &AuditEvent{
		Timestamp:  time.Now(),
		EventType:  EventTypeDecrypt,
		Operation:  "decrypt",
		Bucket:     bucket,
		Key:        key,
		Algorithm:  algorithm,
		KeyVersion: keyVersion,
		Success:    success,
		Duration:   duration,
		Metadata:   l.redactMetadata(metadata),
	}

	if err != nil {
		event.Error = err.Error()
	}

	l.Log(event)
}

// LogKeyRotation logs a key rotation operation.
func (l *auditLogger) LogKeyRotation(keyVersion int, success bool, err error) {
	event := &AuditEvent{
		Timestamp:  time.Now(),
		EventType:  EventTypeKeyRotation,
		Operation:  "key_rotation",
		KeyVersion: keyVersion,
		Success:    success,
	}

	if err != nil {
		event.Error = err.Error()
	}

	l.Log(event)
}

// LogAccess logs a general access operation.
func (l *auditLogger) LogAccess(eventType, bucket, key, clientIP, userAgent, requestID string, success bool, err error, duration time.Duration) {
	l.LogAccessWithMetadata(eventType, bucket, key, clientIP, userAgent, requestID, success, err, duration, nil)
}

// LogAccessWithMetadata logs a general access operation with structured metadata.
func (l *auditLogger) LogAccessWithMetadata(eventType, bucket, key, clientIP, userAgent, requestID string, success bool, err error, duration time.Duration, metadata map[string]interface{}) {
	event := &AuditEvent{
		Timestamp: time.Now(),
		EventType: EventType(eventType),
		Operation: eventType,
		Bucket:    bucket,
		Key:       key,
		ClientIP:  clientIP,
		UserAgent: userAgent,
		RequestID: requestID,
		Success:   success,
		Duration:  duration,
		Metadata:  l.redactMetadata(metadata),
	}

	if err != nil {
		event.Error = err.Error()
	}

	l.Log(event)
}

// GetEvents returns all audit events (for testing/querying).
func (l *auditLogger) GetEvents() []*AuditEvent {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Return a copy to prevent external modifications
	events := make([]*AuditEvent, len(l.events))
	copy(events, l.events)
	return events
}


