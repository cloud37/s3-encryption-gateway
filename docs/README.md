# Documentation

This directory contains comprehensive documentation for the S3 Encryption Gateway.

## Getting Started

- **[DEVELOPMENT_GUIDE.md](DEVELOPMENT_GUIDE.md)** - Complete development setup, coding guidelines, and configuration schema
- **[DEPLOYMENT.md](DEPLOYMENT.md)** - Docker and Kubernetes deployment instructions
- **[ARCHITECTURE.md](ARCHITECTURE.md)** - System architecture and design decisions

## Technical Documentation

- **[ENCRYPTION_DESIGN.md](ENCRYPTION_DESIGN.md)** - Detailed encryption system design and implementation
- **[S3_API_IMPLEMENTATION.md](S3_API_IMPLEMENTATION.md)** - S3 API compatibility and implementation strategy
- **[KMS_COMPATIBILITY.md](KMS_COMPATIBILITY.md)** - Key Management Service integration guide

## Architecture Decision Records (ADRs)

- **[ADR 0001: Range Optimization Design](adr/0001-range-optimization-design.md)** - Design decisions for range-optimized decryption
- **[ADR 0002: Multipart Upload Security Validation](adr/0002-multipart-upload-interoperability.md)** - XML validation and interoperability decisions for multipart uploads

## Diagrams

- **[Range Optimization Flow](diagrams/range-optimization.svg)** - Visual explanation of range request optimization
- **[Multipart Upload Flow](diagrams/multipart-upload-flow.svg)** - Multipart request validation flow; encryption behavior is documented in [ADR 0009](adr/0009-encrypted-multipart-uploads.md)

## Security & Operations

- **[SECURITY_AUDIT.md](SECURITY_AUDIT.md)** - STRIDE threat model, security hardening guide, and audit recommendations

## Planning

- **[ROADMAP.md](ROADMAP.md)** - Future improvements and milestones
