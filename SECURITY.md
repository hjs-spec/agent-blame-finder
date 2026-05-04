# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| 0.2.x alpha | ✅ |
| 0.1.x | Historical |

## Reporting a Vulnerability

Please do not report security vulnerabilities through public GitHub issues.

Email: signal@humanjudgment.org

## Scope

Relevant issues include:

- event signature bypass;
- event hash tampering;
- unsafe log handling;
- accidental data leakage;
- insecure evidence reference handling;
- dependency chain manipulation.

## Boundary

Agent Blackbox records local runtime trace artifacts.

It does not provide authorization, sandboxing, legal compliance, or complete-log guarantees.
