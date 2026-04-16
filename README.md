# 🚀 Agent Blame-Finder

### *"Find out which Agent messed up in 3 seconds."*

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python](https://img.shields.io/badge/python-3.9+-blue.svg)](https://pypi.org/)
[![Rust](https://img.shields.io/badge/core-rust-orange.svg)](https://www.rust-lang.org/)

---

## 🧐 What is this?

When your Multi-Agent system breaks down, it usually goes like this:

- Agent A says: "Agent B gave me bad instructions"
- Agent B says: "I just followed Agent C's output"
- Agent C says: "I just passed data, not my problem"
- **You**: Digging through thousands of log lines, finding nothing

**Agent-Blackbox** solves this.

It installs a **"Black Box"** in every Agent that automatically records:
- Who made the decision
- Which parent output this decision was based on
- When it happened
- Cryptographic signature to prevent denial

When something breaks, just enter the incident hash — **3 seconds later, you know exactly who to blame.**

---

## ✨ Core Features

| Feature | Description |
|---------|-------------|
| **One-Click Blame Analysis** | Input incident ID, instantly locate the broken link in your responsibility chain |
| **Causality Tree Visualization** | Git-like tree showing your Agent decision chain |
| **Cryptographic Signatures** | Every decision gets an Ed25519 signature. No denial possible. |

---

## 🚀 30-Second Quick Start

### Installation

```bash
pip install agent-blame-finder
```

### Usage

```python
from blame_finder import BlameFinder

# Initialize the black box
finder = BlameFinder(storage="./logs")

@finder.trace(agent_name="Coder-Agent")
def write_code(requirement: str) -> str:
    # Your Agent logic here
    return "print('hello world')"

# Execute
result = write_code("write a hello world")

# When something breaks, find out who to blame
print(finder.blame(incident_id="task_123"))
```

### Sample Output

```json
{
  "incident": "task_123",
  "verdict": "Coder-Agent",
  "reason": "Input requirement was correct, but output didn't match expectations",
  "chain": [
    {"agent": "PM-Agent", "action": "Dispatch task", "status": "ok"},
    {"agent": "Coder-Agent", "action": "Write code", "status": "failed"},
    {"agent": "Verifier-Agent", "action": "Verify", "status": "not_reached"}
  ],
  "confidence": 0.94
}
```

---

## 🖥️ Visual Dashboard

```bash
blame-finder dashboard
```

Open your browser and see:

- **Causality Topology** — Who called whom, at a glance
- **Failed Nodes Highlighted in Red** — Problem agents stand out
- **Blame Share Pie Chart** — PM Agent takes 60% blame, Coder Agent 35%, Others 5%

---

## 📦 Supported Languages / Frameworks

| Language / Framework | SDK Status |
|----------------------|------------|
| Python | ✅ Available |
| TypeScript | ✅ Available |
| Rust | ✅ Core implemented |
| LangChain | 🚧 In development |
| CrewAI | 🚧 In development |

---

## 📅 Roadmap

- [x] Rust core engine
- [x] Python/TypeScript SDK
- [ ] LangChain official adapter
- [ ] CrewAI official adapter
- [ ] One-click PDF/HTML report export

---

## 🤝 Contributing

PRs welcome! Whether it's fixing bugs, improving docs, or adding features.

1. Fork the repo
2. Create your feature branch (`git checkout -b feature/amazing`)
3. Commit your changes (`git commit -m 'add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing`)
5. Open a Pull Request

---

## 📜 License

MIT © Agent Blame-Finder
