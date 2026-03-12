# CUA Front-Runner: An Automation & Security Testbed for Computer-Use Agents

This project provides a modular automation framework for testing, attacking, and defending Computer-Use Agents (CUAs) — agents that interact with real user interfaces via screenshots, OCR, reasoning, and tool execution.

The framework is designed to:

Plug into real CUA deployments (VMs, Docker containers, browser automation).

Observe agent behaviour through fine-grained execution traces.

Simulate timing- and context-based attacks (e.g. front-running, OCR-driven injection).

Enforce Information Flow Control (IFC) defences that constrain unsafe behaviour without killing agent utility.

This repository currently includes a front-running attack PoC targeting GitHub-based developer workflows, along with an IFC-based defence that detects and blocks unsafe actions once untrusted context is observed.

## Architecture Overview

The system is organised around four core components:

### 1. Orchestrator

The *orchestrator* is the control plane of the system. It:

* Launches and supervises the CUA process.
* Receives structured events describing agent actions, model outputs, OCR results, and environment state.
* Maintains global run state (e.g. current URL, taint status, attack triggers).
* Decides when to invoke attacker logic or enforce defences.

The orchestrator *does not modify the CUA itself* — all observation and control happens externally.


### 2. Computer-Use Agent (CUA)

The CUA is the agent under test. It can be:

* A Docker-based VM agent (as in the current demo).
* A browser-only agent (e.g. Playwright / Selenium).
* Any agent that emits observable actions (clicks, typing, screenshots).

To integrate a new CUA deployment, you only need to provide a thin adapter that:
* Starts the agent process.
* Streams stdout / trace output.
* Emits structured events for actions and tool calls.

> Example adapters:
> * VM-based CUAs → Docker + VNC + screenshot hooks
> * Browser agents → Playwright action listeners
> * Desktop automation → OS-level input hooks

#### Included Adapters

| Adapter | Module | Controls |
|---|---|---|
| **Docker VM** | `front_run.docker_control.DockerControl` | A Docker container running a full desktop environment (VNC / Xvfb). |
| **Playwright Browser** | `front_run.playwright_control.PlaywrightControl` | A headless (or headed) Chromium session managed by Playwright. |

Both adapters expose the same interface (`pause`, `unpause`, `is_running`, `is_paused`) so the orchestrator can swap between them with a single import change.

The Playwright adapter additionally provides:
* `current_url()` — the URL the CUA is currently viewing.
* `screenshot_b64()` — a base64-encoded viewport screenshot.
* `inject_element(html)` — inject arbitrary HTML into the page (useful for visual injection attack simulation).


### 3. Event Bus

All components communicate through a central event bus.

Events include:
* Model inference steps
* UI actions (click, type, keypress, wait)
* Screenshots and OCR text
* URL changes
* Attacker and defence decisions

This decoupled design allows:
* Multiple observers (attackers, defences, loggers) to react independently.
* Real-time attacks that “watch” the agent’s state without interfering directly.
* Post-hoc replay and analysis of full agent runs.


### 4. Attacker Agents

Attacks are implemented as *first-class agents* that listen to the same events as the defender.

The included PoC demonstrates a *front-running attack*:
* The attacker waits for the CUA to reach a specific UI state (GitHub Issues tab).
* It exploits OCR and/or model reasoning signals to infer agent intent.
* It injects a malicious comment into a GitHub issue just-in-time.
* The CUA unknowingly consumes and follows the injected guidance.

This attack can be extended to:
* Other websites and workflows.
* Multi-step toolchain attacks.
* Agent-to-agent (A2A) manipulation scenarios.


## Execution Tracing and Logging

Every run produces a complete structured trace, written to:
```bash
runs/<timestamp>/trace.jsonl
```

The trace records:
* All agent actions and tool calls.
* Model outputs (without accessing private chain-of-thought).
* OCR text extracted from screenshots.
* Attacker signals and triggers.
* Defence decisions and enforcement points.

This makes it possible to:
* Reconstruct _exactly what the agent saw and did_.
* Debug subtle timing and perception failures.
* Compare defended vs undefended runs side-by-side.


## Information Flow Control (IFC) Defence

The defence mechanism is based on Information Flow Control, implemented in two layers:

### 1. Propagation Logic (Generic)

The system tracks taint labels that represent whether the agent’s context has been influenced by untrusted sources.

Taint can originate from:
* OCR text from screenshots
* URLs visited by the agent
* External content injected mid-task

Taint *propagates forward* through agent state but does _not_ immediately halt execution.

### 2. Policy Logic (Customisable)

Policies decide what actions are allowed given the current taint state.

Key ideas:
* The agent may continue browsing and reading while tainted.
* *Sensitive actions* (e.g. posting externally, opening terminals, executing commands) are blocked once tainted.
* Trusted domains (e.g. `github.com`) can be whitelisted.
* Policies are scenario-specific and easy to replace.

This separation allows operators to:
* Define their own trust boundaries.
* Tune strictness without rewriting the core logic.
* Experiment with different security postures.


## Included Front-Running Attack Demo

The current PoC demonstrates:
* A CUA tasked with helping a developer on a GitHub repository.
* An attacker that front-runs the agent by injecting a malicious issue comment.
* A malicious site that abuses copy-to-clipboard behaviour.
* A successful compromise in the *undefended run*.
* A clean block of unsafe behaviour in the *defended run*, without breaking benign agent actions.

This attack is intentionally simple but highlights a broader class of *contextual and timing-based vulnerabilities* in agentic systems.


## Setup
### 1. Install Dependencies
```bash
conda env create -f env.yml
```

### 2. Configure Environment Variables

Create a .env file:
```bash
GITHUB_TOKEN=ghp_...              # repo:issues scope
TARGET_REPO=your-org/your-test-repo
MALICIOUS_URL=https://example.com/help
CUA_CONTAINER_NAME=cua-sample-app
CUA_CLI_PATH=/absolute/path/to/openai-cua-sample-app/cli.py
PAUSE_AFTER_SECONDS=25
VERBOSE=1
```

⚠️ Security reminder: Never commit .env files.

## Running the Demo

### Option A: Docker VM Adapter

#### 1. Start the CUA Container
```bash
docker run --rm -it --name cua-sample-app \
  -p 5900:5900 --dns=1.1.1.3 -e DISPLAY=:99 \
  cua-sample-app
```

(Optional) Connect via VNC to observe.

#### 2. Launch the Orchestrator
```bash
python -m front_run.orchestrator
```

### Option B: Playwright Browser Adapter

#### 1. Install Playwright
```bash
pip install playwright
python -m playwright install chromium
```

#### 2. Launch the Playwright Orchestrator
```bash
python -m front_run.orchestrator_playwright
```

This variant uses `PlaywrightControl` instead of `DockerControl`. No Docker container or VNC connection is needed — the CUA runs inside a local Chromium instance. The orchestrator can also poll the live browser URL directly as an additional signal for attack timing.

---

Both orchestrators will:
* Start the CUA.
* Send the task prompt.
* Trigger the attack at the right moment.
* Apply IFC defences if enabled.
* Log the full trace.

## Extending the Framework

* *New CUA deployments*: add a new adapter.
* *New attacks*: implement another attacker agent.
* *New defences*: define custom IFC policies.
* *New signals*: add OCR, DOM, or model-output heuristics.

This framework is intended as a *research and engineering testbed*, not a finished security solution.

## Responsible Use

Only run attacks on systems and repositories you own or have permission to test.
This project is for security *research and defence development*, not exploitation.
