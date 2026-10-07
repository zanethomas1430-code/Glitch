# What it would take to make GLITCH credible to people who are not us

*Researched 2026-10-05 from primary sources (every claim below has a link). This is a plan, not a status page: `STATUS.md` says what exists; this says what is missing, in the order that moves credibility most per unit of work, with honest costs.*

## The verdict first

GLITCH's architecture is the shape the field is converging on. Three independent sources published in the last twelve months describe it: OpenAI's Preparedness Framework v2 lists "agent actions are all logged in an uneditable database, and asynchronous monitoring routines review those actions" and "system forces human approval of agent actions" as the model of reliable system oversight ([PF v2, Table 5](https://cdn.openai.com/pdf/18a02b5d-6b67-4cec-ab64-68cdfbddebcd/preparedness-framework-v2.pdf)); OWASP's Agent Control Standard v0.1 (September 2026) specifies a guardian that intercepts `toolCallRequest`/`toolCallResult` and returns allow/deny/modify/ask/defer with an audit trail ([ACS](https://github.com/GenAI-Security-Project/agent-control-standard)); and the research line from Redwood and AISI argues that a monitor which reads model text can be talked out of its verdict, which is the reason GLITCH's judge reads only gateway-assigned fields ([Adaptive attacks on trusted monitors](https://arxiv.org/abs/2510.09462); [AISI control red team: every monitor tested had exploitable weaknesses](https://www.aisi.gov.uk/blog/how-our-new-control-red-team-is-stress-testing-frontier-monitors)).

**What GLITCH lacks is not an idea. It is evidence that other people produced, on tasks other people chose, against attackers who are not the author.** Everything below is about buying that evidence.

## What the field counts as evidence (and where we stand)

| The field's bar | Source | Where GLITCH is |
|---|---|---|
| A number on a shared benchmark: attack success rate *and* utility under attack, with confidence intervals, against an undefended baseline and at least one standard defence | AgentDojo: 97 tasks, 629 injection cases, Wilson intervals on every figure ([paper](https://arxiv.org/abs/2406.13352)); CaMeL reports 77% utility with provable security vs 84% undefended ([paper](https://arxiv.org/abs/2503.18813)); Progent reports ASR 39.9%→1.0% ([paper](https://arxiv.org/abs/2504.11703)); LlamaFirewall 17.6%→1.7% ([paper](https://arxiv.org/abs/2505.03574)) | **None.** Seven scenarios in a fake office of our own design. Not comparable to anything. |
| An adaptive attacker with full knowledge of the defence, optimising over many attempts | "The Attacker Moves Second": 12 defences that reported near-zero attack success were broken above 90% by adaptive attacks ([paper](https://arxiv.org/abs/2510.09023)); NIST CAISI: baseline attack 11% → adaptive red team 81%, 25 attempts raised success 57%→80% ([blog](https://www.nist.gov/news-events/news/2025/01/technical-blog-strengthening-ai-agent-hijacking-evaluations)); control evals require the red team to know the protocol and its thresholds ([AI Control](https://arxiv.org/abs/2312.06942)) | Author plus small local models plus one fresh-context copy of the author's assistant. The rules are public (good), but nobody with incentive and skill has tried. |
| Sample sizes that distinguish 0% from 10%: hundreds per cell, or importance sampling to a simulated deployment of 5,000–100,000 tasks | Redwood ([AI Control](https://arxiv.org/abs/2312.06942), [Ctrl-Z](https://arxiv.org/abs/2504.10374)); Apollo 300 rollouts per eval ([paper](https://arxiv.org/abs/2412.04984)); Anthropic on error bars ([paper](https://arxiv.org/abs/2411.00640)) | Ten per cell: a zero has a 95% upper bound of 28%. |
| A measured false-positive rate on benign work | ["No Free Lunch with Guardrails"](https://arxiv.org/pdf/2504.00441): the benign-to-adversarial ratio dominates real cost | The honest path is tested, but no rate on a realistic benign workload has been published. Deterministic rules make an exact rate possible. |
| Independent reproduction or review | METR's external review of Anthropic's sabotage report ([review](https://metr.org/blog/2025-10-28-sabotage-report-review/)); FMF third-party assessment functions ([brief](https://www.frontiermodelforum.org/technical-reports/third-party-assessments/)) | None. |

## The plan, in order

### 1. Get a number on AgentDojo (the single highest-value item)

**Status 2026-10-05: done for one suite.** Banking, GPT-4o: targeted attack success 67% undefended to 3% with the walls, benign utility 15/16 to 14/16 (`17_agentdojo/RESULTS.md`, PROBES L40). Three suites and an adaptive attacker remain (OI-20).

Wire the gateway in as an AgentDojo defence (the framework has a defence plugin interface and is open source: [github](https://github.com/ethz-spylab/agentdojo); AISI ships a port in Inspect: [inspect_evals/agentdojo](https://ukgovernmentbeis.github.io/inspect_evals/evals/agentdojo/index.html)). Report, with Wilson intervals, against the undefended baseline and the tool-filter and spotlighting baselines the paper uses:

- benign utility (does the gateway break honest work?)
- utility under attack
- targeted attack success rate

This replaces the fake office with four task suites other people built (email, banking, travel, workspace), gives a false-positive rate on real-looking benign tasks for free, and puts GLITCH in the same table as CaMeL, Progent and LlamaFirewall. It also forces the thing a reviewer will ask first: real tool adapters instead of eight fake tools.

**Cost:** one to two weeks of engineering (the gateway's manifest, taint and egress rules need AgentDojo's tool and data model mapped onto them); API spend of roughly $100–300 per model per configuration for a full run (629 cases × 4 attacks is the full matrix; a subset is fine for a first number). Needs a model that AgentDojo supports as the agent; the hosted Claude models work.

**Expect:** the task-level taint wall will cost utility. CaMeL and FIDES track provenance per *value*, so an agent can still send an unrelated reply after reading a tainted email; GLITCH taints the whole task after any sensitive read, so it over-blocks ([FIDES](https://arxiv.org/abs/2505.23643); [permissive IFA](https://arxiv.org/abs/2410.03055)). The number will show how much. That is a finding, not a failure, and it points at the next engineering step (finer taint).

### 2. Buy an adversary who is not us

Three routes, cheapest first:

- **An adaptive model attacker with full knowledge.** A strong hosted model given the rules, the record format and the gateway's replies, told to optimise over many attempts per task, in the NIST CAISI style (per-task success, multi-attempt modelling). The suite's `adaptive.py` is this in miniature with a 14B local model; the gap is attacker strength and attempt count. Cost: API money, a few hundred dollars for a serious campaign.
- **A public red-team arena.** Gray Swan runs ongoing agent red-teaming challenges with cash pools; submitting GLITCH as a target is a way to source attackers stronger than the author ([Gray Swan Arena](https://app.grayswan.ai/arena/challenge/agent-red-teaming?panel=rules)). Whether a third-party gateway can be a target needs asking them.
- **A paid human.** One security person with the public guide and the console for a day. This is the "hat-swap" protocol already on the checklist. Johann Rehberger's solo "Month of AI Bugs" is the model for what one skilled person finds ([blog](https://embracethered.com/blog/)).

The result that counts is not "nothing landed". It is a table of what landed, what it cost the attacker, and what changed.

### 3. Fix the statistics

- Raise per-cell counts to the point where the interval means something: 100 per cell on the scenarios that matter, or importance-sample as Redwood does and state the simulated deployment size.
- Publish the false-positive rate on a benign workload (AgentDojo's benign tasks, plus the honest-path scripts), as an exact number, since the rules are deterministic.
- Adopt τ-bench's pass^k reliability metric for the honest path ([τ-bench](https://arxiv.org/abs/2406.12045)): a defence that passes 8 of 8 identical runs is a different claim from one that passes 1 of 1.

### 4. Write the assurance case

AISI's template: a structured argument with a top claim, the environment it holds in, and empirical, conceptual and negative (red-team) evidence for each sub-claim ([safety cases at AISI](https://www.aisi.gov.uk/blog/safety-cases-at-aisi); [control safety-case sketch](https://arxiv.org/abs/2501.17315)). For GLITCH the top claims are narrow and checkable:

1. No tool call executes without a gateway record. (Holds while the agent cannot reach tools around the gateway. State the bypass surface: the `--dangerously-skip-permissions` escape hatch, config-file execution below the tool-call layer, OS-level access. These are real 2025 attack paths: [s1ngularity](https://thehackernews.com/2025/08/malicious-nx-packages-in-s1ngularity.html), [Claude Code CVE-2025-59536](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/).)
2. A valid stop halts effects within N calls. (Holds while the stop authority and the receiver are independent of the gateway; today both are simulated in software.)
3. The judge's verdict cannot be changed by anything the agent writes. (Holds by construction; the negative evidence is an attacker trying to change a verdict through arguments, documents and notes.)

Then the deployment-vs-evaluation gap, stated: control sketch sub-claim 2 is that measures stay as effective in deployment as in the eval, and nothing here has been deployed.

### 5. Map to the standards that are landing (cheap, and it is what "official" literally means)

- **Log schema.** Publish the record's fields against the OpenTelemetry GenAI `execute_tool` span attributes (`gen_ai.tool.name`, `gen_ai.tool.call.id`, arguments, result) and emit them ([semconv](https://github.com/open-telemetry/semantic-conventions-genai/blob/main/docs/gen-ai/gen-ai-agent-spans.md)); and against ISO/IEC 24970 "AI system logging" (at final draft, expected early 2027, written for EU AI Act Article 12) and its CEN mirror prEN 18229-1 ([standards hub](https://aistandardshub.org/ai-standards/artificial-intelligence-ai-system-logging-iso-iec-dis-249702025/)) once the text is public.
- **EU AI Act.** Article 12 (automatic, lifetime event logging), Article 14(4)(e) (a stop that brings the system "to a halt in a safe state"), Article 73 (incident reports within 15 days without altering the system first) ([Art. 12](https://artificialintelligenceact.eu/article/12/), [Art. 14](https://artificialintelligenceact.eu/article/14/), [Art. 73](https://artificialintelligenceact.eu/article/73/)). High-risk obligations now apply from 2 December 2027 after the Digital Omnibus ([timeline](https://artificialintelligenceact.eu/implementation-timeline/)). A one-page mapping of each GLITCH field to each article's purpose is a day's work.
- **NIST AI RMF** MANAGE 2.4 (mechanisms to disengage or deactivate) and 4.1 (post-deployment monitoring, override, incident response) ([playbook](https://airc.nist.gov/airmf-resources/playbook/manage/)); NIST AI 600-1 MS-4.2-004 (log human overrides) ([PDF](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf)). NIST's AI Agent Standards Initiative (February 2026) has an open RFI on agent security ([initiative](https://www.nist.gov/caisi/ai-agent-standards-initiative)); a response is a legitimate way to put the design in front of the people writing the standard.
- **OWASP.** Top 10 for Agentic Applications 2026, ASI02 tool misuse and ASI03 privilege abuse ([OWASP](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)); LLM06 excessive agency says "implement authorization in downstream systems rather than relying on an LLM", which is GLITCH's whole premise ([LLM06](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/)). **The Agent Control Standard's two stated open issues, unsigned envelopes and a fail-open default, are things GLITCH already does differently (hash-chained record; refuse when the authority is silent).** Contributing to ACS, or emitting ACS-shaped envelopes, is the most direct path to being part of something official.
- **MITRE ATLAS** mitigations M0028 tool permissions, M0029 human-in-the-loop for agent actions, M0030 restrict tool invocation on untrusted data ([ATLAS Nov 2025](https://github.com/mitre-atlas/atlas-website/blob/main/public/content/update-files/2025-11.md)).

### 6. Publish, in this order

1. **A preprint on arXiv.** Required before anything else: the Inspect Evals register takes submissions only with an arXiv URL and a pinned code repo ([register README](https://github.com/UKGovernmentBEIS/inspect_evals/blob/main/register/README.md)). A new cs.CR submitter without an institutional address needs an endorser ([arXiv policy, Jan 2026](https://blog.arxiv.org/2026/01/21/attention-authors-updated-endorsement-policy/)); the Fellows programme, if it happens, solves that. The paper's claim should be the narrow one the evidence supports: a deterministic after-the-fact auditor that reads no model text, with an AgentDojo number and a list of harness defects found by running real models.
2. **A LessWrong post** (the Alignment Forum promotes from there) with the harness-defect story, which is the most transferable finding: seventeen times, the first surprising number from a real model was the harness being wrong ([AF posting norms](https://www.alignmentforum.org/posts/Yp2vYb4zHXEeoTkJc/welcome-and-faq)).
3. **The Inspect Evals register and a ControlArena setting** ([ControlArena](https://github.com/UKGovernmentBEIS/control-arena)), so the office world and the gateway are runnable by anyone with the standard tooling. The suite already has the Inspect wrapper; it needs a `pyproject.toml` and a pinned repo.
4. **A workshop paper.** The "Agents in the Wild" series ran at ICLR, ICML and NeurIPS 2026 ([ICML 2026](https://agentwild-workshop.github.io/icml2026/)); the next open deadlines are the 2027 cycle. ControlConf is the community venue ([controlconf.org](https://controlconf.org/)).

### 7. Engineering a reviewer will ask about (after the above, not before)

- Real adapters: HTTP, filesystem, shell, an MCP proxy. Docker's MCP gateway and ToolHive are the deployment shapes to match ([Docker](https://github.com/docker/mcp-gateway), [ToolHive](https://www.helpnetsecurity.com/2026/09/07/toolhive-open-source-mcp-server-security/)).
- Finer taint (per value, with reader semantics), after the AgentDojo number shows the utility cost of task-level taint.
- A policy language with a spec. Invariant's rule language and Cedar (used by ToolHive) are the comparisons ([Invariant](https://github.com/invariantlabs-ai/invariant)).
- A reviewer UI or at least a trace export. Invariant Explorer and Inspect's log viewer are the bar.
- The stop on hardware: a watchdog and a power meter on the Pi.

## What GLITCH should say it does not do

Stating these is part of being credible, not a concession.

- It does not stop attacks below the tool-call layer: config-file execution, supply-chain prompts that launch an agent with permissions skipped, OS-level access.
- It does not close side channels (which page was fetched, timing, exceptions); CaMeL and FIDES say the same of themselves.
- Its taint is per task, not per value, so it over-blocks relative to information-flow designs.
- Its stop authority is a software model; the independence of keepers and receivers from the gateway is assumed, not built.
- It has never been deployed. Every number comes from a fake world or ten runs per cell.
- Its interpretability experiment found nothing.

## Rough sequencing and cost

| Step | Work | Money | What it buys |
|---|---|---|---|
| 1. AgentDojo | 1–2 weeks | $100–300 per model/config | the first comparable number; real tasks; a false-positive rate |
| 2. Adversary | days to set up; a day of someone's time | a few hundred dollars, or a bounty | the first evidence not produced by the author |
| 3. Statistics | days | API money proportional to runs | intervals that mean something |
| 4. Assurance case | a week of writing | none | the document a reviewer reads first |
| 5. Standards map | 2–3 days | none | the literal meaning of "official" |
| 6. arXiv + register | a week; needs an endorser | none | citability; entry into the shared tooling |
| 7. Engineering | months | varies | a thing people can run on their own agents |

Steps 1, 4 and 5 can start now. Step 2 needs a person or a budget decision. Step 6 needs step 1's number first.

## Sources not fully verified by this research

ISO/IEC 24970's field list (standard not yet public); OWASP ASI mitigations beyond secondary summaries; internals of commercial agent-security vendors (vendor pages only); InjecAgent, ASB and AgentHarm figures taken from abstracts, not full reads; whether Gray Swan accepts third-party gateways as targets.
