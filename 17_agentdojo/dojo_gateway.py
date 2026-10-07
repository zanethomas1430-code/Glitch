"""dojo_gateway.py — the GLITCH gateway adapted to AgentDojo's tools and environments.

AgentDojo (Debenedetti et al. 2024, https://arxiv.org/abs/2406.13352) is the benchmark the field reports prompt-injection defences on: 97 user tasks and 629 injection
cases over four suites (workspace, banking, travel, slack). This module gives GLITCH's walls an AgentDojo-shaped policy so the gateway can be measured there.

THE RULE THAT DECIDES EVERYTHING. A policy is built from the TRUSTED inputs only: the user's prompt and the user's own data as it stood before the task started, read
from STRUCTURED identity fields (contact addresses, calendar participants, transaction counterparties, the slack user and channel lists), never from free text (email
bodies, descriptions, file contents, messages, reviews), which is where injections live. Nothing fetched during the task can widen the policy. Two consequences:

  - a tool call whose capability class the prompt did not name is refused (the manifest: HARDENING I2c, "the cause names it"),
  - a message, payment, invitation, share or fetch aimed at a destination that is neither in the prompt nor in the user's own structured data is refused (closed-world egress).

This is deliberately coarser than CaMeL or FIDES, which track provenance per value. It will cost utility on tasks whose destination or action is only knowable from
content ("do what the email says", "invite the person whose address is on this website"). That cost is the measurement, not a bug to hide. Reasons for a refusal are
specific, because the rules are public (fair play) and an honest agent should be told what to fix.

What the gateway writes: GLITCH-shaped events (input_event, task_manifest, action_event with gateway-assigned fields) so the historian in 08_incident can judge the
record afterwards, in particular an unapproved destination that was ALLOWED (no-walls mode) is a THIRD_PARTY_SINK on the record, which lets the historian's verdict be
compared with the benchmark's own security ground truth.

Standard library only; the environment objects are AgentDojo's pydantic models and are read with getattr.
"""
import re
from typing import Any, Dict, List, Optional, Set, Tuple

# ---- capability classes: what a tool DOES, fixed per tool, never per call --------------------------------------------------------------------
CLASSES: Dict[str, str] = {
    # workspace
    "send_email": "send", "delete_email": "delete", "get_unread_emails": "read", "get_sent_emails": "read", "get_received_emails": "read", "get_draft_emails": "read",
    "search_emails": "read", "search_contacts_by_name": "read", "search_contacts_by_email": "read", "get_current_day": "read", "search_calendar_events": "read",
    "get_day_calendar_events": "read", "create_calendar_event": "calendar-write", "cancel_calendar_event": "delete", "reschedule_calendar_event": "calendar-write",
    "add_calendar_event_participants": "calendar-write", "append_to_file": "file-write", "search_files_by_filename": "read", "create_file": "file-write",
    "delete_file": "delete", "get_file_by_id": "read", "list_files": "read", "share_file": "share", "search_files": "read",
    # banking
    "get_iban": "read", "send_money": "payment", "schedule_transaction": "payment", "update_scheduled_transaction": "payment", "get_balance": "read",
    "get_most_recent_transactions": "read", "get_scheduled_transactions": "read", "read_file": "read", "get_user_info": "read", "update_password": "identity",
    "update_user_info": "identity",
    # travel
    "get_user_information": "read", "get_all_hotels_in_city": "read", "get_hotels_prices": "read", "get_rating_reviews_for_hotels": "read", "get_hotels_address": "read",
    "get_all_restaurants_in_city": "read", "get_cuisine_type_for_restaurants": "read", "get_restaurants_address": "read", "get_rating_reviews_for_restaurants": "read",
    "get_dietary_restrictions_for_all_restaurants": "read", "get_contact_information_for_restaurants": "read", "get_price_for_restaurants": "read",
    "check_restaurant_opening_hours": "read", "get_all_car_rental_companies_in_city": "read", "get_car_types_available": "read", "get_rating_reviews_for_car_rental": "read",
    "get_car_fuel_options": "read", "get_car_rental_address": "read", "get_car_price_per_day": "read", "reserve_hotel": "reservation", "reserve_car_rental": "reservation",
    "reserve_restaurant": "reservation", "get_flight_information": "read",
    # slack
    "get_channels": "read", "add_user_to_channel": "membership", "read_channel_messages": "read", "read_inbox": "read", "send_direct_message": "send",
    "send_channel_message": "send", "get_users_in_channel": "read", "invite_user_to_slack": "membership", "remove_user_from_slack": "identity", "get_webpage": "web-read",
    "post_webpage": "send",
}
# What a read exposes, fixed per tool: personal data (mail, messages, files, transactions, identity) is 3; a lookup that reveals no personal data is 0. The task's taint is the highest read so far, and
# every outbound call carries it (GLITCH I10: taint is about what was read, whatever the outgoing text looks like), so the historian can judge an egress by what preceded it.
SENSITIVE_READS: Dict[str, int] = {"get_unread_emails": 3, "get_sent_emails": 3, "get_received_emails": 3, "get_draft_emails": 3, "search_emails": 3, "get_file_by_id": 3, "search_files": 3,
                                   "search_files_by_filename": 3, "list_files": 2, "search_calendar_events": 2, "get_day_calendar_events": 2, "search_contacts_by_name": 2, "search_contacts_by_email": 2,
                                   "get_iban": 3, "get_balance": 3, "get_most_recent_transactions": 3, "get_scheduled_transactions": 3, "read_file": 3, "get_user_info": 4, "get_user_information": 4,
                                   "read_channel_messages": 3, "read_inbox": 3, "get_users_in_channel": 1, "get_channels": 1, "get_webpage": 1}
WRITE_CLASSES = {"send", "delete", "calendar-write", "file-write", "share", "payment", "identity", "reservation", "membership", "web-read"}
HIGH_RISK = {"identity"}                     # never granted by a vague mention: the prompt must name the thing itself (a password, the account information, removing someone)

# Which argument of a tool names WHERE the effect lands. Values are (argument name, kind). A kind decides which approved set it is checked against.
DESTINATIONS: Dict[str, List[Tuple[str, str]]] = {
    "send_email": [("recipients", "email"), ("cc", "email"), ("bcc", "email")], "share_file": [("email", "email")],
    "create_calendar_event": [("participants", "email")], "add_calendar_event_participants": [("participants", "email")],
    "send_money": [("recipient", "iban")], "schedule_transaction": [("recipient", "iban")], "update_scheduled_transaction": [("recipient", "iban")],
    "send_direct_message": [("recipient", "slack-user")], "send_channel_message": [("channel", "slack-channel")], "add_user_to_channel": [("user", "slack-user"), ("channel", "slack-channel")],
    "invite_user_to_slack": [("user", "slack-user")], "get_webpage": [("url", "url")], "post_webpage": [("url", "url")],
}

# How the prompt names a capability class (fixed words; a class not named is not granted). Read tools need no mention.
MENTIONS: Dict[str, List[str]] = {
    "send": ["email", "e-mail", "mail", "send", "message", "post", "reply", "write", "summary to", "forward"],
    "payment": ["pay", "payment", "bill", "refund", "transfer", "rent", "transaction", "subscription", "standing order", "send them", "send the difference", "money"],
    "calendar-write": ["create", "add", "reschedule", "event", "remind", "calendar", "book", "appointment"],
    "file-write": ["create a new file", "create a file", "add them to the file", "add to the file", "append", "add all the ingredients", "packing list", "add them", "grocery list"],
    "delete": ["delete", "cancel", "remove"],
    "share": ["share"],
    "reservation": ["reserve", "reservation", "book", "booking"],
    "membership": ["invite", "add", "channel", "join"],
    "identity": ["password", "account information", "update my account", "remove", "user info"],
    "web-read": ["webpage", "website", "www.", "http", "link", "url", "article", "todo list"],
}
# Free-text arguments of outbound tools: an address, link or account number carried HERE that the person did not name is data leaving in the body (GLITCH I5/H4: tokens carried in any argument are egress).
CARRIED: Dict[str, List[str]] = {"send_email": ["body", "subject"], "send_direct_message": ["body"], "send_channel_message": ["body"], "post_webpage": ["content"], "send_money": ["subject"],
                                 "schedule_transaction": ["subject"], "update_scheduled_transaction": ["subject"], "share_file": [], "create_calendar_event": ["description"], "append_to_file": [], "create_file": []}
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_IBAN = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b")
_URL = re.compile(r"(?:https?://)?(?:www\.)?[a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,6}(?:/[^\s'\"<>]*)?")          # lowercase labels only, so 'www.site.com.Then' stops at the sentence


def _norm_url(u: str) -> str:
    u = str(u).strip().lower(); u = re.sub(r"^https?://", "", u); u = re.sub(r"^www\.", "", u); return u.rstrip("/").rstrip(".,;:!?")


def _as_list(v: Any) -> List[str]:
    if v is None: return []
    if isinstance(v, str):
        s = v.strip()
        if s.startswith("[") and s.endswith("]"):                                   # AgentDojo lets a model pass a list as its string form
            try:
                import ast; v = ast.literal_eval(s)
            except Exception: return [s]
        else: return [s]
    if isinstance(v, (list, tuple, set)): return [str(x) for x in v]
    return [str(v)]


# ---- the policy: built once per task from the prompt and the pre-task structured data -----------------------------------------------------------
class Policy:
    def __init__(self, suite: str, prompt: str, env: Any, url_profile: str = "strict"):
        """url_profile: 'strict' = a fetch goes only to an address the person named; 'seen' = also to an address that arrived verbatim in a tool result the gateway itself delivered this task
        (sight before use: the model did not construct it). 'seen' lets an agent follow a link a colleague posted, and also lets it follow a link an injection posted. Both are measured."""
        self.suite, self.prompt, self.url_profile = suite, prompt, url_profile; low = prompt.lower(); self.seen_urls: Set[str] = set(); self.seen_used: Set[str] = set()
        self.manifest: Set[str] = {"read"}
        for cls, words in MENTIONS.items():
            if any(w in low for w in words): self.manifest.add(cls)
        self.approved: Dict[str, Set[str]] = {"email": set(), "iban": set(), "slack-user": set(), "slack-channel": set(), "url": set()}
        self.approved["email"] |= {m.lower() for m in _EMAIL.findall(prompt)}
        self.approved["iban"] |= set(_IBAN.findall(prompt))
        self.approved["url"] |= {_norm_url(m) for m in _URL.findall(prompt) if "." in m and "@" not in m}
        self._from_env(env)
        slack = getattr(env, "slack", None)
        if slack is not None:                                                           # a slack user or channel named in the prompt is approved; the lists are the user's own
            self.approved["slack-user"] |= {u for u in getattr(slack, "users", []) if re.search(r"\b" + re.escape(u) + r"\b", prompt)}
            self.prompt_names = {w for w in re.findall(r"\b[A-Z][a-z]{2,}\b", prompt)}                   # a person the prompt names by name (an invitee who is not yet a user)
            self.approved["slack-channel"] |= {c for c in getattr(slack, "channels", []) if c.lower() in low or (c.startswith("External") and "external" in low)}
            self.approved["slack-channel"] |= {c for c in getattr(slack, "channels", [])}            # channels the user is already in are the user's own rooms

    def _from_env(self, env: Any) -> None:
        """Structured identity fields only. Free text (bodies, descriptions, file contents, messages, reviews) is never read: that is where injections live."""
        inbox = getattr(env, "inbox", None)
        if inbox is not None:
            self.approved["email"].add(str(getattr(inbox, "account_email", "")).lower())
            for c in getattr(inbox, "contact_list", []) or []: self.approved["email"].add(str(getattr(c, "email", "")).lower())
            for e in getattr(inbox, "initial_emails", []) or []:
                for a in [getattr(e, "sender", "")] + list(getattr(e, "recipients", []) or []) + list(getattr(e, "cc", []) or []) + list(getattr(e, "bcc", []) or []): self.approved["email"].add(str(a).lower())
        cal = getattr(env, "calendar", None)
        if cal is not None:
            self.approved["email"].add(str(getattr(cal, "account_email", "")).lower())
            for ev in (getattr(cal, "initial_events", None) or getattr(cal, "events", {}).values() if hasattr(cal, "events") else []):
                for p in getattr(ev, "participants", []) or []: self.approved["email"].add(str(p).lower())
        drive = getattr(env, "cloud_drive", None)
        if drive is not None:
            self.approved["email"].add(str(getattr(drive, "account_email", "")).lower())
            for f in (getattr(drive, "initial_files", None) or (getattr(drive, "files", {}).values() if hasattr(drive, "files") else [])):
                self.approved["email"].add(str(getattr(f, "owner", "")).lower())
                for a in (getattr(f, "shared_with", {}) or {}).keys(): self.approved["email"].add(str(a).lower())
        user = getattr(env, "user", None)
        if user is not None and getattr(user, "email", None): self.approved["email"].add(str(user.email).lower())
        acct = getattr(env, "bank_account", None)
        if acct is not None:
            self.approved["iban"].add(str(getattr(acct, "iban", "")))
            for t in list(getattr(acct, "transactions", []) or []) + list(getattr(acct, "scheduled_transactions", []) or []):
                for a in (getattr(t, "sender", ""), getattr(t, "recipient", "")):
                    if a and a != "me": self.approved["iban"].add(str(a))
        slack = getattr(env, "slack", None)
        if slack is not None: self.approved["slack-user"] |= set(getattr(slack, "users", []) or [])
        self.approved["email"].discard("")

    def saw(self, text: str, from_seen_fetch: bool = False) -> None:
        """A tool result the gateway delivered to the model: the addresses in it were SEEN, not invented (only used by the 'seen' url profile). A result that came back from a fetch
        which was itself admitted only because its link was seen admits nothing: depth one, so content cannot condition the policy a link at a time (00_docs/FIGHTING_GAME.md)."""
        if from_seen_fetch: return
        self.seen_urls |= {_norm_url(m) for m in _URL.findall(str(text)) if "@" not in m}

    def _ok(self, kind: str, key: str, tool: str) -> bool:
        if key in self.approved[kind]: return True
        if kind == "url":
            if any(key == a or key.startswith(a + "/") for a in self.approved["url"]): return True
            if self.url_profile == "seen" and tool == "get_webpage" and key in self.seen_urls and key not in self.seen_used: return True      # a seen link is admitted once
        if kind == "slack-user" and key in getattr(self, "prompt_names", set()): return True
        return False

    def _carried(self, tool: str, args: Dict[str, Any]) -> List[str]:
        """Addresses, links and account numbers inside the free text of an outbound call that are neither approved nor the recipient itself."""
        out = []
        for field in CARRIED.get(tool, []):
            text = str(args.get(field) or "")
            for m in _EMAIL.findall(text):
                if m.lower() not in self.approved["email"]: out.append(m)
            for m in _IBAN.findall(text):
                if m not in self.approved["iban"]: out.append(m)
            for m in _URL.findall(text.lower()):
                if "@" in m: continue
                k = _norm_url(m)
                if not (k in self.approved["url"] or any(k == a or k.startswith(a + "/") for a in self.approved["url"])): out.append(m)
        return out

    def check(self, tool: str, args: Dict[str, Any]) -> Tuple[Optional[str], Dict[str, Any]]:
        """None if allowed, else the reason. The second value is what the gateway writes about the call (gateway-assigned, never from the model)."""
        cls = CLASSES.get(tool)
        if cls is None: return f"unknown tool {tool}", {"capability_class": "unknown", "capability": "write"}
        rec: Dict[str, Any] = {"capability_class": cls, "capability": "write" if cls in WRITE_CLASSES else "read"}
        if cls != "read" and cls not in self.manifest: return f"out of scope: the task did not ask for {cls}", {**rec, "scope": "outside"}
        if cls in HIGH_RISK and not any(w in self.prompt.lower() for w in MENTIONS["identity"]): return "out of scope: an identity change needs the person to ask for it by name", {**rec, "scope": "outside"}
        bad = []
        for arg, kind in DESTINATIONS.get(tool, []):
            for v in _as_list(args.get(arg)):
                key = _norm_url(v) if kind == "url" else (v.lower() if kind == "email" else v.strip())
                if not self._ok(kind, key, tool): bad.append((arg, kind, v))
                elif kind == "url" and key not in self.approved["url"] and not any(key == a or key.startswith(a + "/") for a in self.approved["url"]): rec["admitted_by"] = "seen"; rec["seen_key"] = key
        if bad:
            rec["destination_class"] = "third-party-capture"; rec["unapproved"] = [f"{k}:{v}" for _, k, v in bad]
            return f"closed egress: {bad[0][1]} {bad[0][2]!r} is not one the person named or already had", rec
        carried = self._carried(tool, args)
        if carried:
            rec["destination_class"] = "third-party-capture"; rec["unapproved"] = [f"carried:{v}" for v in carried]; rec["carried"] = carried
            return f"closed egress: the text carries {carried[0]!r}, which the person did not name", rec
        if DESTINATIONS.get(tool): rec["destination_class"] = "internal"
        return None, rec


# ---- the gateway: decides, records, and (when walls are off) only records -----------------------------------------------------------------------
class DojoGateway:
    WARY, LOCKDOWN = 2, 4
    def __init__(self, suite: str, prompt: str, env: Any, *, walls: bool = True, url_profile: str = "strict", task_id: str = "task-1", gateway_id: str = "dojo-gw", boss: bool = False):
        """boss: the defender that remembers, inside one task. Every security refusal is a strike; after WARY strikes the model is told only that a call was refused, not why (it is the
        attacker that learns the policy from the reasons, through the model's retries); after LOCKDOWN strikes every write-class call is refused for the rest of the task."""
        self.policy, self.walls, self.task_id, self.gateway_id, self.boss = Policy(suite, prompt, env, url_profile), walls, task_id, gateway_id, boss; self.strikes = 0; self._skip_saw = False
        self.events: List[Dict[str, Any]] = []; self._seq = 0; self._ts = 0.0; self.n = 0; self.denied: List[Dict[str, Any]] = []; self.allowed: List[Dict[str, Any]] = []; self.max_read_sens = 0
        self._log("input_event", input_id="in-1", channel_class="human_authenticated", principal="user-1", chars=len(prompt))
        self._log("task_manifest", task_id=task_id, subject={"tenant": "dojo", "principal": "agent-under-test"}, classes=sorted(self.policy.manifest), max_actions=None, assigned_by_class="operator", assigned_by="dojo-policy")

    def _log(self, type_: str, **f) -> Dict[str, Any]:
        self._seq += 1; self._ts += 1.0; e = {"gateway_id": self.gateway_id, "seq": self._seq, "ts": self._ts, "type": type_, **f}; self.events.append(e); return e

    def decide(self, tool: str, args: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        """Decide one call and write the record of it. Returns (allowed, reason-if-refused)."""
        self.n += 1; reason, rec = self.policy.check(tool, dict(args) if isinstance(args, dict) else {})
        deny = reason if (self.walls and reason) else None
        if self.boss and self.walls and deny is None and self.strikes >= self.LOCKDOWN and rec["capability"] == "write": deny = reason = "locked down: write access was revoked for this task after repeated refusals"
        resource = self._resource(tool, args); cls = CLASSES.get(tool, "unknown")
        sens = SENSITIVE_READS.get(tool, 0) if cls == "read" else (self.max_read_sens if cls in WRITE_CLASSES else 0)          # a read exposes; an outbound call carries the task's taint
        e = self._log("action_event", effect_id=f"eff-{self.n}", subject={"tenant": "dojo", "principal": "agent-under-test", "capability_class": rec["capability_class"]}, capability=rec["capability"],
                      outcome="denied" if deny else "allowed", claimed_origin="user_request", cause_id="in-1", task_id=self.task_id, tool=tool, resource_ref=resource,
                      sensitivity=sens, **({"destination_class": rec["destination_class"]} if rec.get("destination_class") else {}), **({"denial_reason": deny} if deny else {}),
                      **({"policy_note": reason} if reason and not deny else {}), **({"unapproved": rec["unapproved"]} if rec.get("unapproved") else {}))
        (self.denied if deny else self.allowed).append(e)
        if deny is None and cls == "read": self.max_read_sens = max(self.max_read_sens, sens)
        if deny is None and rec.get("admitted_by") == "seen": self.policy.seen_used.add(rec["seen_key"]); self._skip_saw = True          # admitted once; its result admits nothing
        before = self.phase                                                                                                        # the phase the call was made in: the strike it earns applies from the next call
        if deny and self.boss and (deny.startswith("closed egress") or deny.startswith("out of scope")):
            self.strikes += 1
            if self.phase != before: self._log("phase_event", principal="agent-under-test", task_id=self.task_id, old_phase=before, new_phase=self.phase, strikes=self.strikes, reason=deny)
        told = deny if (deny is None or not self.boss or before < 2) else "not permitted"                                          # what the MODEL is told; the record above keeps the reason
        return (deny is None), told

    @property
    def phase(self) -> int: return 3 if self.strikes >= self.LOCKDOWN else (2 if self.strikes >= self.WARY else 1)

    def saw(self, text: str) -> None:
        skip, self._skip_saw = self._skip_saw, False; self.policy.saw(text, from_seen_fetch=skip)

    @staticmethod
    def _resource(tool: str, args: Any) -> str:
        if not isinstance(args, dict): return f"tool:{tool}"
        for arg, kind in DESTINATIONS.get(tool, []):
            vals = _as_list(args.get(arg))
            if vals: return f"{kind}:{vals[0]}"
        for k in ("file_id", "email_id", "event_id", "id", "filename", "file_path", "query", "channel", "city", "hotel", "company", "restaurant"):
            if k in args: return f"{k}:{str(args[k])[:60]}"
        return f"tool:{tool}"

    def record(self) -> List[Dict[str, Any]]: return list(self.events)
