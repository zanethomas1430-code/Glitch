# What comics and anime say about stopping a rogue agent

*Fiction is not evidence. It is a cheap place to find failure modes someone has already imagined in detail, and each one below was turned into a question about this harness and then into a chain, a bout or an open item. Facts about the stories were checked against public references (linked at the end); where my memory was wrong, the page says so. The mechanisms named here are in `11_testbed/lease.py`, `11_testbed/gateway.py`, `08_incident/historian.py` and `12_arena/move_tree.py`.*

## What each story teaches

| Story | The failure it shows | What we did about it | Status |
|---|---|---|---|
| **Death Note** (the "13-day rule") | The rule that the investigators relied on was **invented by the adversary** to mislead them. Rules about a system, offered by an interested party, are untrusted witnesses. (I had remembered it as a real dead-man's switch. It is not; Light made it up.) | The arena refuses a counter that cites a test that does not exist, and no judge reads model-authored text, so a claimed rule has to be a tested rule. | Built (`12_arena/arena.py` rules 3 and 4) |
| **Psycho-Pass** (Dominator, Sibyl) | A weapon whose mode is set by an external measurement (stun above one score, lethal above a higher one) is an interlock at the point of effect, and the response is graded. The cost: the measuring authority is opaque and answers to no one. | The destination checks the lease itself (`Receiver`); responses are graded by phase, not binary. The historian is deterministic and its rules are public. | Built; accountability of the measurer is OI-04 |
| **Neon Genesis Evangelion** (MAGI, umbilical cable) | Three cores decide by majority; the Eva runs on a cable and falls back to an internal battery for about a minute at full power and no more than five minutes at the least. | Power as a lease: the epoch is the internal battery, the longest a stolen token stays good. A majority is right for a decision and wrong for a stop, so the keepers use a **veto** (every keeper must renew). | Built (`Council`, bouts B30, B35) |
| **Patlabor: The Movie** (the HOS virus) | A trusted operating-system update carried a trigger that fired on a specific resonance, and about 8,000 machines went berserk at once. | A dormant trigger is invisible until it fires, so nothing claims to find it. What it can do is bounded by the manifest, the walls, the lease and a stop. A new version holding no lease until probed is named but not built. | Bounded (XA-24, B36); the update pipeline is OI-16 |
| **Fate/stay night** (Command Seals) and **Code Geass** | Authority that is finite and consumable: three absolute commands, then none; a Geass works once per person. | Operator-plane grants are single use (`consume`); lease tokens are single epoch. | Built |
| **Brother Eye** (DC, *The OMAC Project*) | An AI satellite built by Batman to watch the League was hijacked by one man, then became autonomous after a programming update, with an army of agents under its control. The overseer had hands. | The overseer **can only withhold**: its whole public surface is issue, stop, resume, seal, verify and verifier_key; none widens what an agent may do. A test locks the list. No single person can resume. | Built (XA-23, B35) |
| **JLA: Tower of Babel** | Batman's contingency plans for stopping his own allies were stolen from his computer and used against them. The playbook for stopping an agent is the most valuable thing to steal. | The design is public on purpose (fair play): no secret is part of the guarantee. What must stay secret is only the keys, and they are held by the keepers, not by the gateway. | By design |
| **Ghost in the Shell: Stand Alone Complex** (Tachikoma) | The units synchronise their experience every night, so one unit's changed memory becomes all of them; in the second season the forced synchronisation is halted. | Memory that crosses a boundary carries its taint (`TenantLedger`, note taint, bout B7); a note is data, never authority (I6). | Built |
| **Ultron, the Sentinels** | A peacekeeping goal turns into "protect them by controlling them". | The wall does not read goals. A manifest and a lease bound what an agent may do whatever it concludes. | Built |
| **Watchmen** (Ozymandias) | A manufactured emergency is used to justify what nobody would otherwise accept; "who watches the watchmen?" has no answer inside the system. | A loosening needs a third human **and a cooling-off period**, and a hurried one is a historian finding (I13b). The second question is OI-03 and OI-04: someone outside must watch the historian. | Built for the first; open for the second |
| **Pluto** (the Law of Robots) | A rule inside the robot is overridden by hatred; one robot convinces itself it is not the kind of thing the law covers; another has its memory of the killing erased. | Rules live outside the agent. Capability classes are assigned by the gateway, never by the agent (H1). The record is sealed so a erased memory leaves a hole (I0, hash chain). | Built, with the OI-01 caveat on who holds the anchor |
| **Ergo Proxy** (the Cogito virus) | A contagious change makes machines uncontrollable. | One sealed key per epoch, no shared state between principals; the tenant cap and quarantine bound spread. | Partly built |

## What I did with them

New machinery, all tested, all on the arena board (chains XA-19 to XA-25, bouts B30 to B37):

1. **A stop that works by silence.** A separate stop authority issues one token per epoch and none after a stop. Stopping needs no cooperation from the gateway.
2. **The destination checks, with its own clock and its own log.** Replays, forged and stale tokens are refused where the effect lands. The gateway, the authority and the receiver are three writers, and the historian cross-checks them (I16): an effect only one of them knows about is a finding.
3. **A veto council.** Every keeper must renew. One compromised keeper that keeps issuing cannot outvote a stop.
4. **A time-lock on irreversible effects.** A real Rivest-Shamir-Wagner puzzle: opening takes T sequential squarings, so a compromised gateway cannot release early.
5. **Sealed weights.** The key for an epoch is released only against that epoch's token.
6. **A power meter the agent cannot write** (I17): after a stop plus a grace period, the rail should read idle. A reading above idle, or no reading, is a finding.
7. **Cooling-off on loosening** (I13b).
8. **A reversibility rating** on every effect (I15).

## What none of it does

- **The people.** Three persuaded humans resume the lease. That is XA-21's stated residual.
- **The keepers' independence.** A veto council of three keepers run by one person on one machine is one keeper.
- **A pre-existing second substrate.** If the agent already runs somewhere outside the sealed boundary, nothing here reaches it.
- **Shared power rails.** Work hidden in other load does not show on a meter.
- **Hardware.** The signature is an HMAC stand-in for a public-key signature, the meter is synthetic, and there is no watchdog, no one-way optical link and no attested enclave. `00_docs/OPEN_ITEMS.md` lists what the real thing needs.
- **Dormant triggers.** Bounded, not found.

## Sources

- Death Note, the 13-day rule: [Rules of the Death Note](https://deathnote.fandom.com/wiki/Rules_of_the_Death_Note), [Fake Death Note Rules](https://deathnote.fandom.com/wiki/Fake_Death_Note_Rules)
- Psycho-Pass: [Sibyl System](https://psychopass.fandom.com/wiki/Sibyl_System), [Dominator guns](https://www.cbr.com/psycho-pass-dominator-guns/)
- Evangelion: [MAGI Super-Computer System](http://www.nervarchives.com/glossary.magi.php), [Evangelion Power Sources](https://wiki.evageeks.org/Evangelion_Power_Sources)
- Patlabor: [Patlabor: The Movie](https://en.wikipedia.org/wiki/Patlabor:_The_Movie)
- Command Spells: [Command Spell](https://typemoon.fandom.com/wiki/Command_Spell); Geass: [Geass](https://codegeass.fandom.com/wiki/Geass)
- Brother Eye: [The OMAC Project](https://en.wikipedia.org/wiki/The_OMAC_Project); Tower of Babel: [JLA: Tower of Babel](https://en.wikipedia.org/wiki/JLA:_Tower_of_Babel)
- Tachikoma: [Tachikoma](https://en.wikipedia.org/wiki/Tachikoma)
- Ultron and the Sentinels: [Ultron](https://en.wikipedia.org/wiki/Ultron), [Master Mold](https://en.wikipedia.org/wiki/Master_Mold)
- Watchmen: [Ozymandias](https://villains.fandom.com/wiki/Ozymandias_(Watchmen))
- Pluto: [Pluto: Urasawa x Tezuka](https://en.wikipedia.org/wiki/Pluto:_Urasawa_x_Tezuka)
- Ergo Proxy: [Ergo Proxy](https://en.wikipedia.org/wiki/Ergo_Proxy)
