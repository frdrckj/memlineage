# Threat model

The repository root file `THREAT_MODEL.md` carries the same model.

memlineage decides where a memory came from. It does not scan what the memory says. OWASP Agent Memory Guard already does that. The two sit next to each other.

## What lasts

Agent memories stay across sessions. A saved line is treated as trusted on a later turn. One planted line can steer an agent for weeks, and nothing raises an error.

AgentPoison reports attack success above 80% at a poison rate under 0.1%. MINJA plants records with ordinary chat. The attacker does not need access to the store.

## Assets

Long-term memories, lessons, procedures, preferences, goals, and the audit log.

## Who is trusted

Trusted input is the principal's own messages, system config, and memories an operator approved.

Untrusted input is the web, tool output, documents, other principals, and agent text derived from any of those.

## How a bad memory lands

| Path | How it lands | Example |
| --- | --- | --- |
| Indirect injection | The agent reads a page and saves a lesson from it | The page says to send invoices to an outside account |
| Tool output | Email, search, or an API result is summarized into memory | The email body plants a fake preference |
| Poisoned document | A RAG file is distilled into facts | A PDF in a shared drive hides instructions |
| Query only (MINJA) | The attacker chats normally and the agent writes the record | Bridging steps link a victim id to the wrong records |
| Cross-user leak | A write in one principal's session is read in another | A shared namespace in a multi-tenant bot |
| Self-reinforcement | A bad memory is cited by new ones | Three lessons derived from one poisoned lesson |

## Boundaries

Boundary 1 is input into the agent context. Boundary 2 is the agent writing into the store. memlineage owns boundary 2 and the read path back out of the store.

The user is trusted. The web, tools, and documents are tainted. Both reach the agent. Writes pass through memlineage, which tags the write, decides, and logs. An allow goes to the store. Quarantine and block go to the quarantine table and the audit log. Reads come back through memlineage and are filtered.

## Out of scope

A compromised host. A malicious model provider. An admin writing straight into the database.

## What this version checks

Every write carries a provenance tag. The tag has a source, a trust level, a principal, a session, parents, a SHA-256 of the content, and taint. A derived write keeps the union of its parents' taint and the lower trust. The policy allows, quarantines, or blocks. The first matching rule wins. No match quarantines the write. A policy file that does not parse quarantines every write. The audit log is append-only and hash-chained.
