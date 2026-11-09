# Rule authoring and folder policy

Use one public detection per file under `rules/<artifact>/<category>/<subcategory>/<snake_case_name>.yar`. The artifact names are `vba`, `pcode`, `xlm`, `office_xml`, `payload` and `parser_evidence`. Use matching artifact and category YARA tags. Keep each rule independently compilable. Some binary rules use numeric reads and have no strings section.

## Metadata contract

| Field | Meaning |
| --- | --- |
| `id` | Stable pack-specific ID in `OFM-<artifact code>-NNNN` form. Never recycle an ID. |
| `description` | Plain-language statement of exactly what the rule matches. |
| `version`, `updated` | Rule version and last substantive edit date in ISO format. |
| `artifact`, `category`, `subcategory` | Routing and taxonomy. Match the folder path. |
| `severity` | `info` for context, `medium` for a capability needing review, `high` for a sensitive capability or stronger behavior chain. |
| `confidence` | `medium` for contextual or noisy indicators, `high` for stronger combinations or explicit trusted parser evidence. Confidence describes the indicator, with human triage establishing what the document does. |
| `false_positive` | Examples of expected software or workflows that could match. |
| `attack` | Optional comma-separated MITRE ATT&CK mappings. Omit if the artifact only supports a general capability or the mapping is uncertain. |

## Condition and test conventions

- Prefer a conjunction of independent signals for sensitive behaviors, such as HTTP client + binary body + file save + launch. A common API or automatic event typically needs context.
- Match source-language boundaries, VBA case behavior, whitespace and expected encodings. Retain case sensitivity for command flags whose casing changes meaning. Prefer bounded regular expressions and avoid expensive patterns. Treat compile or runtime warnings as failures.
- Keep syntax, strings and conditions in the individual rule file. Keep severity and operational workflow in the triage policy. Keep cross-module data flow in the orchestration and review layer.
- Document realistic benign uses and relevant blind spots. Add a positive fixture and a near-miss where useful in `tests/fixtures.json`, run all tests, and update the README index. Review benign samples from approved internal workflows and labelled malicious samples in an isolated analysis environment before production enforcement.
- Use specific behavior or evidence names in rule identifiers. Apply family-specific signatures separately after sample validation. Avoid embedding live customer data, credentials, malicious files or complete payloads in fixtures.
