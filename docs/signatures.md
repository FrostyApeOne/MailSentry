# Signature pack format (version 1)

```json
{
  "version": 1,
  "signatures": [
    {
      "id": "example-generated-prize",
      "name": "Generated sender with specific prize claim",
      "score": 7,
      "when": {
        "all": [
          { "field": "senderDomain", "operator": "startsWith", "value": "--" },
          { "field": "subject", "operator": "containsAll", "values": ["claim your prize", "expires today"] }
        ]
      }
    }
  ]
}
```

IDs must be unique across all packs (case-insensitive). Rules contribute positive integer scores, 1–100, once per matching message. Scores accumulate; reaching the configured threshold yields SPAM. Explicit allow lists always yield TRUSTED before evaluation. No match yields REVIEW.

Fields: `senderName`, `senderAddress`, `senderDomain`, `subject`, `body`, `content`, `importance`. `body` uses the provider's body preview, not full HTML. `content` concatenates sender name, subject and body preview, preserving the original classifier's behavior. `importance` is normal/high/low.

Operators: `contains`, `startsWith`, `endsWith`, `equals`, `regex` use a nonempty `value`. `containsAny` and `containsAll` use nonempty `values`. Matching is case-insensitive after NFKC normalization and normalization of typographic dashes/quotes. Regex patterns use .NET syntax, case-insensitive/culture-invariant matching and a 50 ms timeout; patterns must not match empty input. Regex patterns themselves are not text-normalized.

Compound conditions use `all` (AND) or `any` (OR), each containing nonempty condition arrays. Nesting is supported to 12 levels. A condition must be either one leaf or one compound. Do not mix `all`, `any`, or leaf fields. Unsupported properties are rejected. Maximums: 1000 signatures/pack, 100 children/compound, 100 values/operator, 2000 characters/value, 1 MB/file.

Treat generic marketing, random senders, unusual domains and emoji as supporting evidence. Use specific campaign combinations. Do not make broad signatures that classify generic “offer”, “discount”, “bonus”, “congratulations”, no-reply or unusual TLDs as spam alone. Upload, inspect the current impact, then confirm activation. A zero-impact preview is valid but supplies no evidence about accuracy. Validation checks structure and execution safety, not truth of a rule's claims.

External file errors disable the full snapshot. Correct the file to recover on the next scan/status refresh; no rebuild/restart is needed. Uploaded packs cannot replace an existing filename or reuse an existing ID. Edit/remove existing files administratively if needed; the first version intentionally has no rule editor.
