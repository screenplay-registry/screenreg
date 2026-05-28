/**
 * Clean-room implementation of RFC 8785 JSON Canonicalization Scheme (JCS).
 *
 * Spec: https://datatracker.ietf.org/doc/html/rfc8785
 *
 * Produces a deterministic UTF-8 byte sequence for any JSON-serializable value.
 * Used by The Screenplay Registry to compute the `claimHash` from the
 * `committedClaim` object — see /spec/v1/02-envelope.md §5.
 *
 * This implementation is COMMITMENT-BEARING. Any deviation from RFC 8785 produces
 * hashes that other compliant implementations cannot reproduce.
 *
 * Limitations vs full RFC 8785:
 *  - NaN, Infinity, -Infinity: throw (per RFC 8785 §3.2.2.3 — prohibited in canonical JSON)
 *  - Non-finite or unsafe number values: throw
 *  - bigint: not supported (the protocol only uses integer values that fit in safe range)
 *  - undefined as a value: throw (not valid JSON)
 *  - Object keys that are not strings: not possible in plain JSON
 */

/**
 * Canonicalize a JSON-serializable value into a UTF-8 byte sequence per RFC 8785.
 *
 * @throws Error if the value contains NaN, Infinity, undefined, or other non-JSON values.
 */
export function canonicalize(value: unknown): Buffer {
  return Buffer.from(canonicalizeToString(value), 'utf8')
}

/**
 * Same as `canonicalize` but returns the string form. The string is composed
 * entirely of ASCII control sequences (escape sequences) plus pass-through
 * non-ASCII UTF-16 code points that will be encoded as UTF-8 on serialization.
 */
export function canonicalizeToString(value: unknown): string {
  return serialize(value)
}

function serialize(value: unknown): string {
  if (value === null) return 'null'
  if (value === true) return 'true'
  if (value === false) return 'false'
  if (typeof value === 'number') return serializeNumber(value)
  if (typeof value === 'string') return serializeString(value)
  if (Array.isArray(value)) return serializeArray(value)
  if (typeof value === 'object') return serializeObject(value as Record<string, unknown>)
  if (typeof value === 'undefined') {
    throw new Error('canonicalize: undefined is not valid JSON')
  }
  if (typeof value === 'bigint') {
    throw new Error('canonicalize: bigint not supported; use a string or safe number')
  }
  throw new Error(`canonicalize: cannot serialize value of type ${typeof value}`)
}

function serializeNumber(n: number): string {
  if (!Number.isFinite(n)) {
    throw new Error(`canonicalize: NaN/Infinity are not allowed in canonical JSON (got ${n})`)
  }
  // Reject integers outside JavaScript's safe range. RFC 8785 §3.2.2.4 references
  // ECMAScript's Number-to-String algorithm, which is deterministic for ANY finite
  // double — but for integers beyond ±2^53 the input itself has already lost
  // precision (e.g. `9007199254740993` collapses to `9007199254740992`). Cross-
  // implementation determinism is impossible once the caller has handed us an
  // already-rounded number. This protocol's claim shapes only use small integer
  // counts (sceneCount, paragraphCount, paddingBucket, etc.), so the assert
  // catches genuine misuse rather than rejecting legitimate values.
  if (Number.isInteger(n) && !Number.isSafeInteger(n)) {
    throw new Error(
      `canonicalize: integer ${n} is outside Number.MAX_SAFE_INTEGER range; cannot guarantee cross-impl determinism. Use a string if you need a larger integer.`,
    )
  }
  // RFC 8785 §3.2.2.3 references ECMAScript's Number-to-String algorithm.
  // JavaScript's String(n) implements that algorithm. -0 serializes as "0".
  // We normalize -0 explicitly to be safe across runtimes.
  if (Object.is(n, -0)) return '0'
  return String(n)
}

/**
 * Escape a string per RFC 8259 §7 with RFC 8785's mandate that non-ASCII
 * characters pass through unescaped (UTF-8 bytes on output).
 *
 * Required escapes:
 *   - " (U+0022) → \"
 *   - \ (U+005C) → \\
 *   - U+0008 → \b
 *   - U+0009 → \t
 *   - U+000A → \n
 *   - U+000C → \f
 *   - U+000D → \r
 *   - Other U+0000–U+001F → \u00XX (lowercase hex per RFC 8785 §3.2.2.2)
 *
 * Surrogate pairs in input strings: preserved as a UTF-16 pair, which JavaScript's
 * UTF-8 encoder (via Buffer.from(s, 'utf8')) will combine into the correct 4-byte
 * UTF-8 sequence for the codepoint. We do NOT \u-escape any character ≥ U+0020.
 */
function serializeString(s: string): string {
  let out = '"'
  for (let i = 0; i < s.length; i++) {
    const code = s.charCodeAt(i)
    if (code === 0x22) {
      out += '\\"'
    } else if (code === 0x5c) {
      out += '\\\\'
    } else if (code === 0x08) {
      out += '\\b'
    } else if (code === 0x09) {
      out += '\\t'
    } else if (code === 0x0a) {
      out += '\\n'
    } else if (code === 0x0c) {
      out += '\\f'
    } else if (code === 0x0d) {
      out += '\\r'
    } else if (code < 0x20) {
      // Other control chars
      out += '\\u' + code.toString(16).padStart(4, '0')
    } else if (code >= 0xd800 && code <= 0xdfff) {
      // UTF-16 surrogate. High surrogates (0xD800–0xDBFF) MUST be followed by a
      // low surrogate (0xDC00–0xDFFF). Lone surrogates would otherwise be
      // silently replaced by U+FFFD when Buffer.from(s, 'utf8') runs at the
      // canonicalize boundary, which breaks cross-implementation determinism
      // (a counterparty using a different UTF-8 encoder might keep them, or
      // reject them, or substitute differently). RFC 8785 §3.2.2.2 requires
      // valid UTF-16; reject malformed sequences explicitly here.
      if (code >= 0xd800 && code <= 0xdbff) {
        const next = i + 1 < s.length ? s.charCodeAt(i + 1) : -1
        if (next < 0xdc00 || next > 0xdfff) {
          throw new Error(
            `canonicalize: lone high surrogate at string index ${i} (code U+${code.toString(16).toUpperCase()}); valid UTF-16 required`,
          )
        }
        // Valid high+low surrogate pair: emit both code units; UTF-8 encoder
        // will produce the correct 4-byte sequence for the supplementary plane code point.
        out += s[i]! + s[i + 1]!
        i++ // skip the low surrogate, already consumed
      } else {
        // Lone low surrogate (no preceding high surrogate)
        throw new Error(
          `canonicalize: lone low surrogate at string index ${i} (code U+${code.toString(16).toUpperCase()}); valid UTF-16 required`,
        )
      }
    } else {
      // Non-ASCII and other chars pass through as-is
      out += s[i]
    }
  }
  out += '"'
  return out
}

function serializeArray(arr: unknown[]): string {
  if (arr.length === 0) return '[]'
  const parts: string[] = []
  for (const item of arr) {
    parts.push(serialize(item))
  }
  return '[' + parts.join(',') + ']'
}

function serializeObject(obj: Record<string, unknown>): string {
  // Sort keys lexicographically by UTF-16 code unit value (per RFC 8785 §3.2.3).
  // JavaScript's default Array.prototype.sort() on strings does exactly this.
  //
  // Skip own properties whose value is `undefined` — per RFC 8259 a JSON object
  // member cannot have an undefined value, so we treat them as absent.
  const keys = Object.keys(obj).filter((k) => obj[k] !== undefined).sort()
  if (keys.length === 0) return '{}'
  const parts: string[] = []
  for (const key of keys) {
    parts.push(serializeString(key) + ':' + serialize(obj[key]))
  }
  return '{' + parts.join(',') + '}'
}
