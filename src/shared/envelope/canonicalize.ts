/**
 * Cross-runtime clean-room implementation of RFC 8785 JSON Canonicalization Scheme (JCS).
 *
 * Spec: https://datatracker.ietf.org/doc/html/rfc8785
 *
 * Browser-portable port of src/envelope/canonicalize.ts. The string-building logic is
 * 100% identical (pure JS); the only difference is the final UTF-8 byte conversion uses
 * `TextEncoder` (Web standard, available in both Node 20+ and every evergreen browser)
 * instead of Node's `Buffer.from(s, 'utf8')`.
 *
 * BYTE-EQUIVALENCE GUARANTEE: cross-impl test enforces byte-identical output vs.
 * src/envelope/canonicalize.ts on every CI run. Divergence is a hard CI failure.
 *
 * This implementation is COMMITMENT-BEARING. Any deviation from RFC 8785 produces
 * hashes that other compliant implementations cannot reproduce.
 *
 * Limitations vs full RFC 8785:
 *  - NaN, Infinity, -Infinity: throw (per RFC 8785 §3.2.2.3)
 *  - Non-finite or unsafe number values: throw
 *  - bigint: not supported
 *  - undefined as a value: throw
 *  - Object keys that are not strings: not possible in plain JSON
 */

const UTF8_ENCODER = new TextEncoder()

/**
 * Canonicalize a JSON-serializable value into a UTF-8 byte sequence per RFC 8785.
 * Returns Uint8Array (cross-runtime portable).
 *
 * @throws Error if the value contains NaN, Infinity, undefined, or other non-JSON values.
 */
export function canonicalize(value: unknown): Uint8Array {
  return UTF8_ENCODER.encode(canonicalizeToString(value))
}

/**
 * Same as `canonicalize` but returns the string form. Pure logic; identical between
 * src/envelope/ and src/shared/envelope/.
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
  if (Number.isInteger(n) && !Number.isSafeInteger(n)) {
    throw new Error(
      `canonicalize: integer ${n} is outside Number.MAX_SAFE_INTEGER range; cannot guarantee cross-impl determinism. Use a string if you need a larger integer.`,
    )
  }
  if (Object.is(n, -0)) return '0'
  return String(n)
}

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
      out += '\\u' + code.toString(16).padStart(4, '0')
    } else if (code >= 0xd800 && code <= 0xdfff) {
      if (code >= 0xd800 && code <= 0xdbff) {
        const next = i + 1 < s.length ? s.charCodeAt(i + 1) : -1
        if (next < 0xdc00 || next > 0xdfff) {
          throw new Error(
            `canonicalize: lone high surrogate at string index ${i} (code U+${code.toString(16).toUpperCase()}); valid UTF-16 required`,
          )
        }
        out += s[i]! + s[i + 1]!
        i++
      } else {
        throw new Error(
          `canonicalize: lone low surrogate at string index ${i} (code U+${code.toString(16).toUpperCase()}); valid UTF-16 required`,
        )
      }
    } else {
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
  const keys = Object.keys(obj).filter((k) => obj[k] !== undefined).sort()
  if (keys.length === 0) return '{}'
  const parts: string[] = []
  for (const key of keys) {
    parts.push(serializeString(key) + ':' + serialize(obj[key]))
  }
  return '{' + parts.join(',') + '}'
}
