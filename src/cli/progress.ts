/**
 * Terminal progress helpers for the CLI: a spinner for short indeterminate waits
 * and duration formatting for the `finalize --watch` countdown.
 *
 * Everything here is gated on `process.stderr.isTTY`. When stderr is a pipe
 * (CI, `2>log`, a parent process capturing output) the spinner is silent by
 * default and the countdown collapses to one plain line per cycle, so logs stay
 * readable and the byte stream a caller parses is never polluted with carriage
 * returns or ANSI codes. All output goes to stderr; stdout is reserved for
 * machine-readable results.
 */

const FRAMES = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
const HIDE_CURSOR = '\x1b[?25l'
const SHOW_CURSOR = '\x1b[?25h'
const CLEAR_LINE = '\r\x1b[2K'

let cursorRestoreInstalled = false

/**
 * Restore the cursor on process exit and on Ctrl-C, exactly once. A spinner
 * hides the cursor while it animates; if the process dies mid-spin (or the user
 * interrupts) the terminal would otherwise be left with an invisible cursor.
 */
function ensureCursorRestore(): void {
  if (cursorRestoreInstalled) return
  cursorRestoreInstalled = true
  const restore = (): void => {
    if (process.stderr.isTTY) process.stderr.write(SHOW_CURSOR)
  }
  process.on('exit', restore)
  process.on('SIGINT', () => {
    restore()
    // 130 = terminated by SIGINT, the conventional shell exit status.
    process.exit(130)
  })
}

/**
 * Start an indeterminate spinner with `label`. Returns a stop function that
 * clears the spinner line (TTY) or does nothing (non-TTY). Safe to call stop
 * more than once.
 *
 * On a non-TTY the spinner is silent by default — a pipe/CI log gets no extra
 * bytes. Pass `quietLabel: true` only where the pre-spinner code already printed
 * this label unconditionally, so non-interactive output stays byte-identical.
 */
export function startSpinner(label: string, opts?: { quietLabel?: boolean }): () => void {
  const stream = process.stderr
  if (!stream.isTTY) {
    if (opts?.quietLabel) stream.write(label + '\n')
    return () => {}
  }
  ensureCursorRestore()
  let i = 0
  stream.write(HIDE_CURSOR)
  const render = (): void => {
    stream.write(`\r${FRAMES[i++ % FRAMES.length]} ${label}`)
  }
  render()
  const timer = setInterval(render, 80)
  // Don't let the spinner alone keep the event loop alive.
  timer.unref?.()
  let stopped = false
  return () => {
    if (stopped) return
    stopped = true
    clearInterval(timer)
    stream.write(CLEAR_LINE + SHOW_CURSOR)
  }
}

/** Format a duration in seconds as `1h05m`, `12m03s`, or `45s`. */
export function formatDuration(totalSeconds: number): string {
  const s = Math.max(0, Math.round(totalSeconds))
  const h = Math.floor(s / 3600)
  const m = Math.floor((s % 3600) / 60)
  const sec = s % 60
  if (h > 0) return `${h}h${String(m).padStart(2, '0')}m`
  if (m > 0) return `${m}m${String(sec).padStart(2, '0')}s`
  return `${sec}s`
}

const delay = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms))

/**
 * Wait `intervalSeconds` before the next poll, showing a live countdown.
 *
 * On a TTY the line updates every second: `⧗ pending · elapsed 12m03s · next
 * check in 08m20s`. On a non-TTY it prints a single line (no per-second spam) so
 * `finalize --watch 2>log` produces one tidy entry per cycle.
 */
export async function countdownSleep(
  intervalSeconds: number,
  elapsedSeconds: number,
): Promise<void> {
  const stream = process.stderr
  if (!stream.isTTY) {
    stream.write(
      `⧗ still pending (elapsed ${formatDuration(elapsedSeconds)}); next check in ${formatDuration(intervalSeconds)}…\n`,
    )
    await delay(intervalSeconds * 1000)
    return
  }
  for (let remaining = intervalSeconds; remaining > 0; remaining--) {
    const elapsed = elapsedSeconds + (intervalSeconds - remaining)
    stream.write(
      `\r\x1b[2K⧗ pending · elapsed ${formatDuration(elapsed)} · next check in ${formatDuration(remaining)}`,
    )
    await delay(1000)
  }
  stream.write(CLEAR_LINE)
}
