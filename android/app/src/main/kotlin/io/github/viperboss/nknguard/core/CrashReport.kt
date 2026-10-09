package io.github.viperboss.nknguard.core

/** A bounded, redacted excerpt from the existing memory log, never a file. */
object CrashReport {
    fun extract(lines: List<String>): List<String> {
        val start = lines.indexOfLast { it.startsWith("panic:") || it.startsWith("fatal error:") }
        if (start < 0) return emptyList()
        return lines.drop(start).take(80).takeWhile { !it.startsWith("core exited with status") }
            .map { line ->
                if (Regex("(?i)password|private.?key|secret|seed|token").containsMatchIn(line)) {
                    "[sensitive crash line omitted]"
                } else {
                    line.take(1024)
                        .replace(Regex("[a-fA-F0-9]{64,}"), "[redacted hex]")
                        .replace(Regex("[A-Za-z0-9+/]{43,}={0,2}"), "[redacted key]")
                }
            }
    }
}
