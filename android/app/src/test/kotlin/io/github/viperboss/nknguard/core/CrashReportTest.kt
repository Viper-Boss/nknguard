package io.github.viperboss.nknguard.core

import org.junit.Assert.*
import org.junit.Test

class CrashReportTest {
    @Test fun excerptIsBoundedAndStopsAtExit() {
        val lines = listOf("ordinary log", "panic: send on closed channel", "goroutine 1", "source.go:12", "core exited with status 2", "new process")
        assertEquals(listOf("panic: send on closed channel", "goroutine 1", "source.go:12"), CrashReport.extract(lines))
        assertTrue(CrashReport.extract(listOf("ordinary log")).isEmpty())
        assertEquals(80, CrashReport.extract(listOf("panic: crash") + List(100) { "stack" }).size)
    }

    @Test fun secretMaterialIsNotExported() {
        val report = CrashReport.extract(listOf("panic: crash", "seed=secret-material", "a".repeat(64), "A".repeat(43)+"="))
        assertFalse(report.joinToString().contains("secret-material"))
        assertFalse(report.joinToString().contains("a".repeat(64)))
        assertFalse(report.joinToString().contains("A".repeat(43)))
    }
}
