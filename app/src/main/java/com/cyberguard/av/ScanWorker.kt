package com.cyberguard.av

import android.content.Context
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import java.util.concurrent.TimeUnit

class ScanWorker(ctx: Context, params: WorkerParameters) : CoroutineWorker(ctx, params) {
    override suspend fun doWork(): Result {
        val c = applicationContext
        Scanner.scanAll(c, heavy = false).findings.forEach {
            val title = if (it.level == Level.THREAT) "تهدید: ${it.label}" else "مشکوک: ${it.label}"
            Notifier.alert(c, it.pkg.hashCode(), title, it.reasons.joinToString(" · "))
        }
        UsageMonitor.heavyForeground(c).filter { it.pkg != c.packageName }.take(3).forEach {
            Notifier.alert(c, ("batt" + it.pkg).hashCode(), "مصرف غیرعادی باتری",
                "${it.pkg}: ${it.minutes} دقیقه در پیش‌زمینه (۲۴ ساعت گذشته)")
        }
        return Result.success()
    }

    companion object {
        fun schedule(ctx: Context) {
            WorkManager.getInstance(ctx).enqueueUniquePeriodicWork(
                "cyberguard-scan", ExistingPeriodicWorkPolicy.KEEP,
                PeriodicWorkRequestBuilder<ScanWorker>(15, TimeUnit.MINUTES).build()
            )
        }
    }
}
