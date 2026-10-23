package com.cyberguard.av

import android.app.AppOpsManager
import android.app.usage.UsageStatsManager
import android.content.Context
import android.content.Intent
import android.os.BatteryManager
import android.os.Build
import android.os.Process
import android.provider.Settings

/**
 * توجه: اندروید API عمومی «درصد باتری مصرف‌شده توسط هر برنامه» به اپ‌های ثالث نمی‌دهد.
 * راه عملی: زمان حضور در پیش‌زمینه (UsageStatsManager) به‌عنوان نماینده مصرف + افت باتری دستگاه.
 */
object UsageMonitor {
    data class Heavy(val pkg: String, val minutes: Long)

    fun hasAccess(ctx: Context): Boolean {
        val ops = ctx.getSystemService(Context.APP_OPS_SERVICE) as AppOpsManager
        val mode = if (Build.VERSION.SDK_INT >= 29)
            ops.unsafeCheckOpNoThrow(AppOpsManager.OPSTR_GET_USAGE_STATS, Process.myUid(), ctx.packageName)
        else @Suppress("DEPRECATION")
            ops.checkOpNoThrow(AppOpsManager.OPSTR_GET_USAGE_STATS, Process.myUid(), ctx.packageName)
        return mode == AppOpsManager.MODE_ALLOWED
    }

    fun openSettings(ctx: Context) {
        ctx.startActivity(Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
    }

    fun heavyForeground(ctx: Context, thresholdMin: Long = 180): List<Heavy> {
        if (!hasAccess(ctx)) return emptyList()
        val usm = ctx.getSystemService(Context.USAGE_STATS_SERVICE) as UsageStatsManager
        val end = System.currentTimeMillis()
        val stats = usm.queryUsageStats(UsageStatsManager.INTERVAL_DAILY, end - 24 * 3_600_000L, end) ?: return emptyList()
        return stats.groupBy { it.packageName }
            .map { (pkg, list) -> Heavy(pkg, list.sumOf { it.totalTimeInForeground } / 60_000) }
            .filter { it.minutes >= thresholdMin }
            .sortedByDescending { it.minutes }
    }

    fun batteryPercent(ctx: Context): Int {
        val bm = ctx.getSystemService(Context.BATTERY_SERVICE) as BatteryManager
        return bm.getIntProperty(BatteryManager.BATTERY_PROPERTY_CAPACITY)
    }
}
