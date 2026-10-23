package com.cyberguard.av

import android.app.ActivityManager
import android.content.Context
import android.os.BatteryManager
import android.os.Environment
import android.os.StatFs

object DeviceHealth {
    data class Snap(
        val battery: Int, val charging: Boolean,
        val storageFreeGb: Double, val storageTotalGb: Double,
        val ramFreeMb: Long, val ramTotalMb: Long
    )

    fun snapshot(ctx: Context): Snap {
        val bm = ctx.getSystemService(Context.BATTERY_SERVICE) as BatteryManager
        val st = StatFs(Environment.getDataDirectory().path)
        val gb = 1024.0 * 1024.0 * 1024.0
        val am = ctx.getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager
        val mi = ActivityManager.MemoryInfo()
        am.getMemoryInfo(mi)
        return Snap(
            bm.getIntProperty(BatteryManager.BATTERY_PROPERTY_CAPACITY), bm.isCharging,
            st.availableBytes / gb, st.totalBytes / gb,
            mi.availMem / 1048576, mi.totalMem / 1048576
        )
    }
}
