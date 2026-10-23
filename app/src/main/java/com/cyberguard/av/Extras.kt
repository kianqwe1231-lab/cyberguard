package com.cyberguard.av

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.wifi.WifiManager
import android.os.Build

/** بررسی نوع رمزنگاری Wi-Fi فعلی (نیاز به اندروید ۱۲+ برای تشخیص دقیق). */
object WifiAudit {
    data class Info(val label: String, val level: Level, val note: String)

    fun check(ctx: Context): Info {
        try {
            val cm = ctx.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            val caps = cm.getNetworkCapabilities(cm.activeNetwork)
            if (caps == null || !caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI))
                return Info("به Wi-Fi وصل نیستی", Level.CLEAN, "")
            if (Build.VERSION.SDK_INT < 31)
                return Info("Wi-Fi وصل است", Level.CLEAN, "تشخیص نوع رمزنگاری نیاز به اندروید ۱۲ یا بالاتر دارد.")
            val wm = ctx.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
            @Suppress("DEPRECATION")
            val type = wm.connectionInfo.currentSecurityType
            return when (type) {
                0 -> Info("شبکه‌ی باز (بدون رمز)", Level.THREAT, "هر کسی می‌تواند ترافیکت را ببیند. از بانک و ورود به حساب‌ها خودداری کن یا VPN بزن.")
                1 -> Info("WEP (قدیمی و ناامن)", Level.THREAT, "در چند دقیقه شکسته می‌شود. به روتر بگو WPA2/WPA3 بگذارد.")
                2 -> Info("WPA2 / WPA", Level.CLEAN, "رمزنگاری استاندارد است.")
                4 -> Info("WPA3", Level.CLEAN, "امن‌ترین نوع رایج.")
                3 -> Info("سازمانی (Enterprise)", Level.CLEAN, "")
                5 -> Info("Enhanced Open (OWE)", Level.CLEAN, "رمزنگاری بدون رمز عبور.")
                else -> Info("نوع نامشخص", Level.SUSPICIOUS, "نوع رمزنگاری قابل تشخیص نبود.")
            }
        } catch (e: Exception) {
            return Info("نتوانستم بررسی کنم", Level.CLEAN, "")
        }
    }
}

/** ممیزی حریم خصوصی: کدام برنامه‌ها واقعاً مجوز حساس را «گرفته‌اند». */
object PrivacyAudit {
    data class Result(
        val mic: List<String>, val camera: List<String>,
        val location: List<String>, val sms: List<String>
    )

    fun run(ctx: Context): Result {
        val pm = ctx.packageManager
        val flags = PackageManager.GET_PERMISSIONS
        val pkgs = if (Build.VERSION.SDK_INT >= 33)
            pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(flags.toLong()))
        else @Suppress("DEPRECATION") pm.getInstalledPackages(flags)
        val mic = mutableSetOf<String>()
        val camera = mutableSetOf<String>()
        val location = mutableSetOf<String>()
        val sms = mutableSetOf<String>()
        for (p in pkgs) {
            val ai = p.applicationInfo ?: continue
            if (ai.flags and ApplicationInfo.FLAG_SYSTEM != 0) continue
            val perms = p.requestedPermissions ?: continue
            val fl = p.requestedPermissionsFlags ?: continue
            val label = pm.getApplicationLabel(ai).toString()
            for (i in perms.indices) {
                if (i >= fl.size) break
                if (fl[i] and PackageInfo.REQUESTED_PERMISSION_GRANTED == 0) continue
                when (perms[i]) {
                    "android.permission.RECORD_AUDIO" -> mic += label
                    "android.permission.CAMERA" -> camera += label
                    "android.permission.ACCESS_FINE_LOCATION",
                    "android.permission.ACCESS_COARSE_LOCATION" -> location += label
                    "android.permission.READ_SMS" -> sms += label
                }
            }
        }
        return Result(mic.sorted(), camera.sorted(), location.sorted(), sms.sorted())
    }
}
