package com.cyberguard.av

import android.content.ComponentName
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import android.provider.Settings
import java.io.File
import java.security.MessageDigest

enum class Level { CLEAN, SUSPICIOUS, THREAT }

data class Finding(
    val pkg: String,
    val label: String,
    val level: Level,
    val score: Int,
    val reasons: List<String>,
    val sha256: String? = null
)

/** پایگاه امضا. عمداً خالی است؛ از یک فید امضاشده/به‌روزشونده پر کن (سرور خودت، یا API هش مثل VirusTotal با کلید خودت). */
object Signatures {
    val hashes: MutableMap<String, String> = mutableMapOf()   // sha256(APK) -> family
    val packages: MutableMap<String, String> = mutableMapOf() // packageName -> family
}

object Scanner {
    private val RISKY = mapOf(
        "android.permission.SEND_SMS" to 3,
        "android.permission.READ_SMS" to 3,
        "android.permission.RECEIVE_SMS" to 2,
        "android.permission.READ_CALL_LOG" to 2,
        "android.permission.SYSTEM_ALERT_WINDOW" to 2,
        "android.permission.REQUEST_INSTALL_PACKAGES" to 2,
        "android.permission.MANAGE_EXTERNAL_STORAGE" to 2,
        "android.permission.RECORD_AUDIO" to 1,
        "android.permission.READ_CONTACTS" to 1,
        "android.permission.ACCESS_BACKGROUND_LOCATION" to 1
    )
    private val TRUSTED_INSTALLERS = setOf(
        "com.android.vending", "com.sec.android.app.samsungapps",
        "com.amazon.venezia", "org.fdroid.fdroid"
    )

    fun scanAll(
        ctx: Context,
        heavy: Boolean,
        onProgress: (done: Int, total: Int, pkg: String) -> Unit = { _, _, _ -> }
    ): List<Finding> {
        val pm = ctx.packageManager
        val a11y = accessibilityPackages(ctx)
        val pkgs = installed(pm)
        val out = ArrayList<Finding>()
        pkgs.forEachIndexed { i, p ->
            onProgress(i + 1, pkgs.size, p.packageName)
            val f = scanInfo(pm, p, heavy, a11y, includeSystem = false)
            if (f != null && f.level != Level.CLEAN) out += f
        }
        return out.sortedByDescending { it.score }
    }

    fun scanPackage(ctx: Context, pkg: String, heavy: Boolean): Finding? {
        val pm = ctx.packageManager
        val info = try { pkgInfo(pm, pkg) } catch (e: Exception) { return null }
        return scanInfo(pm, info, heavy, accessibilityPackages(ctx), includeSystem = true)
    }

    private fun scanInfo(
        pm: PackageManager, p: PackageInfo, heavy: Boolean,
        a11y: Set<String>, includeSystem: Boolean
    ): Finding? {
        val ai = p.applicationInfo ?: return null
        val system = ai.flags and ApplicationInfo.FLAG_SYSTEM != 0
        if (system && !heavy && !includeSystem) return null

        val reasons = mutableListOf<String>()
        var score = 0
        var level = Level.CLEAN
        var hash: String? = null
        val label = pm.getApplicationLabel(ai).toString()

        Signatures.packages[p.packageName]?.let {
            reasons += "Signature: $it"; level = Level.THREAT; score += 10
        }
        if (heavy) {
            hash = try { sha256(File(ai.sourceDir)) } catch (e: Exception) { null }
            Signatures.hashes[hash]?.let {
                reasons += "Hash match: $it"; level = Level.THREAT; score += 10
            }
        }

        var hasSms = false
        p.requestedPermissions?.forEach { perm ->
            RISKY[perm]?.let { w ->
                score += w; reasons += perm.substringAfterLast('.')
                if (perm.endsWith("SMS")) hasSms = true
            }
        }
        val a11yOn = p.packageName in a11y
        if (a11yOn) { score += 4; reasons += "Accessibility service enabled" }
        if (hasSms && a11yOn) { score += 3; reasons += "SMS + Accessibility (banking-trojan pattern)" }

        if (!system) {
            val inst = installer(pm, p.packageName)
            if (inst == null || inst !in TRUSTED_INSTALLERS) {
                score += 2; reasons += "Sideloaded (${inst ?: "unknown source"})"
            }
        }

        if (level != Level.THREAT && score >= 8) level = Level.SUSPICIOUS
        return Finding(p.packageName, label, level, score, reasons, hash)
    }

    fun accessibilityPackages(ctx: Context): Set<String> {
        val raw = Settings.Secure.getString(
            ctx.contentResolver, Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES
        ) ?: return emptySet()
        return raw.split(':').mapNotNull { ComponentName.unflattenFromString(it)?.packageName }.toSet()
    }

    private fun installed(pm: PackageManager): List<PackageInfo> {
        val flags = PackageManager.GET_PERMISSIONS
        return if (Build.VERSION.SDK_INT >= 33)
            pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(flags.toLong()))
        else @Suppress("DEPRECATION") pm.getInstalledPackages(flags)
    }

    private fun pkgInfo(pm: PackageManager, pkg: String): PackageInfo {
        val flags = PackageManager.GET_PERMISSIONS
        return if (Build.VERSION.SDK_INT >= 33)
            pm.getPackageInfo(pkg, PackageManager.PackageInfoFlags.of(flags.toLong()))
        else @Suppress("DEPRECATION") pm.getPackageInfo(pkg, flags)
    }

    private fun installer(pm: PackageManager, pkg: String): String? = try {
        if (Build.VERSION.SDK_INT >= 30) pm.getInstallSourceInfo(pkg).installingPackageName
        else @Suppress("DEPRECATION") pm.getInstallerPackageName(pkg)
    } catch (e: Exception) { null }

    fun sha256(f: File): String {
        val md = MessageDigest.getInstance("SHA-256")
        f.inputStream().use { s ->
            val buf = ByteArray(64 * 1024)
            while (true) {
                val n = s.read(buf)
                if (n < 0) break
                md.update(buf, 0, n)
            }
        }
        return md.digest().joinToString("") { "%02x".format(it) }
    }
}
