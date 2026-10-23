package com.cyberguard.av

import android.app.admin.DevicePolicyManager
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
    val system: Boolean,
    val sha256: String? = null
)

data class ScanReport(
    val findings: List<Finding>,
    val scanned: Int,
    val total: Int,
    val durationMs: Long,
    val stopped: Boolean,
    val heavy: Boolean
)

/** پایگاه امضا. عمداً خالی است؛ از یک فید امضاشده/به‌روزشونده پر کن (سرور خودت، یا API هش مثل VirusTotal با کلید خودت). */
object Signatures {
    val hashes: MutableMap<String, String> = mutableMapOf()   // sha256 -> family
    val packages: MutableMap<String, String> = mutableMapOf() // packageName -> family
}

internal class Env(val a11y: Set<String>, val admins: Set<String>, val listeners: Set<String>)

/**
 * منطق تشخیص (برای جلوگیری از هشدار اشتباه روی برنامه‌های عادی مثل تلگرام):
 *  1) امضای شناخته‌شده‌ی ویروس  → همیشه «ویروس».
 *  2) برنامه‌ی سیستمی یا نصب‌شده از فروشگاه معتبر (پلی‌استور…) → فقط با امضا شناسایی می‌شود؛ مجوز تنها هرگز هشدار نمی‌دهد.
 *  3) برنامه‌ی نصب‌شده از منبع ناشناس → امتیاز رفتاری: مجوزها (سقف ۵) + قابلیت‌های خطرناک
 *     (دسترسی‌پذیری، مدیر دستگاه، خواندن اعلان‌ها، بدون آیکون) . ≥۸ مشکوک، ≥۱۴ ویروس.
 */
object Scanner {
    private const val THREAT_SCORE = 14
    private const val SUSPICIOUS_SCORE = 8
    private const val PERM_CAP = 5

    private val RISKY: Map<String, Pair<Int, String>> = mapOf(
        "android.permission.SEND_SMS" to (3 to "می‌تواند پیامک بفرستد (هزینه‌زا / پخش بدافزار)"),
        "android.permission.READ_SMS" to (3 to "می‌تواند پیامک‌ها و کدهای تأیید را بخواند"),
        "android.permission.RECEIVE_SMS" to (2 to "می‌تواند پیامک‌های ورودی را دریافت کند"),
        "android.permission.READ_CALL_LOG" to (2 to "به تاریخچه‌ی تماس‌ها دسترسی دارد"),
        "android.permission.SYSTEM_ALERT_WINDOW" to (2 to "می‌تواند روی برنامه‌های دیگر نمایش دهد (فیشینگ)"),
        "android.permission.REQUEST_INSTALL_PACKAGES" to (2 to "می‌تواند برنامه‌ی دیگر نصب کند"),
        "android.permission.MANAGE_EXTERNAL_STORAGE" to (2 to "دسترسی کامل به همه‌ی فایل‌ها"),
        "android.permission.RECORD_AUDIO" to (1 to "دسترسی به میکروفن"),
        "android.permission.READ_CONTACTS" to (1 to "دسترسی به مخاطبین"),
        "android.permission.ACCESS_BACKGROUND_LOCATION" to (1 to "موقعیت مکانی در پس‌زمینه")
    )
    private val TRUSTED_INSTALLERS = setOf(
        "com.android.vending", "com.sec.android.app.samsungapps",
        "com.amazon.venezia", "org.fdroid.fdroid"
    )

    /** امتیاز مجوزها (با سقف) + توضیح فارسی؛ برای APKهای نصب‌نشده هم استفاده می‌شود. */
    fun permissionScore(perms: Array<String>?): Pair<Int, List<String>> {
        var s = 0
        val r = ArrayList<String>()
        perms?.forEach { perm ->
            RISKY[perm]?.let { (w, text) -> s += w; r += text }
        }
        return Pair(minOf(s, PERM_CAP), r)
    }

    fun scanAll(
        ctx: Context,
        heavy: Boolean,
        shouldStop: () -> Boolean = { false },
        onProgress: (done: Int, total: Int, pkg: String) -> Unit = { _, _, _ -> }
    ): ScanReport {
        val t0 = System.currentTimeMillis()
        val pm = ctx.packageManager
        val env = buildEnv(ctx)
        val ignored = Store.ignored(ctx)
        val pkgs = installed(pm)
        val out = ArrayList<Finding>()
        var done = 0
        var stopped = false
        for (p in pkgs) {
            if (shouldStop()) { stopped = true; break }
            done++
            onProgress(done, pkgs.size, p.packageName)
            if (p.packageName == ctx.packageName || p.packageName in ignored) continue
            val f = (try { scanInfo(pm, p, heavy, env, includeSystem = false) } catch (e: Exception) { null }) ?: continue
            if (f.level != Level.CLEAN) out += f
            Thread.sleep(if (heavy) 12L else 35L) // سرعت نمایشی تا بشود اسکن را دید و متوقف کرد
        }
        return ScanReport(out.sortedByDescending { it.score }, done, pkgs.size,
            System.currentTimeMillis() - t0, stopped, heavy)
    }

    fun scanPackage(ctx: Context, pkg: String, heavy: Boolean): Finding? {
        val pm = ctx.packageManager
        val info = try { pkgInfo(pm, pkg) } catch (e: Exception) { return null }
        return scanInfo(pm, info, heavy, buildEnv(ctx), includeSystem = true)
    }

    private fun scanInfo(
        pm: PackageManager, p: PackageInfo, heavy: Boolean, env: Env, includeSystem: Boolean
    ): Finding? {
        val ai = p.applicationInfo ?: return null
        val system = ai.flags and ApplicationInfo.FLAG_SYSTEM != 0
        if (system && !heavy && !includeSystem) return null

        val pkg = p.packageName
        val label = pm.getApplicationLabel(ai).toString()
        val reasons = mutableListOf<String>()
        var sig = false
        var hash: String? = null

        Signatures.packages[pkg]?.let { reasons += "امضای ویروس شناخته‌شده: $it"; sig = true }
        if (heavy && !system) {
            val h = try { sha256(File(ai.sourceDir)) } catch (e: Exception) { null }
            hash = h
            if (h != null) {
                Signatures.hashes[h]?.let { reasons += "هش APK با ویروس «$it» یکی است"; sig = true }
            }
        }

        val inst = if (system) null else installer(pm, pkg)
        val fromStore = !system && inst != null && inst in TRUSTED_INSTALLERS

        // برنامه‌ی سیستمی یا فروشگاهی: فقط امضای ویروس
        if (sig) return Finding(pkg, label, Level.THREAT, 20, reasons, system, hash)
        if (system || fromStore) return Finding(pkg, label, Level.CLEAN, 0, reasons, system, hash)

        // منبع ناشناس: امتیاز رفتاری
        val (permScore, permReasons) = permissionScore(p.requestedPermissions)
        var score = permScore
        reasons += permReasons
        val hasSms = p.requestedPermissions?.any { it.endsWith("_SMS") } == true
        val a11yOn = pkg in env.a11y

        if (a11yOn) { score += 4; reasons += "سرویس دسترسی‌پذیری فعال (می‌تواند صفحه را بخواند و کلیک کند)" }
        if (pkg in env.admins) { score += 4; reasons += "مدیر دستگاه فعال است (حذفش سخت می‌شود)" }
        if (pkg in env.listeners) { score += 3; reasons += "به همه‌ی اعلان‌ها دسترسی دارد (کدهای تأیید)" }
        if (hasSms && a11yOn) { score += 3; reasons += "ترکیب پیامک + دسترسی‌پذیری (الگوی تروجان بانکی)" }
        if (pm.getLaunchIntentForPackage(pkg) == null) { score += 3; reasons += "آیکون ندارد و پنهان است" }
        score += 1
        reasons += "نصب از منبع ناشناس (${inst ?: "نامعلوم"})"

        val level = when {
            score >= THREAT_SCORE -> Level.THREAT
            score >= SUSPICIOUS_SCORE -> Level.SUSPICIOUS
            else -> Level.CLEAN
        }
        return Finding(pkg, label, level, score, reasons, false, hash)
    }

    private fun buildEnv(ctx: Context): Env {
        val dpm = ctx.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager
        val admins = dpm.activeAdmins?.map { it.packageName }?.toSet() ?: emptySet()
        return Env(
            componentPkgs(ctx, Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES),
            admins,
            componentPkgs(ctx, "enabled_notification_listeners")
        )
    }

    private fun componentPkgs(ctx: Context, key: String): Set<String> {
        val raw = Settings.Secure.getString(ctx.contentResolver, key) ?: return emptySet()
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
