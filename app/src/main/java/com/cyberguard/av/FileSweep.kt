package com.cyberguard.av

import android.Manifest
import android.content.Context
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import android.os.Environment
import android.os.StatFs
import androidx.core.content.ContextCompat
import java.io.ByteArrayOutputStream
import java.io.File
import java.nio.file.Files
import java.security.MessageDigest

data class FileFinding(
    val path: String, val name: String, val size: Long,
    val level: Level, val reasons: List<String>
)

/** اسکن سنگین فایل‌ها: کل حافظه‌ی داخلی (/storage/emulated/0) را می‌گردد. */
object FileSweep {
    data class Result(val findings: List<FileFinding>, val filesSeen: Int, val stopped: Boolean)

    private const val EICAR_SHA = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
    private val WIN_EXEC = setOf("exe", "scr", "bat", "cmd", "vbs", "msi", "com", "pif", "jse", "wsf", "ps1")
    private val EXEC_EXT = WIN_EXEC + setOf("apk", "dex", "jar", "js", "sh")
    private val MEDIA_EXT = setOf("jpg", "jpeg", "png", "gif", "webp", "heic", "mp3", "mp4", "mkv", "avi",
        "mov", "m4a", "wav", "aac", "flac", "3gp", "webm", "ogg")
    private val DISGUISE_EXT = MEDIA_EXT + setOf("pdf", "txt", "doc", "docx", "xls", "xlsx", "ppt", "pptx")
    private val DOUBLE = Regex(
        ".*\\.(pdf|jpg|jpeg|png|gif|doc|docx|mp3|mp4|txt)\\.(apk|exe|scr|bat|js|sh|vbs|cmd|com|pif)$",
        RegexOption.IGNORE_CASE
    )
    private val SKIP_DIRS = setOf("/Android/data", "/Android/obb")

    fun hasAccess(ctx: Context): Boolean =
        if (Build.VERSION.SDK_INT >= 30) Environment.isExternalStorageManager()
        else ContextCompat.checkSelfPermission(ctx, Manifest.permission.READ_EXTERNAL_STORAGE) == PackageManager.PERMISSION_GRANTED &&
            ContextCompat.checkSelfPermission(ctx, Manifest.permission.WRITE_EXTERNAL_STORAGE) == PackageManager.PERMISSION_GRANTED

    fun delete(path: String): Boolean = try { File(path).delete() } catch (e: Exception) { false }

    fun sweep(
        ctx: Context,
        ignored: Set<String>,
        shouldStop: () -> Boolean,
        onProgress: (pct: Int, seen: Int, path: String) -> Unit
    ): Result {
        val root = Environment.getExternalStorageDirectory()
        val stat = StatFs(root.path)
        val used = (stat.totalBytes - stat.availableBytes).coerceAtLeast(1L)
        val rootPath = root.absolutePath
        val stack = ArrayDeque<File>()
        stack.addLast(root)
        val out = ArrayList<FileFinding>()
        var seen = 0
        var bytes = 0L
        var stopped = false

        while (stack.isNotEmpty() && !stopped) {
            val dir = stack.removeLast()
            val kids = dir.listFiles() ?: continue
            for (f in kids) {
                if (shouldStop()) { stopped = true; break }
                if (f.isDirectory) {
                    val rel = f.absolutePath.removePrefix(rootPath)
                    if (rel in SKIP_DIRS) continue
                    val link = try { Files.isSymbolicLink(f.toPath()) } catch (e: Exception) { true }
                    if (!link) stack.addLast(f)
                    continue
                }
                seen++
                bytes += f.length()
                if (f.absolutePath !in ignored) analyze(ctx, f)?.let { out += it }
                if (seen % 25 == 0) onProgress(minOf(99, (bytes * 100 / used).toInt()), seen, f.absolutePath)
            }
        }
        onProgress(100, seen, rootPath)
        return Result(out.sortedWith(compareByDescending<FileFinding> { it.level }.thenBy { it.name }), seen, stopped)
    }

    private fun analyze(ctx: Context, f: File): FileFinding? {
        val name = f.name
        val ext = name.substringAfterLast('.', "").lowercase()
        val size = f.length()
        val reasons = ArrayList<String>()
        var threat = false
        var sus = false

        if (DOUBLE.matches(name)) { reasons += "پسوند دوگانه‌ی فریبنده"; threat = true }
        val isExec = ext in EXEC_EXT

        val hashIt = (isExec && size <= 300L * 1024 * 1024) || (size <= 100L * 1024 && ext !in MEDIA_EXT)
        if (hashIt) {
            val hh = hashAndHead(f)
            if (hh != null) {
                val sig = Signatures.hashes[hh.first] ?: (if (hh.first == EICAR_SHA) "EICAR-Test-File" else null)
                if (sig != null) { reasons += "امضای ویروس: $sig"; threat = true }
                if (hh.second.size <= 128 * 1024 &&
                    String(hh.second, Charsets.ISO_8859_1).contains("EICAR-STANDARD-ANTIVIRUS-TEST-FILE")) {
                    reasons += "رشته‌ی تست EICAR داخل فایل"; threat = true
                }
            }
        }

        if (!isExec && ext in DISGUISE_EXT && size > 4) {
            val kind = sniff(f)
            if (kind != null) { reasons += "$kind با پسوند ساختگی .$ext"; threat = true }
        }

        if (ext in WIN_EXEC) { reasons += "فایل اجرایی ویندوز روی گوشی (معمولاً بدافزار منتقل‌شده)"; sus = true }
        if (name.startsWith(".") && isExec) { reasons += "فایل اجرایی پنهان"; sus = true }

        if (ext == "apk" && size <= 150L * 1024 * 1024) {
            val pi = archiveInfo(ctx.packageManager, f.absolutePath)
            if (pi != null) {
                Signatures.packages[pi.packageName]?.let { reasons += "امضای ویروس: $it"; threat = true }
                val (sc, rs) = Scanner.permissionScore(pi.requestedPermissions)
                if (sc >= 5) {
                    reasons += "APK نصب‌نشده با مجوزهای پرخطر:"
                    rs.forEach { reasons += "  – $it" }
                    sus = true
                }
            }
        }

        if (!threat && !sus) return null
        return FileFinding(f.absolutePath, name, size, if (threat) Level.THREAT else Level.SUSPICIOUS, reasons)
    }

    private fun hashAndHead(f: File): Pair<String, ByteArray>? = try {
        val md = MessageDigest.getInstance("SHA-256")
        val head = ByteArrayOutputStream()
        f.inputStream().use { s ->
            val buf = ByteArray(64 * 1024)
            while (true) {
                val n = s.read(buf)
                if (n < 0) break
                md.update(buf, 0, n)
                if (head.size() < 128 * 1024) head.write(buf, 0, minOf(n, 128 * 1024 - head.size()))
            }
        }
        Pair(md.digest().joinToString("") { "%02x".format(it) }, head.toByteArray())
    } catch (e: Exception) { null }

    private fun sniff(f: File): String? = try {
        val b = ByteArray(4)
        val n = f.inputStream().use { it.read(b) }
        when {
            n >= 2 && b[0] == 0x4D.toByte() && b[1] == 0x5A.toByte() -> "فایل اجرایی ویندوز (MZ)"
            n >= 4 && b[0] == 0x7F.toByte() && b[1] == 0x45.toByte() -> "فایل اجرایی ELF"
            n >= 4 && b[0] == 0x64.toByte() && b[1] == 0x65.toByte() && b[2] == 0x78.toByte() && b[3] == 0x0A.toByte() -> "کد DEX اندروید"
            else -> null
        }
    } catch (e: Exception) { null }

    private fun archiveInfo(pm: PackageManager, path: String): PackageInfo? = try {
        if (Build.VERSION.SDK_INT >= 33)
            pm.getPackageArchiveInfo(path, PackageManager.PackageInfoFlags.of(PackageManager.GET_PERMISSIONS.toLong()))
        else @Suppress("DEPRECATION") pm.getPackageArchiveInfo(path, PackageManager.GET_PERMISSIONS)
    } catch (e: Exception) { null }
}
