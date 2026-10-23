package com.cyberguard.av

import android.content.Context
import android.net.Uri
import android.provider.OpenableColumns
import java.io.ByteArrayOutputStream
import java.security.MessageDigest

data class FileResult(
    val name: String, val size: Long, val sha256: String,
    val level: Level, val reasons: List<String>
)

/** اسکن فایل انتخاب‌شده با Storage Access Framework (بدون نیاز به مجوز ذخیره‌سازی). */
object FileScanner {
    private const val EICAR_SHA = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
    private const val HEAD_MAX = 2 * 1024 * 1024
    private val DOUBLE = Regex(".*\\.(pdf|jpg|jpeg|png|doc|docx|mp4|txt)\\.(apk|exe|scr|bat|js|sh|vbs)$", RegexOption.IGNORE_CASE)
    private val EXEC = Regex(".*\\.(apk|dex|jar|exe|scr|bat|cmd|vbs|js|sh)$", RegexOption.IGNORE_CASE)

    fun scan(ctx: Context, uri: Uri): FileResult {
        val name = displayName(ctx, uri)
        val md = MessageDigest.getInstance("SHA-256")
        val head = ByteArrayOutputStream()
        var size = 0L
        val input = ctx.contentResolver.openInputStream(uri) ?: throw IllegalStateException("cannot open file")
        input.use { s ->
            val buf = ByteArray(64 * 1024)
            while (true) {
                val n = s.read(buf)
                if (n < 0) break
                md.update(buf, 0, n)
                size += n
                if (head.size() < HEAD_MAX) head.write(buf, 0, minOf(n, HEAD_MAX - head.size()))
            }
        }
        val sha = md.digest().joinToString("") { "%02x".format(it) }
        val bytes = head.toByteArray()
        val reasons = mutableListOf<String>()
        var threat = false
        var sus = false

        val sigName = Signatures.hashes[sha] ?: (if (sha == EICAR_SHA) "EICAR-Test-File" else null)
        if (sigName != null) { reasons += "امضای ویروس: $sigName"; threat = true }
        val text = String(bytes, Charsets.ISO_8859_1)
        if (text.contains("EICAR-STANDARD-ANTIVIRUS-TEST-FILE")) { reasons += "رشته‌ی تست EICAR داخل فایل"; threat = true }
        if (DOUBLE.matches(name)) { reasons += "پسوند دوگانه‌ی فریبنده"; threat = true }
        else if (EXEC.matches(name)) { reasons += "فایل اجرایی / نصبی"; sus = true }
        if (bytes.size > 1 && bytes[0] == 0x4D.toByte() && bytes[1] == 0x5A.toByte()) { reasons += "هدر اجرایی ویندوز (MZ)"; sus = true }
        if (bytes.size > 3 && bytes[0] == 0x7F.toByte() && bytes[1] == 0x45.toByte()) { reasons += "هدر اجرایی ELF"; sus = true }
        if (bytes.size > 3 && bytes[0] == 0x64.toByte() && bytes[1] == 0x65.toByte() &&
            bytes[2] == 0x78.toByte() && bytes[3] == 0x0A.toByte()) { reasons += "هدر DEX اندروید"; sus = true }

        val level = when { threat -> Level.THREAT; sus -> Level.SUSPICIOUS; else -> Level.CLEAN }
        return FileResult(name, size, sha, level, reasons)
    }

    private fun displayName(ctx: Context, uri: Uri): String =
        ctx.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { c ->
            if (c.moveToFirst()) c.getString(0) else null
        } ?: (uri.lastPathSegment ?: "file")
}
