package com.cyberguard.av

import java.net.URI

/** تحلیل ظاهری لینک (فیشینگ). تضمین امنیت نیست؛ بعداً به Safe Browsing/فید دامنه‌های بد وصل کن. */
object UrlChecker {
    data class Result(val score: Int, val reasons: List<String>, val host: String?) {
        val level get() = when { score >= 5 -> Level.THREAT; score >= 2 -> Level.SUSPICIOUS; else -> Level.CLEAN }
    }

    private val BRANDS = listOf("paypal", "apple", "google", "microsoft", "amazon", "netflix", "instagram",
        "whatsapp", "telegram", "binance", "metamask", "dhl", "fedex", "spotify")
    private val SHORT = setOf("bit.ly", "tinyurl.com", "t.co", "cutt.ly", "is.gd", "rb.gy", "shorturl.at")
    private val BAD_TLD = setOf("zip", "mov", "top", "xyz", "click", "work", "gq", "tk", "ml", "cf", "ga", "icu", "cam", "rest", "country")
    private val KW = Regex("login|verify|secure|update|wallet|password|otp|confirm")

    fun check(raw: String): Result {
        val uri = try {
            URI(if (Regex("^[a-zA-Z]+://").containsMatchIn(raw)) raw else "http://$raw")
        } catch (e: Exception) { return Result(9, listOf("آدرس نامعتبر"), null) }
        val host = uri.host?.lowercase() ?: return Result(9, listOf("آدرس نامعتبر"), null)
        val r = mutableListOf<String>(); var s = 0
        val parts = host.split('.'); val n = parts.size
        var reg = parts.takeLast(2).joinToString(".")
        if (n > 2 && parts.last().length == 2 && parts[n - 2] in setOf("co", "com", "org", "net", "gov", "ac"))
            reg = parts.takeLast(3).joinToString(".")

        if (uri.scheme == "http") { s += 1; r += "بدون HTTPS" }
        if (Regex("^\\d{1,3}(\\.\\d{1,3}){3}$").matches(host)) { s += 3; r += "آدرس IP به‌جای دامنه" }
        if (uri.userInfo != null) { s += 3; r += "علامت @ در آدرس" }
        if ("xn--" in host) { s += 3; r += "دامنه Punycode" }
        if (n >= 5) { s += 2; r += "زیردامنه‌های زیاد" }
        if (parts.last() in BAD_TLD) { s += 2; r += "پسوند پرخطر .${parts.last()}" }
        if (host.count { it == '-' } >= 3) { s += 1; r += "خط تیره زیاد" }
        BRANDS.forEach { b ->
            if (b in host && reg != "$b.com" && reg.substringBefore('.') != b) { s += 4; r += "تقلید از برند $b" }
        }
        if (host in SHORT) { s += 1; r += "لینک کوتاه‌شده" }
        val kw = KW.findAll(((uri.path ?: "") + (uri.query ?: "")).lowercase()).count()
        if (kw > 0) { s += minOf(2, kw); r += "کلمات حساس در مسیر" }
        if (raw.length > 120) { s += 1; r += "آدرس خیلی بلند" }
        return Result(s, r, host)
    }
}
