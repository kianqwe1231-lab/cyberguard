package com.cyberguard.av

import android.content.Context

/** ذخیره‌ی ساده: «نادیده بگیر»ها (پکیج یا مسیر فایل) و تاریخچه‌ی اسکن. */
object Store {
    private fun prefs(ctx: Context) = ctx.getSharedPreferences("cyberguard", Context.MODE_PRIVATE)

    fun ignored(ctx: Context): Set<String> =
        prefs(ctx).getStringSet("ignored", emptySet()) ?: emptySet()

    fun ignore(ctx: Context, key: String) {
        prefs(ctx).edit().putStringSet("ignored", ignored(ctx) + key).apply()
    }

    fun clearIgnored(ctx: Context) {
        prefs(ctx).edit().remove("ignored").apply()
    }

    fun history(ctx: Context): List<String> =
        prefs(ctx).getString("history", "")?.split("\n")?.filter { it.isNotBlank() } ?: emptyList()

    fun addHistory(ctx: Context, line: String) {
        val next = (listOf(line) + history(ctx)).take(10)
        prefs(ctx).edit().putString("history", next.joinToString("\n")).apply()
    }
}
