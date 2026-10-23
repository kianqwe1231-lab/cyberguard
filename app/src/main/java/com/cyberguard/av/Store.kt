package com.cyberguard.av

import android.content.Context

/** ذخیره‌ی ساده: برنامه‌هایی که کاربر «نادیده بگیر» زده. */
object Store {
    private fun prefs(ctx: Context) = ctx.getSharedPreferences("cyberguard", Context.MODE_PRIVATE)

    fun ignored(ctx: Context): Set<String> =
        prefs(ctx).getStringSet("ignored", emptySet()) ?: emptySet()

    fun ignore(ctx: Context, pkg: String) {
        prefs(ctx).edit().putStringSet("ignored", ignored(ctx) + pkg).apply()
    }

    fun clearIgnored(ctx: Context) {
        prefs(ctx).edit().remove("ignored").apply()
    }
}
