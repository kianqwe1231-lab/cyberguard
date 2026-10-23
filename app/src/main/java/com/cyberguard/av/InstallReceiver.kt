package com.cyberguard.av

import android.app.Application
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import androidx.core.content.ContextCompat
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

/** اسکن فوری هر برنامه‌ای که نصب می‌شود. (receiver داینامیک؛ برای ماندگاری کامل باید Foreground Service اضافه شود.) */
class InstallReceiver : BroadcastReceiver() {
    override fun onReceive(ctx: Context, intent: Intent) {
        val pkg = intent.data?.schemeSpecificPart ?: return
        if (intent.getBooleanExtra(Intent.EXTRA_REPLACING, false)) return
        val pending = goAsync()
        CoroutineScope(Dispatchers.IO).launch {
            try {
                val f = Scanner.scanPackage(ctx, pkg, heavy = true)
                if (f != null && f.level != Level.CLEAN) {
                    val title = if (f.level == Level.THREAT) "برنامه آلوده نصب شد" else "برنامه مشکوک نصب شد"
                    Notifier.alert(ctx, pkg.hashCode(), title, "${f.label}: ${f.reasons.firstOrNull() ?: ""}")
                }
            } finally { pending.finish() }
        }
    }

    companion object {
        fun register(app: Application) {
            val filter = IntentFilter(Intent.ACTION_PACKAGE_ADDED).apply { addDataScheme("package") }
            ContextCompat.registerReceiver(app, InstallReceiver(), filter, ContextCompat.RECEIVER_EXPORTED)
        }
    }
}
