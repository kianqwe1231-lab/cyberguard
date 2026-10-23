package com.cyberguard.av

import android.app.Application

class CyberApp : Application() {
    override fun onCreate() {
        super.onCreate()
        Notifier.ensureChannel(this)
        ScanWorker.schedule(this)      // اسکن سبک دوره‌ای هر ۱۵ دقیقه
        InstallReceiver.register(this) // اسکن فوری برنامه تازه‌نصب‌شده
    }
}
