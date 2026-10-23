package com.cyberguard.av

import android.Manifest
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.drawscope.rotate
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.app.NotificationManagerCompat
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.Locale
import java.util.concurrent.atomic.AtomicBoolean

private val Neon = Color(0xFF00FF41)
private val Red = Color(0xFFFF003C)
private val Amber = Color(0xFFFFD000)
private val Dimmed = Color(0xFF3FA062)
private val Soft = Color(0xFFB8FFC8)
private val PanelBg = Color(0xFF020A05)
private val Mono = FontFamily.Monospace

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme(
                colorScheme = darkColorScheme(
                    primary = Neon, onPrimary = Color.Black, background = Color.Black,
                    surface = PanelBg, onBackground = Neon, onSurface = Neon
                )
            ) {
                Surface(color = Color.Black, modifier = Modifier.fillMaxSize()) { Screen() }
            }
        }
    }
}

// ---------------------------------------------------------------- state & helpers

private class AvState {
    var heavy by mutableStateOf(false)
    var scanning by mutableStateOf(false)
    var progress by mutableStateOf(0)
    var current by mutableStateOf("")
    var report by mutableStateOf<ScanReport?>(null)
    var findings by mutableStateOf<List<Finding>>(emptyList())
    var queue by mutableStateOf<List<Finding>>(emptyList())
    val stop = AtomicBoolean(false)
}

private fun levelColor(l: Level) = when (l) {
    Level.THREAT -> Red; Level.SUSPICIOUS -> Amber; Level.CLEAN -> Neon
}

private fun levelFa(l: Level) = when (l) {
    Level.THREAT -> "ویروس"; Level.SUSPICIOUS -> "مشکوک"; Level.CLEAN -> "سالم"
}

private fun isInstalled(ctx: Context, pkg: String): Boolean = try {
    ctx.packageManager.getPackageInfo(pkg, 0); true
} catch (e: PackageManager.NameNotFoundException) { false }

private fun removalIntent(f: Finding): Intent =
    if (f.system) Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:${f.pkg}"))
    else Intent(Intent.ACTION_DELETE, Uri.parse("package:${f.pkg}"))

private fun appLabel(ctx: Context, pkg: String): String = try {
    val pm = ctx.packageManager
    pm.getApplicationLabel(pm.getApplicationInfo(pkg, 0)).toString()
} catch (e: Exception) { pkg }

private fun advice(f: Finding): String = when {
    f.level == Level.THREAT && f.system -> "برنامه‌ی سیستمی است؛ حذف نمی‌شود. از تنظیمات غیرفعالش کن و اگر شک داری گوشی را ریست/به‌روزرسانی کن."
    f.level == Level.THREAT -> "پیشنهاد: همین الان حذفش کن."
    f.system -> "برنامه‌ی سیستمی است؛ معمولاً خطری ندارد. اگر مطمئن نیستی نادیده بگیر."
    else -> "پیشنهاد: اگر خودت نصبش کرده‌ای و می‌شناسی «نادیده بگیر»؛ وگرنه حذفش کن."
}

// ---------------------------------------------------------------- UI pieces

@Composable
private fun Panel(border: Color = Neon, content: @Composable ColumnScope.() -> Unit) {
    OutlinedCard(
        border = BorderStroke(1.dp, border),
        colors = CardDefaults.outlinedCardColors(containerColor = PanelBg),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(6.dp), content = content)
    }
}

@Composable
private fun Title(t: String, color: Color = Neon) =
    Text(t, color = color, fontWeight = FontWeight.Bold, fontSize = 15.sp)

@Composable
private fun Dim(t: String) = Text(t, color = Dimmed, fontSize = 12.sp)

@Composable
private fun Body(t: String, color: Color = Soft) = Text(t, color = color, fontSize = 13.sp)

@Composable
private fun chipColors() = FilterChipDefaults.filterChipColors(
    selectedContainerColor = Neon, selectedLabelColor = Color.Black, labelColor = Neon
)

@Composable
private fun Radar(scanning: Boolean, label: String, color: Color) {
    val t = rememberInfiniteTransition(label = "radar")
    val angle by t.animateFloat(0f, 360f, infiniteRepeatable(tween(1600, easing = LinearEasing)), label = "angle")
    Box(Modifier.size(210.dp), contentAlignment = Alignment.Center) {
        Canvas(Modifier.fillMaxSize()) {
            val c = center
            val r = size.minDimension / 2
            listOf(1f, .66f, .33f).forEach { drawCircle(color.copy(alpha = .45f), r * it, c, style = Stroke(2f)) }
            drawLine(color.copy(alpha = .25f), Offset(c.x - r, c.y), Offset(c.x + r, c.y))
            drawLine(color.copy(alpha = .25f), Offset(c.x, c.y - r), Offset(c.x, c.y + r))
            if (scanning) rotate(angle, c) {
                drawArc(
                    brush = Brush.sweepGradient(0f to Color.Transparent, 0.2f to color.copy(alpha = .6f), center = c),
                    startAngle = 0f, sweepAngle = 70f, useCenter = true,
                    topLeft = Offset(c.x - r, c.y - r), size = Size(r * 2, r * 2)
                )
            }
        }
        Text(label, color = color, fontFamily = Mono, fontSize = 34.sp, fontWeight = FontWeight.Bold)
    }
}

// ---------------------------------------------------------------- root

@Composable
private fun Screen() {
    val ctx = LocalContext.current
    val st = remember { AvState() }
    var tab by remember { mutableStateOf(0) }

    val notifPerm = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { }
    LaunchedEffect(Unit) {
        if (Build.VERSION.SDK_INT >= 33) notifPerm.launch(Manifest.permission.POST_NOTIFICATIONS)
    }

    // صف حذف: هر برنامه یک دیالوگ تأیید سیستم دارد؛ بعد از هرکدام نوبت بعدی می‌آید
    val uninstall = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) {
        st.findings = st.findings.filter { isInstalled(ctx, it.pkg) }
        st.queue = st.queue.drop(1)
    }
    LaunchedEffect(st.queue) {
        st.queue.firstOrNull()?.let { uninstall.launch(removalIntent(it)) }
    }

    Scaffold(
        containerColor = Color.Black,
        bottomBar = {
            NavigationBar(containerColor = PanelBg) {
                listOf("اسکن" to ">_", "ابزارها" to "{ }", "وضعیت" to "%").forEachIndexed { i, (label, glyph) ->
                    NavigationBarItem(
                        selected = tab == i, onClick = { tab = i },
                        icon = { Text(glyph, fontFamily = Mono) }, label = { Text(label) },
                        colors = NavigationBarItemDefaults.colors(
                            selectedIconColor = Color.Black, selectedTextColor = Neon, indicatorColor = Neon,
                            unselectedIconColor = Neon, unselectedTextColor = Dimmed
                        )
                    )
                }
            }
        }
    ) { pad ->
        Box(Modifier.padding(pad).fillMaxSize()) {
            when (tab) {
                0 -> ScanTab(st)
                1 -> ToolsTab()
                else -> StatusTab()
            }
        }
    }
}

// ---------------------------------------------------------------- tab 0: scan

@Composable
private fun ScanTab(st: AvState) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    val threats = st.findings.filter { it.level == Level.THREAT }
    val rep = st.report
    val radarColor = if (threats.isNotEmpty()) Red else Neon
    val label = when {
        st.scanning -> "${st.progress}%"
        rep == null -> "OK"
        st.findings.isEmpty() -> "100"
        else -> "!"
    }

    fun startScan() {
        st.scanning = true; st.stop.set(false); st.report = null
        st.findings = emptyList(); st.progress = 0; st.current = ""
        scope.launch {
            val r = withContext(Dispatchers.Default) {
                Scanner.scanAll(ctx, st.heavy, shouldStop = { st.stop.get() }) { d, t, p ->
                    st.progress = if (t == 0) 100 else d * 100 / t
                    st.current = p
                }
            }
            st.report = r
            st.findings = r.findings
            st.scanning = false
        }
    }

    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).statusBarsPadding().padding(16.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        Text("[ CYBERGUARD ]", color = Neon, fontFamily = Mono, fontSize = 24.sp, fontWeight = FontWeight.Bold)
        Radar(st.scanning, label, radarColor)
        Text(
            if (st.scanning) st.current else "NO MERCY FOR MALWARE",
            color = Dimmed, fontFamily = Mono, fontSize = 12.sp, maxLines = 1
        )

        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            FilterChip(selected = !st.heavy, enabled = !st.scanning, onClick = { st.heavy = false },
                label = { Text("اسکن سبک") }, colors = chipColors())
            FilterChip(selected = st.heavy, enabled = !st.scanning, onClick = { st.heavy = true },
                label = { Text("اسکن سنگین") }, colors = chipColors())
        }
        Dim(if (st.heavy) "سنگین: برنامه‌های سیستمی + هش APK + همه‌ی بررسی‌ها" else "سبک: برنامه‌های نصب‌شده توسط کاربر، سریع")

        if (st.scanning) {
            OutlinedButton(
                onClick = { st.stop.set(true) }, border = BorderStroke(1.dp, Red),
                modifier = Modifier.fillMaxWidth()
            ) { Text("■ توقف اسکن", color = Red, fontFamily = Mono) }
        } else {
            Button(onClick = { startScan() }, modifier = Modifier.fillMaxWidth()) {
                Text(">_ شروع اسکن", fontFamily = Mono)
            }
        }

        if (rep != null) SummaryCard(rep, st.findings)

        if (threats.isNotEmpty()) {
            Button(
                onClick = { st.queue = threats },
                colors = ButtonDefaults.buttonColors(containerColor = Red, contentColor = Color.Black),
                modifier = Modifier.fillMaxWidth()
            ) { Text("☠ حذف همه‌ی ویروس‌ها (${threats.size})", fontWeight = FontWeight.Bold) }
            Dim("اندروید برای هر برنامه یک تأیید می‌گیرد؛ تأیید کن تا حذف شود.")
        }

        st.findings.forEach { f ->
            key(f.pkg) {
                FindingCard(
                    f,
                    onRemove = { st.queue = listOf(f) },
                    onIgnore = {
                        Store.ignore(ctx, f.pkg)
                        st.findings = st.findings.filter { x -> x.pkg != f.pkg }
                    }
                )
            }
        }

        if (rep != null) ReportCard(rep)
        HealthCard()
        Spacer(Modifier.height(12.dp))
    }
}

@Composable
private fun SummaryCard(r: ScanReport, findings: List<Finding>) {
    val threats = findings.count { it.level == Level.THREAT }
    val sus = findings.count { it.level == Level.SUSPICIOUS }
    val color = when { threats > 0 -> Red; sus > 0 -> Amber; else -> Neon }
    val secs = String.format(Locale.US, "%.1f", r.durationMs / 1000.0)
    val head = when {
        threats > 0 -> "⛔ گوشی شما $threats ویروس دارد"
        sus > 0 -> "⚠ $sus برنامه‌ی مشکوک پیدا شد"
        else -> "✅ چیزی پیدا نشد؛ گوشی سالم است"
    }
    Panel(color) {
        Text(head, color = color, fontWeight = FontWeight.Bold, fontSize = 17.sp)
        if (r.stopped) Body("اسکن را متوقف کردی؛ ${r.scanned} از ${r.total} برنامه بررسی شد.", Amber)
        else Body("${r.scanned} برنامه در $secs ثانیه بررسی شد (${if (r.heavy) "اسکن سنگین" else "اسکن سبک"}).")
        if (threats + sus > 0) Dim("برای هر مورد می‌توانی «حذف» یا «نادیده بگیر» را بزنی.")
    }
}

@Composable
private fun FindingCard(f: Finding, onRemove: () -> Unit, onIgnore: () -> Unit) {
    val c = levelColor(f.level)
    Panel(c) {
        Text("${levelFa(f.level)} · ${f.label}", color = c, fontWeight = FontWeight.Bold, fontSize = 16.sp)
        Text(f.pkg, color = Dimmed, fontFamily = Mono, fontSize = 11.sp)
        f.reasons.forEach { Body("• $it") }
        Body(advice(f), Amber)
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(
                onClick = onRemove,
                colors = ButtonDefaults.buttonColors(containerColor = c, contentColor = Color.Black)
            ) { Text(if (f.system) "غیرفعال‌سازی" else "حذف") }
            OutlinedButton(onClick = onIgnore) { Text("نادیده بگیر") }
        }
    }
}

@Composable
private fun ReportCard(r: ScanReport) {
    Panel {
        Title("گزارش عملکرد")
        val sigCount = Signatures.hashes.size + Signatures.packages.size
        Body("✔ پایگاه امضا: $sigCount امضا" + if (sigCount == 0) " (خالی؛ فقط تحلیل رفتاری)" else "")
        Body("✔ مجوزهای پرخطر (پیامک، تماس، میکروفن، نمایش روی برنامه‌ها، نصب برنامه…)")
        Body("✔ سرویس دسترسی‌پذیری و مدیر دستگاه فعال")
        Body("✔ دسترسی به اعلان‌ها (سرقت کد تأیید)")
        Body("✔ منبع نصب (پلی‌استور یا ناشناس)")
        Body(if (r.heavy) "✔ هش SHA-256 فایل APK و برنامه‌های سیستمی" else "– هش APK و برنامه‌های سیستمی (فقط در اسکن سنگین)")
        Dim("امتیاز ریسک ≥ ۸ مشکوک و ≥ ۱۴ ویروس است. هشدار به معنای قطعی بودن آلودگی نیست؛ برنامه‌هایی که می‌شناسی را «نادیده بگیر» کن.")
    }
}

@Composable
private fun HealthCard() {
    val ctx = LocalContext.current
    val h = remember { DeviceHealth.snapshot(ctx) }
    Panel {
        Title("سلامت دستگاه")
        Body("باتری: ${h.battery}%" + if (h.charging) " ⚡ در حال شارژ" else "")
        Body("حافظه‌ی آزاد: ${String.format(Locale.US, "%.1f", h.storageFreeGb)} از ${String.format(Locale.US, "%.1f", h.storageTotalGb)} گیگ")
        Body("RAM آزاد: ${h.ramFreeMb} از ${h.ramTotalMb} مگ")
    }
}

// ---------------------------------------------------------------- tab 1: tools

@Composable
private fun ToolsTab() {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    val clip = LocalClipboardManager.current
    var url by remember { mutableStateOf("") }
    var urlRes by remember { mutableStateOf<UrlChecker.Result?>(null) }
    var fileRes by remember { mutableStateOf<FileResult?>(null) }
    var fileBusy by remember { mutableStateOf(false) }
    var fileErr by remember { mutableStateOf(false) }

    val picker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) {
            fileBusy = true; fileRes = null; fileErr = false
            scope.launch {
                val r = withContext(Dispatchers.IO) { try { FileScanner.scan(ctx, uri) } catch (e: Exception) { null } }
                fileRes = r; fileErr = r == null; fileBusy = false
            }
        }
    }

    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).statusBarsPadding().padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        Text("[ ابزارها ]", color = Neon, fontFamily = Mono, fontSize = 22.sp, fontWeight = FontWeight.Bold)

        Panel {
            Title("بررسی لینک: سالمه یا نه؟")
            OutlinedTextField(
                value = url, onValueChange = { url = it }, singleLine = true,
                label = { Text("لینک را اینجا بچسبان") }, modifier = Modifier.fillMaxWidth()
            )
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(onClick = { clip.getText()?.text?.let { url = it.trim() } }) { Text("جای‌گذاری") }
                Button(onClick = { if (url.isNotBlank()) urlRes = UrlChecker.check(url.trim()) }) { Text(">_ بررسی") }
            }
        }
        urlRes?.let { r ->
            val c = levelColor(r.level)
            Panel(c) {
                Text(
                    when (r.level) {
                        Level.CLEAN -> "✅ ظاهراً سالم"
                        Level.SUSPICIOUS -> "⚠ مشکوک"
                        Level.THREAT -> "⛔ خطرناک (احتمال فیشینگ)"
                    },
                    color = c, fontWeight = FontWeight.Bold, fontSize = 18.sp
                )
                r.host?.let { Text(it, color = Dimmed, fontFamily = Mono, fontSize = 12.sp) }
                r.reasons.forEach { Body("• $it") }
                Dim("امتیاز ریسک: ${r.score}. این بررسی ظاهری است و تضمین امنیت نیست؛ لینک ناشناس را با احتیاط باز کن.")
            }
        }

        Panel {
            Title("اسکن فایل")
            Body("هر فایلی را انتخاب کن؛ هش SHA-256 و الگوهای مشکوک بررسی می‌شود. فایل از گوشی خارج نمی‌شود.")
            Button(onClick = { picker.launch(arrayOf("*/*")) }, enabled = !fileBusy) {
                Text(if (fileBusy) "در حال اسکن…" else ">_ انتخاب فایل")
            }
        }
        if (fileErr) Panel(Amber) { Body("فایل خوانده نشد.", Amber) }
        fileRes?.let { r ->
            val c = levelColor(r.level)
            Panel(c) {
                Text("${levelFa(r.level)} · ${r.name}", color = c, fontWeight = FontWeight.Bold, fontSize = 16.sp)
                Dim("${r.size / 1024} KB")
                if (r.reasons.isEmpty()) Body("هیچ نشانه‌ی مشکوکی پیدا نشد.") else r.reasons.forEach { Body("• $it") }
                Text("SHA256 ${r.sha256}", color = Dimmed, fontFamily = Mono, fontSize = 10.sp)
            }
        }
        Spacer(Modifier.height(12.dp))
    }
}

// ---------------------------------------------------------------- tab 2: status

@Composable
private fun StatusTab() {
    val ctx = LocalContext.current
    var tick by remember { mutableStateOf(0) }
    val usage = remember(tick) { UsageMonitor.hasAccess(ctx) }
    val notif = remember(tick) { NotificationManagerCompat.from(ctx).areNotificationsEnabled() }
    val heavy = remember(tick) {
        if (usage) UsageMonitor.heavyForeground(ctx, 30).filter { it.pkg != ctx.packageName }.take(6)
        else emptyList()
    }

    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).statusBarsPadding().padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        Text("[ وضعیت محافظ ]", color = Neon, fontFamily = Mono, fontSize = 22.sp, fontWeight = FontWeight.Bold)

        Panel {
            Title("موتورهای محافظ")
            Body("✔ اسکن خودکار سبک هر ۱۵ دقیقه")
            Body("✔ اسکن فوری هر برنامه‌ی تازه‌نصب")
            Body(if (notif) "✔ اعلان‌ها روشن است" else "✖ اعلان‌ها خاموش است (از تنظیمات گوشی روشن کن)", if (notif) Soft else Red)
            Body(if (usage) "✔ پایش مصرف برنامه‌ها فعال است" else "✖ پایش مصرف: هنوز دسترسی نداده‌ای", if (usage) Soft else Red)
            if (!usage) OutlinedButton(onClick = { UsageMonitor.openSettings(ctx) }) { Text("فعال‌سازی Usage access") }
            OutlinedButton(onClick = { tick++ }) { Text("به‌روزرسانی وضعیت") }
        }

        if (heavy.isNotEmpty()) {
            Panel(Amber) {
                Title("برنامه‌های پرمصرف (۲۴ ساعت گذشته)", Amber)
                heavy.forEach { Body("${appLabel(ctx, it.pkg)} · ${it.minutes} دقیقه در پیش‌زمینه") }
                Dim("اندروید درصد باتری هر برنامه را به برنامه‌های دیگر نمی‌دهد؛ زمان پیش‌زمینه معیار است.")
            }
        }

        Panel {
            Title("چرا گوشی می‌گوید CyberGuard خطرناک است؟")
            Body("این معمولاً هشدار اشتباه (false positive) است، به این دلایل:")
            Body("• برنامه با کلید دیباگ ساخته شده و از پلی‌استور نصب نشده؛ Play Protect هر برنامه‌ی ناشناس را تذکر می‌دهد.")
            Body("• مجوزهایی مثل «لیست همه‌ی برنامه‌ها»، «آمار استفاده» و «حذف برنامه» را می‌خواهد؛ آنتی‌ویروس‌ها هم به همین مجوزها نیاز دارند، ولی بدافزارها هم از آن‌ها استفاده می‌کنند.")
            Body("• برنامه‌ی تازه است و هنوز «شهرت» ندارد.")
            Body("برای استفاده‌ی شخصی: «More details ← Install anyway» را بزن. برای انتشار عمومی: نسخه‌ی release با کلید امضای ثابت بساز، در پلی‌استور منتشر کن و در Play Console گزارش false positive بده.")
        }

        Panel {
            Title("نادیده‌گرفته‌ها")
            OutlinedButton(onClick = { Store.clearIgnored(ctx); tick++ }) {
                Text("پاک‌کردن لیست (${Store.ignored(ctx).size})")
            }
        }
        Spacer(Modifier.height(12.dp))
    }
}
