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
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.ui.draw.clip
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
import androidx.compose.ui.graphics.Shadow
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.drawscope.rotate
import androidx.compose.ui.graphics.nativeCanvas
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.atomic.AtomicBoolean

private val Neon = Color(0xFF39FF88)
private val Red = Color(0xFFFF3158)
private val Amber = Color(0xFFFFC857)
private val Cyan = Color(0xFF28E7FF)
private val Violet = Color(0xFF9B7BFF)
private val Dimmed = Color(0xFF6C9C86)
private val Soft = Color(0xFFD2FFE0)
private val PanelBg = Color(0xFF07110F)
private val Glass = Color(0xF2091512)
private val Deep = Color(0xFF020807)
private val Mono = FontFamily.Monospace

class MainActivity : ComponentActivity() {
    private val notificationPermission = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { /* Notification permission is optional; scans still work without it. */ }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val prefs = getSharedPreferences("cyberguard", MODE_PRIVATE)
        if (Build.VERSION.SDK_INT >= 33 &&
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED &&
            !prefs.getBoolean("notification_prompted", false)
        ) {
            prefs.edit().putBoolean("notification_prompted", true).apply()
            notificationPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
        setContent {
            MaterialTheme(
                colorScheme = darkColorScheme(
                    primary = Neon, onPrimary = Color.Black, secondary = Cyan, onSecondary = Color.Black,
                    tertiary = Violet, background = Deep, surface = PanelBg, onBackground = Soft, onSurface = Soft,
                    error = Red, onError = Color.Black
                ),
                shapes = Shapes(
                    extraSmall = RoundedCornerShape(8.dp), small = RoundedCornerShape(12.dp),
                    medium = RoundedCornerShape(18.dp), large = RoundedCornerShape(24.dp),
                    extraLarge = RoundedCornerShape(28.dp)
                )
            ) {
                Surface(color = Deep, modifier = Modifier.fillMaxSize()) { Screen() }
            }
        }
    }
}

// ================================================================ state & helpers

private class AvState {
    var heavy by mutableStateOf(false)
    var scanning by mutableStateOf(false)
    var progress by mutableStateOf(0)
    var current by mutableStateOf("")
    var stage by mutableStateOf("")
    var report by mutableStateOf<ScanReport?>(null)
    var findings by mutableStateOf<List<Finding>>(emptyList())
    var fileFindings by mutableStateOf<List<FileFinding>>(emptyList())
    var filesSeen by mutableStateOf(0)
    var needAccess by mutableStateOf(false)
    var wasStopped by mutableStateOf(false)
    var error by mutableStateOf<String?>(null)
    var logTail by mutableStateOf<List<String>>(emptyList())
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

private fun humanSize(b: Long): String = when {
    b >= 1_048_576L -> String.format(Locale.US, "%.1f MB", b / 1048576.0)
    b >= 1024L -> "${b / 1024} KB"
    else -> "$b B"
}

private fun advice(f: Finding): String = when {
    f.level == Level.THREAT && f.system -> "برنامه‌ی سیستمی است و حذف نمی‌شود؛ از تنظیمات غیرفعالش کن."
    f.level == Level.THREAT -> "پیشنهاد: همین الان حذفش کن."
    else -> "اگر خودت نصبش کرده‌ای و می‌شناسی «نادیده بگیر»؛ وگرنه حذفش کن."
}

// ================================================================ UI pieces

@Composable
private fun Panel(border: Color = Neon, content: @Composable ColumnScope.() -> Unit) {
    val shape = RoundedCornerShape(18.dp)
    Box(
        Modifier.fillMaxWidth()
            .clip(shape)
            .background(Brush.verticalGradient(listOf(Color(0xF20C1C17), Color(0xF2050D0B))))
            .border(Brush.horizontalGradient(listOf(border.copy(alpha = .95f), border.copy(alpha = .28f), Cyan.copy(alpha = .55f))), shape)
    ) {
        Column(Modifier.padding(15.dp), verticalArrangement = Arrangement.spacedBy(7.dp), content = content)
    }
}

@Composable
private fun StatusPill(label: String, color: Color, dot: Boolean = true) {
    Row(
        modifier = Modifier.clip(RoundedCornerShape(50)).background(color.copy(alpha = .10f))
            .border(1.dp, color.copy(alpha = .42f), RoundedCornerShape(50)).padding(horizontal = 10.dp, vertical = 6.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(6.dp)
    ) {
        if (dot) Box(Modifier.size(6.dp).clip(RoundedCornerShape(50)).background(color))
        Text(label, color = color, fontFamily = Mono, fontSize = 9.sp, fontWeight = FontWeight.Bold, maxLines = 1)
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
private fun Glow(t: String, color: Color = Neon, size: Int = 22) =
    Text(
        t, color = color, fontFamily = Mono, fontSize = size.sp, fontWeight = FontWeight.Bold,
        style = TextStyle(shadow = Shadow(color, blurRadius = 18f))
    )

@Composable
private fun chipColors() = FilterChipDefaults.filterChipColors(
    selectedContainerColor = Neon, selectedLabelColor = Color.Black, labelColor = Neon
)

@Composable
private fun GlitchTitle(text: String) {
    val t = rememberInfiniteTransition(label = "glitch")
    val v by t.animateFloat(0f, 1f, infiniteRepeatable(tween(2600, easing = LinearEasing)), label = "v")
    val d = if (v > 0.9f) 4.dp else 1.dp
    Box {
        Text(text, color = Red.copy(alpha = .8f), fontFamily = Mono, fontSize = 25.sp,
            fontWeight = FontWeight.Black, modifier = Modifier.offset(x = -d))
        Text(text, color = Cyan.copy(alpha = .8f), fontFamily = Mono, fontSize = 25.sp,
            fontWeight = FontWeight.Black, modifier = Modifier.offset(x = d))
        Glow(text, Neon, 25)
    }
}

@Composable
private fun MatrixRain(modifier: Modifier = Modifier) {
    val glyphs = remember { "ｱｲｳｴｵｶｷｸｹｺｻｼｽｾｿﾀﾁﾂﾃﾄ01ABCDEF<>{}/#".toCharArray() }
    val cols = 26
    val drops = remember { IntArray(cols) { (it * 7) % 40 } }
    var tick by remember { mutableStateOf(0) }
    LaunchedEffect(Unit) {
        while (true) {
            delay(90)
            for (i in drops.indices) drops[i] = if (drops[i] > 70 + (i % 9) * 3) 0 else drops[i] + 1
            tick++
        }
    }
    val paint = remember {
        android.graphics.Paint().apply { isAntiAlias = true; typeface = android.graphics.Typeface.MONOSPACE }
    }
    Canvas(modifier) {
        val t = tick
        val cw = size.width / cols
        val fs = cw * 0.9f
        paint.textSize = fs
        for (i in 0 until cols) {
            for (k in 0..9) {
                val row = drops[i] - k
                if (row < 0) continue
                val y = row * fs * 1.1f
                if (y > size.height) continue
                val a = if (k == 0) 150 else (10 - k) * 8
                paint.color = android.graphics.Color.argb(a, 0, 255, 65)
                val g = glyphs[(i * 31 + row * 17 + (if (k == 0) t else 0)) % glyphs.size]
                drawContext.canvas.nativeCanvas.drawText(g.toString(), i * cw, y, paint)
            }
        }
    }
}

@Composable
private fun Scanlines(modifier: Modifier = Modifier) {
    Canvas(modifier) {
        var y = 0f
        while (y < size.height) {
            drawLine(Color(0x1400FF41), Offset(0f, y), Offset(size.width, y), strokeWidth = 1f)
            y += 5f
        }
    }
}

@Composable
private fun Radar(scanning: Boolean, label: String, color: Color) {
    val t = rememberInfiniteTransition(label = "radar")
    val angle by t.animateFloat(0f, 360f, infiniteRepeatable(tween(1600, easing = LinearEasing)), label = "angle")
    Box(Modifier.size(200.dp), contentAlignment = Alignment.Center) {
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
        Glow(label, color, 32)
    }
}

// ================================================================ root

@Composable
private fun Screen() {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    val st = remember { AvState() }
    var tab by remember { mutableStateOf(0) }

    // صف حذف برنامه‌ها: هر برنامه یک دیالوگ تأیید سیستم دارد؛ بعد از هرکدام نوبت بعدی می‌آید
    val uninstall = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) {
        st.findings = st.findings.filter { isInstalled(ctx, it.pkg) }
        st.queue = st.queue.drop(1)
    }
    LaunchedEffect(st.queue) {
        st.queue.firstOrNull()?.let { uninstall.launch(removalIntent(it)) }
    }

    Box(Modifier.fillMaxSize()) {
        MatrixRain(Modifier.fillMaxSize())
        Scaffold(
            containerColor = Color.Transparent,
            bottomBar = {
                NavigationBar(
                    containerColor = Color(0xF507100D),
                    tonalElevation = 0.dp,
                    modifier = Modifier.border(BorderStroke(1.dp, Neon.copy(alpha = .22f)))
                ) {
                    listOf("اسکن" to ">_", "ابزارها" to "{ }", "قرنطینه" to "[#]", "وضعیت" to "%")
                        .forEachIndexed { i, (label, glyph) ->
                            NavigationBarItem(
                                selected = tab == i, onClick = { tab = i },
                                icon = { Text(glyph, fontFamily = Mono) }, label = { Text(label, fontSize = 11.sp) },
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
                    0 -> ScanTab(st, scope)
                    1 -> ToolsTab()
                    2 -> QuarantineTab()
                    else -> StatusTab()
                }
            }
        }
        Scanlines(Modifier.fillMaxSize())
    }
}

// ================================================================ tab 0: scan

@Composable
private fun ScanTab(st: AvState, scope: CoroutineScope) {
    val ctx = LocalContext.current
    var confirmAll by remember { mutableStateOf(false) }
    val legacyPerm = rememberLauncherForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) { }

    val appThreats = st.findings.filter { it.level == Level.THREAT }
    val fileThreats = st.fileFindings.filter { it.level == Level.THREAT }
    val totalThreats = appThreats.size + fileThreats.size
    val rep = st.report
    val radarColor = if (totalThreats > 0) Red else Neon
    val label = when {
        st.scanning -> "${st.progress}%"
        rep == null -> "OK"
        st.findings.isEmpty() && st.fileFindings.isEmpty() -> "100"
        else -> "!"
    }

    fun askFileAccess() {
        if (Build.VERSION.SDK_INT >= 30) {
            ctx.startActivity(
                Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION, Uri.parse("package:${ctx.packageName}"))
                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            )
        } else {
            legacyPerm.launch(arrayOf(Manifest.permission.READ_EXTERNAL_STORAGE, Manifest.permission.WRITE_EXTERNAL_STORAGE))
        }
    }

    fun startScan() {
        if (st.heavy && !FileSweep.hasAccess(ctx)) { st.needAccess = true; return }
        st.needAccess = false; st.error = null
        st.scanning = true; st.stop.set(false); st.wasStopped = false
        st.report = null; st.findings = emptyList(); st.fileFindings = emptyList()
        st.filesSeen = 0; st.progress = 0; st.logTail = emptyList(); st.stage = "برنامه‌ها"
        scope.launch {
            try {
                val r = withContext(Dispatchers.Default) {
                    Scanner.scanAll(ctx, st.heavy, shouldStop = { st.stop.get() }) { d, t, p ->
                        val pct = if (t == 0) 100 else d * 100 / t
                        st.progress = if (st.heavy) pct * 30 / 100 else pct
                        st.current = p
                        st.logTail = (st.logTail + "[APP] $p").takeLast(7)
                    }
                }
                st.report = r
                st.findings = r.findings
                if (st.heavy && !r.stopped) {
                    st.stage = "فایل‌ها"
                    val fr = withContext(Dispatchers.IO) {
                        FileSweep.sweep(ctx, Store.ignored(ctx), shouldStop = { st.stop.get() }) { pct, seen, path ->
                            st.progress = 30 + pct * 70 / 100
                            st.filesSeen = seen
                            st.current = path
                            st.logTail = (st.logTail + "[FILE] ${path.substringAfterLast('/')}").takeLast(7)
                        }
                    }
                    st.fileFindings = fr.findings
                    st.filesSeen = fr.filesSeen
                }
                st.wasStopped = st.stop.get()
                val whenText = SimpleDateFormat("MM/dd HH:mm", Locale.US).format(Date())
                val bad = st.findings.count { it.level == Level.THREAT } + st.fileFindings.count { it.level == Level.THREAT }
                Store.addHistory(
                    ctx,
                    "$whenText · ${if (st.heavy) "سنگین" else "سبک"} · ${r.scanned} برنامه · ${st.filesSeen} فایل · $bad ویروس"
                )
            } catch (e: Exception) {
                st.error = e.message ?: e.toString()
            } finally {
                st.scanning = false
            }
        }
    }

    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).statusBarsPadding().padding(16.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        GlitchTitle("[ CYBERGUARD ]")
        Row(
            Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            StatusPill(if (st.scanning) "SCANNING" else "SYSTEM READY", if (st.scanning) Cyan else Neon)
            StatusPill("LOCAL ENGINE", Violet, dot = false)
        }
        Box(
            Modifier.fillMaxWidth().height(1.dp)
                .background(Brush.horizontalGradient(listOf(Color.Transparent, Neon.copy(alpha = .7f), Cyan.copy(alpha = .65f), Color.Transparent)))
        )
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
        Dim(
            if (st.heavy) "سنگین: همه‌ی برنامه‌ها + گشتن کل حافظه برای فایل‌های مشکوک و ویروسی"
            else "سبک: فقط چک برنامه‌های نصب‌شده"
        )

        if (st.needAccess) {
            Panel(Amber) {
                Title("برای اسکن سنگین، دسترسی به فایل‌ها لازم است", Amber)
                Body("اجازه‌ی «دسترسی به همه‌ی فایل‌ها» را بده، برگرد و دوباره اسکن را بزن.")
                Button(onClick = { askFileAccess() }) { Text("دادن اجازه") }
            }
        }

        if (st.scanning) {
            OutlinedButton(
                onClick = { st.stop.set(true) }, border = BorderStroke(1.dp, Red),
                modifier = Modifier.fillMaxWidth()
            ) { Text("■ توقف اسکن", color = Red, fontFamily = Mono) }
            if (st.heavy) Dim("مرحله: ${st.stage} · فایل‌های بررسی‌شده: ${st.filesSeen}")
            Panel {
                Text("root@guard:~# scan --${if (st.heavy) "heavy" else "light"}", color = Dimmed, fontFamily = Mono, fontSize = 11.sp)
                st.logTail.forEach { Text(it, color = Neon, fontFamily = Mono, fontSize = 11.sp, maxLines = 1) }
            }
        } else {
            Button(onClick = { startScan() }, modifier = Modifier.fillMaxWidth()) {
                Text(">_ شروع اسکن", fontFamily = Mono)
            }
        }

        st.error?.let { e -> Panel(Red) { Body("خطا در اسکن: $e", Red) } }

        if (rep != null && !st.scanning) {
            SummaryCard(st, rep)
            if (totalThreats > 0) {
                Button(
                    onClick = { confirmAll = true },
                    colors = ButtonDefaults.buttonColors(containerColor = Red, contentColor = Color.Black),
                    modifier = Modifier.fillMaxWidth()
                ) { Text("☠ حذف همه‌ی ویروس‌ها ($totalThreats)", fontWeight = FontWeight.Bold) }
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
            st.fileFindings.forEach { f ->
                key(f.path) {
                    FileFindingCard(
                        f,
                        onQuarantine = {
                            scope.launch {
                                val ok = withContext(Dispatchers.IO) { Quarantine.add(ctx, File(f.path)) }
                                if (ok) st.fileFindings = st.fileFindings.filter { x -> x.path != f.path }
                            }
                        },
                        onDelete = {
                            scope.launch {
                                val ok = withContext(Dispatchers.IO) { FileSweep.delete(f.path) }
                                if (ok) st.fileFindings = st.fileFindings.filter { x -> x.path != f.path }
                            }
                        },
                        onIgnore = {
                            Store.ignore(ctx, f.path)
                            st.fileFindings = st.fileFindings.filter { x -> x.path != f.path }
                        }
                    )
                }
            }
            ReportCard(st, rep)
        }
        HealthCard()
        Spacer(Modifier.height(12.dp))
    }

    if (confirmAll) {
        AlertDialog(
            onDismissRequest = { confirmAll = false },
            containerColor = PanelBg,
            title = { Text("حذف همه‌ی ویروس‌ها؟", color = Red) },
            text = {
                Text(
                    "${fileThreats.size} فایل ویروسی مستقیم حذف می‌شود و ${appThreats.size} برنامه برای حذف به تأیید خودت می‌رسد.",
                    color = Soft
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    confirmAll = false
                    scope.launch {
                        withContext(Dispatchers.IO) { fileThreats.forEach { FileSweep.delete(it.path) } }
                        st.fileFindings = st.fileFindings.filter { f -> File(f.path).exists() }
                        if (appThreats.isNotEmpty()) st.queue = appThreats
                    }
                }) { Text("حذف", color = Red) }
            },
            dismissButton = { TextButton(onClick = { confirmAll = false }) { Text("لغو", color = Neon) } }
        )
    }
}

@Composable
private fun SummaryCard(st: AvState, r: ScanReport) {
    val threats = st.findings.count { it.level == Level.THREAT } + st.fileFindings.count { it.level == Level.THREAT }
    val sus = st.findings.count { it.level == Level.SUSPICIOUS } + st.fileFindings.count { it.level == Level.SUSPICIOUS }
    val color = when { threats > 0 -> Red; sus > 0 -> Amber; else -> Neon }
    val secs = String.format(Locale.US, "%.1f", r.durationMs / 1000.0)
    val head = when {
        threats > 0 -> "⛔ گوشی شما $threats ویروس دارد"
        sus > 0 -> "⚠ $sus مورد مشکوک پیدا شد"
        else -> "✅ چیزی پیدا نشد؛ گوشی سالم است"
    }
    Panel(color) {
        Text(head, color = color, fontWeight = FontWeight.Bold, fontSize = 17.sp)
        if (st.wasStopped) Body("اسکن را متوقف کردی؛ نتیجه‌ی ناقص است.", Amber)
        Body("${r.scanned} برنامه بررسی شد" + (if (r.heavy) " و ${st.filesSeen} فایل" else "") + " ($secs ثانیه برای برنامه‌ها)")
        if (threats + sus > 0) Dim("برای هر مورد می‌توانی حذف، قرنطینه یا «نادیده بگیر» را بزنی.")
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
private fun FileFindingCard(f: FileFinding, onQuarantine: () -> Unit, onDelete: () -> Unit, onIgnore: () -> Unit) {
    val c = levelColor(f.level)
    Panel(c) {
        Text("${levelFa(f.level)} · ${f.name}", color = c, fontWeight = FontWeight.Bold, fontSize = 16.sp)
        Text(f.path, color = Dimmed, fontFamily = Mono, fontSize = 10.sp)
        Dim(humanSize(f.size))
        f.reasons.forEach { Body("• $it") }
        Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            Button(
                onClick = onDelete,
                colors = ButtonDefaults.buttonColors(containerColor = c, contentColor = Color.Black)
            ) { Text("حذف") }
            OutlinedButton(onClick = onQuarantine) { Text("قرنطینه") }
            OutlinedButton(onClick = onIgnore) { Text("نادیده") }
        }
    }
}

@Composable
private fun ReportCard(st: AvState, r: ScanReport) {
    Panel {
        Title("گزارش عملکرد")
        val sigCount = Signatures.hashes.size + Signatures.packages.size
        Body("✔ پایگاه امضا: $sigCount امضا" + if (sigCount == 0) " (خالی؛ فعلاً رفتاری)" else "")
        Body("✔ برنامه‌های پلی‌استور و سیستمی فقط با امضای ویروس شناسایی می‌شوند؛ مجوز تنها هرگز هشدار نمی‌دهد (تلگرام و مثل آن امن‌اند).")
        Body("✔ برنامه‌ی نصب‌شده از منبع ناشناس: مجوزها + دسترسی‌پذیری + مدیر دستگاه + خواندن اعلان + پنهان بودن.")
        if (r.heavy) {
            Body("✔ هش SHA-256 همه‌ی APKهای نصب‌شده")
            Body("✔ گشتن کل حافظه: ${st.filesSeen} فایل (EICAR/امضا، پسوند دوگانه، فایل اجرایی با پسوند جعلی، APK نصب‌نشده با مجوز پرخطر)")
            Dim("پوشه‌های Android/data و Android/obb را خود اندروید قفل کرده و قابل اسکن نیستند.")
        } else {
            Dim("اسکن سبک فقط برنامه‌ها را می‌بیند؛ برای فایل‌ها «اسکن سنگین» را بزن.")
        }
        Dim("امتیاز رفتاری ≥ ۸ مشکوک و ≥ ۱۴ ویروس است. هشدار یعنی «بررسی کن»، نه حکم قطعی.")
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

// ================================================================ tab 1: tools

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
    var wifi by remember { mutableStateOf<WifiAudit.Info?>(null) }
    var priv by remember { mutableStateOf<PrivacyAudit.Result?>(null) }
    var privBusy by remember { mutableStateOf(false) }

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
        Glow("[ ابزارها ]")

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
            Title("اسکن یک فایل")
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
                Dim(humanSize(r.size))
                if (r.reasons.isEmpty()) Body("هیچ نشانه‌ی مشکوکی پیدا نشد.") else r.reasons.forEach { Body("• $it") }
                Text("SHA256 ${r.sha256}", color = Dimmed, fontFamily = Mono, fontSize = 10.sp)
            }
        }

        Panel {
            Title("امنیت Wi-Fi")
            Body("نوع رمزنگاری شبکه‌ای که به آن وصلی را بررسی می‌کند.")
            Button(onClick = { wifi = WifiAudit.check(ctx) }) { Text(">_ بررسی Wi-Fi") }
        }
        wifi?.let { w ->
            val c = levelColor(w.level)
            Panel(c) {
                Text(w.label, color = c, fontWeight = FontWeight.Bold, fontSize = 16.sp)
                if (w.note.isNotEmpty()) Body(w.note)
            }
        }

        Panel {
            Title("ممیزی حریم خصوصی")
            Body("کدام برنامه‌ها مجوز میکروفن، دوربین، موقعیت و پیامک را واقعاً گرفته‌اند.")
            Button(
                enabled = !privBusy,
                onClick = {
                    privBusy = true
                    scope.launch {
                        priv = withContext(Dispatchers.Default) { try { PrivacyAudit.run(ctx) } catch (e: Exception) { null } }
                        privBusy = false
                    }
                }
            ) { Text(if (privBusy) "در حال بررسی…" else ">_ اجرای ممیزی") }
        }
        priv?.let { p ->
            Panel {
                @Composable
                fun Section(name: String, list: List<String>) {
                    Text("$name (${list.size})", color = Cyan, fontWeight = FontWeight.Bold, fontSize = 13.sp)
                    Body(if (list.isEmpty()) "—" else list.take(10).joinToString("، ") + if (list.size > 10) " …" else "")
                }
                Section("میکروفن", p.mic)
                Section("دوربین", p.camera)
                Section("موقعیت مکانی", p.location)
                Section("پیامک", p.sms)
                Dim("فقط برنامه‌های غیرسیستمی. مجوز اضافی را از تنظیمات گوشی ← برنامه‌ها ← مجوزها ببند.")
            }
        }
        Spacer(Modifier.height(12.dp))
    }
}

// ================================================================ tab 2: quarantine

@Composable
private fun QuarantineTab() {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    var tick by remember { mutableStateOf(0) }
    val items = remember(tick) { Quarantine.list(ctx) }

    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).statusBarsPadding().padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        Glow("[ قرنطینه ]")
        Dim("فایل‌های مشکوک اینجا امن و غیرفعال نگه داشته می‌شوند. می‌توانی بازگردانی کنی یا برای همیشه حذف.")
        if (items.isEmpty()) Panel { Body("قرنطینه خالی است.") }
        items.forEach { it ->
            key(it.id) {
                Panel(Amber) {
                    Text(it.path.substringAfterLast('/'), color = Amber, fontWeight = FontWeight.Bold)
                    Text(it.path, color = Dimmed, fontFamily = Mono, fontSize = 10.sp)
                    Dim(humanSize(it.size))
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedButton(onClick = {
                            scope.launch { withContext(Dispatchers.IO) { Quarantine.restore(ctx, it) }; tick++ }
                        }) { Text("بازگردانی") }
                        Button(
                            onClick = { scope.launch { withContext(Dispatchers.IO) { Quarantine.deleteForever(ctx, it) }; tick++ } },
                            colors = ButtonDefaults.buttonColors(containerColor = Red, contentColor = Color.Black)
                        ) { Text("حذف دائمی") }
                    }
                }
            }
        }
        Spacer(Modifier.height(12.dp))
    }
}

// ================================================================ tab 3: status

@Composable
private fun StatusTab() {
    val ctx = LocalContext.current
    var tick by remember { mutableStateOf(0) }
    val usage = remember(tick) { UsageMonitor.hasAccess(ctx) }
    val heavy = remember(tick) {
        if (usage) UsageMonitor.heavyForeground(ctx, 30).filter { it.pkg != ctx.packageName }.take(6)
        else emptyList()
    }
    val history = remember(tick) { Store.history(ctx) }

    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).statusBarsPadding().padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        Glow("[ وضعیت ]")

        Panel {
            Title("حالت کار")
            Body("✔ اسکن دستی + بررسی سبک پس‌زمینه (WorkManager؛ با محدودیت‌های اندروید).")
            Body("✔ تحلیل‌ها روی دستگاه انجام می‌شوند؛ برنامه داده‌ای برای سرور ارسال نمی‌کند.")
            Body(if (FileSweep.hasAccess(ctx)) "✔ دسترسی به فایل‌ها داده شده (اسکن سنگین آماده است)" else "✖ دسترسی به فایل‌ها داده نشده (برای اسکن سنگین لازم است)", if (FileSweep.hasAccess(ctx)) Soft else Amber)
            Body(if (usage) "✔ پایش مصرف برنامه‌ها فعال است" else "✖ پایش مصرف: دسترسی نداده‌ای", if (usage) Soft else Amber)
            if (!usage) OutlinedButton(onClick = { UsageMonitor.openSettings(ctx) }) { Text("فعال‌سازی Usage access") }
            OutlinedButton(onClick = { tick++ }) { Text("به‌روزرسانی وضعیت") }
        }

        if (heavy.isNotEmpty()) {
            Panel(Amber) {
                Title("برنامه‌های پرمصرف (۲۴ ساعت گذشته)", Amber)
                heavy.forEach { Body("${appLabel(ctx, it.pkg)} · ${it.minutes} دقیقه در پیش‌زمینه") }
                Dim("اندروید درصد باتری هر برنامه را نمی‌دهد؛ زمان پیش‌زمینه معیار است.")
            }
        }

        Panel {
            Title("تاریخچه‌ی اسکن")
            if (history.isEmpty()) Body("هنوز اسکنی انجام نشده.") else history.forEach { Body(it) }
        }

        Panel {
            Title("چرا گوشی می‌گوید CyberGuard خطرناک است؟")
            Body("معمولاً هشدار اشتباه است: برنامه با کلید دیباگ ساخته شده، از پلی‌استور نیامده و مجوزهایی می‌خواهد که آنتی‌ویروس‌ها هم لازم دارند. برای استفاده‌ی شخصی «More details ← Install anyway» را بزن.")
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
