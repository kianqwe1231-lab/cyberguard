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
    Level.THREAT -> "ظˆغŒط±ظˆط³"; Level.SUSPICIOUS -> "ظ…ط´ع©ظˆع©"; Level.CLEAN -> "ط³ط§ظ„ظ…"
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
    f.level == Level.THREAT && f.system -> "ط¨ط±ظ†ط§ظ…ظ‡â€ŒغŒ ط³غŒط³طھظ…غŒ ط§ط³طھ ظˆ ط­ط°ظپ ظ†ظ…غŒâ€Œط´ظˆط¯ط› ط§ط² طھظ†ط¸غŒظ…ط§طھ ط؛غŒط±ظپط¹ط§ظ„ط´ ع©ظ†."
    f.level == Level.THREAT -> "ظ¾غŒط´ظ†ظ‡ط§ط¯: ظ‡ظ…غŒظ† ط§ظ„ط§ظ† ط­ط°ظپط´ ع©ظ†."
    else -> "ط§ع¯ط± ط®ظˆط¯طھ ظ†طµط¨ط´ ع©ط±ط¯ظ‡â€Œط§غŒ ظˆ ظ…غŒâ€Œط´ظ†ط§ط³غŒ آ«ظ†ط§ط¯غŒط¯ظ‡ ط¨ع¯غŒط±آ»ط› ظˆع¯ط±ظ†ظ‡ ط­ط°ظپط´ ع©ظ†."
}

// ================================================================ UI pieces

@Composable
private fun Panel(border: Color = Neon, content: @Composable ColumnScope.() -> Unit) {
    val shape = RoundedCornerShape(18.dp)
    Box(
        Modifier.fillMaxWidth()
            .clip(shape)
            .background(Brush.verticalGradient(listOf(Color(0xF20C1C17), Color(0xF2050D0B))))
            .border(1.dp, Brush.horizontalGradient(listOf(border.copy(alpha = .95f), border.copy(alpha = .28f), Cyan.copy(alpha = .55f))), shape)
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
    val glyphs = remember { "ï½±ï½²ï½³ï½´ï½µï½¶ï½·ï½¸ï½¹ï½؛ï½»ï½¼ï½½ï½¾ï½؟ï¾€ï¾پï¾‚ï¾ƒï¾„01ABCDEF<>{}/#".toCharArray() }
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
private fun NexusPanel(
    scanning: Boolean,
    progress: Int,
    current: String,
    filesSeen: Int,
    logs: List<String>,
    heavy: Boolean,
    threats: Int
) {
    val accent = if (threats > 0) Red else Neon
    val pct = progress.coerceIn(0, 100)

    Column(
        Modifier
            .fillMaxWidth()
            .background(Color(0xFF07110D), RoundedCornerShape(12.dp))
            .padding(14.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        Row(
            Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column {
                Text(
                    "NEXUS // SCAN CORE",
                    color = Cyan,
                    fontFamily = Mono,
                    fontWeight = FontWeight.Bold,
                    fontSize = 16.sp
                )
                Text(
                    if (scanning) "LIVE ANALYSIS IN PROGRESS" else "THREAT ANALYSIS SYSTEM",
                    color = Dimmed,
                    fontFamily = Mono,
                    fontSize = 10.sp
                )
            }
            Text(
                if (scanning) "$pct%" else if (threats > 0) "ALERT" else "READY",
                color = accent,
                fontFamily = Mono,
                fontWeight = FontWeight.Bold,
                fontSize = 19.sp
            )
        }

        Box(
            Modifier
                .fillMaxWidth()
                .height(5.dp)
                .background(Color(0xFF183126), RoundedCornerShape(4.dp))
        ) {
            if (scanning) {
                Box(
                    Modifier
                        .fillMaxWidth(pct / 100f)
                        .height(5.dp)
                        .background(accent, RoundedCornerShape(4.dp))
                )
            } else {
                Box(
                    Modifier
                        .fillMaxWidth(if (progress > 0) pct / 100f else 1f)
                        .height(5.dp)
                        .background(accent.copy(alpha = 0.7f), RoundedCornerShape(4.dp))
                )
            }
        }

        Row(
            Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Column(
                Modifier.weight(1f)
                    .background(Color(0xFF0D1D15), RoundedCornerShape(8.dp))
                    .padding(10.dp)
            ) {
                Text("SCAN MODE", color = Dimmed, fontSize = 10.sp, fontFamily = Mono)
                Text(if (heavy) "DEEP" else "QUICK", color = Neon, fontSize = 15.sp, fontFamily = Mono)
            }
            Column(
                Modifier.weight(1f)
                    .background(Color(0xFF0D1D15), RoundedCornerShape(8.dp))
                    .padding(10.dp)
            ) {
                Text("FILES CHECKED", color = Dimmed, fontSize = 10.sp, fontFamily = Mono)
                Text("$filesSeen", color = Cyan, fontSize = 15.sp, fontFamily = Mono)
            }
            Column(
                Modifier.weight(1f)
                    .background(Color(0xFF0D1D15), RoundedCornerShape(8.dp))
                    .padding(10.dp)
            ) {
                Text("THREATS", color = Dimmed, fontSize = 10.sp, fontFamily = Mono)
                Text("$threats", color = if (threats > 0) Red else Neon, fontSize = 15.sp, fontFamily = Mono)
            }
        }

        Text(
            if (scanning) "ACTIVE TARGET" else "SYSTEM STATUS",
            color = Cyan,
            fontFamily = Mono,
            fontSize = 11.sp
        )
        Text(
            if (scanning && current.isNotBlank()) current
            else if (scanning) "Initializing scan engine..." else "NO MERCY FOR MALWARE",
            color = Soft,
            fontFamily = Mono,
            fontSize = 12.sp
        )

        Box(
            Modifier.fillMaxWidth().height(1.dp)
                .background(Neon.copy(alpha = 0.35f))
        )

        Text("LIVE EVENT STREAM", color = Cyan, fontFamily = Mono, fontSize = 11.sp)
        if (logs.isEmpty()) {
            Text(
                "> Awaiting scan events...",
                color = Dimmed,
                fontFamily = Mono,
                fontSize = 11.sp
            )
        } else {
            logs.takeLast(4).forEach { entry ->
                Text(
                    "> $entry",
                    color = Neon,
                    fontFamily = Mono,
                    fontSize = 10.sp,
                    maxLines = 2
                )
            }
        }
    }
}

// ================================================================ root

@Composable
private fun Screen() {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    val st = remember { AvState() }
    var tab by remember { mutableStateOf(0) }

    // طµظپ ط­ط°ظپ ط¨ط±ظ†ط§ظ…ظ‡â€Œظ‡ط§: ظ‡ط± ط¨ط±ظ†ط§ظ…ظ‡ غŒع© ط¯غŒط§ظ„ظˆع¯ طھط£غŒغŒط¯ ط³غŒط³طھظ… ط¯ط§ط±ط¯ط› ط¨ط¹ط¯ ط§ط² ظ‡ط±ع©ط¯ط§ظ… ظ†ظˆط¨طھ ط¨ط¹ط¯غŒ ظ…غŒâ€Œط¢غŒط¯
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
                    listOf("ط§ط³ع©ظ†" to ">_", "ط§ط¨ط²ط§ط±ظ‡ط§" to "{ }", "ظ‚ط±ظ†ط·غŒظ†ظ‡" to "[#]", "ظˆط¶ط¹غŒطھ" to "%")
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
        st.filesSeen = 0; st.progress = 0; st.logTail = emptyList(); st.stage = "ط¨ط±ظ†ط§ظ…ظ‡â€Œظ‡ط§"
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
                    st.stage = "ظپط§غŒظ„â€Œظ‡ط§"
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
                    "$whenText آ· ${if (st.heavy) "ط³ظ†ع¯غŒظ†" else "ط³ط¨ع©"} آ· ${r.scanned} ط¨ط±ظ†ط§ظ…ظ‡ آ· ${st.filesSeen} ظپط§غŒظ„ آ· $bad ظˆغŒط±ظˆط³"
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
        NexusPanel(st.scanning, st.progress, st.current, st.filesSeen, st.logTail, st.heavy, totalThreats)
        Text(
            if (st.scanning) st.current else "NO MERCY FOR MALWARE",
            color = Dimmed, fontFamily = Mono, fontSize = 12.sp, maxLines = 1
        )

        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            FilterChip(selected = !st.heavy, enabled = !st.scanning, onClick = { st.heavy = false },
                label = { Text("ط§ط³ع©ظ† ط³ط¨ع©") }, colors = chipColors())
            FilterChip(selected = st.heavy, enabled = !st.scanning, onClick = { st.heavy = true },
                label = { Text("ط§ط³ع©ظ† ط³ظ†ع¯غŒظ†") }, colors = chipColors())
        }
        Dim(
            if (st.heavy) "ط³ظ†ع¯غŒظ†: ظ‡ظ…ظ‡â€ŒغŒ ط¨ط±ظ†ط§ظ…ظ‡â€Œظ‡ط§ + ع¯ط´طھظ† ع©ظ„ ط­ط§ظپط¸ظ‡ ط¨ط±ط§غŒ ظپط§غŒظ„â€Œظ‡ط§غŒ ظ…ط´ع©ظˆع© ظˆ ظˆغŒط±ظˆط³غŒ"
            else "ط³ط¨ع©: ظپظ‚ط· ع†ع© ط¨ط±ظ†ط§ظ…ظ‡â€Œظ‡ط§غŒ ظ†طµط¨â€Œط´ط¯ظ‡"
        )

        if (st.needAccess) {
            Panel(Amber) {
                Title("ط¨ط±ط§غŒ ط§ط³ع©ظ† ط³ظ†ع¯غŒظ†طŒ ط¯ط³طھط±ط³غŒ ط¨ظ‡ ظپط§غŒظ„â€Œظ‡ط§ ظ„ط§ط²ظ… ط§ط³طھ", Amber)
                Body("ط§ط¬ط§ط²ظ‡â€ŒغŒ آ«ط¯ط³طھط±ط³غŒ ط¨ظ‡ ظ‡ظ…ظ‡â€ŒغŒ ظپط§غŒظ„â€Œظ‡ط§آ» ط±ط§ ط¨ط¯ظ‡طŒ ط¨ط±ع¯ط±ط¯ ظˆ ط¯ظˆط¨ط§ط±ظ‡ ط§ط³ع©ظ† ط±ط§ ط¨ط²ظ†.")
                Button(onClick = { askFileAccess() }) { Text("ط¯ط§ط¯ظ† ط§ط¬ط§ط²ظ‡") }
            }
        }

        if (st.scanning) {
            OutlinedButton(
                onClick = { st.stop.set(true) }, border = BorderStroke(1.dp, Red),
                modifier = Modifier.fillMaxWidth()
            ) { Text("â–  طھظˆظ‚ظپ ط§ط³ع©ظ†", color = Red, fontFamily = Mono) }
            if (st.heavy) Dim("ظ…ط±ط­ظ„ظ‡: ${st.stage} آ· ظپط§غŒظ„â€Œظ‡ط§غŒ ط¨ط±ط±ط³غŒâ€Œط´ط¯ظ‡: ${st.filesSeen}")
            Panel {
                Text("root@guard:~# scan --${if (st.heavy) "heavy" else "light"}", color = Dimmed, fontFamily = Mono, fontSize = 11.sp)
                st.logTail.forEach { Text(it, color = Neon, fontFamily = Mono, fontSize = 11.sp, maxLines = 1) }
            }
        } else {
            Button(onClick = { startScan() }, modifier = Modifier.fillMaxWidth()) {
                Text(">_ ط´ط±ظˆط¹ ط§ط³ع©ظ†", fontFamily = Mono)
            }
        }

        st.error?.let { e -> Panel(Red) { Body("ط®ط·ط§ ط¯ط± ط§ط³ع©ظ†: $e", Red) } }

        if (rep != null && !st.scanning) {
            SummaryCard(st, rep)
            if (totalThreats > 0) {
                Button(
                    onClick = { confirmAll = true },
                    colors = ButtonDefaults.buttonColors(containerColor = Red, contentColor = Color.Black),
                    modifier = Modifier.fillMaxWidth()
                ) { Text("âک  ط­ط°ظپ ظ‡ظ…ظ‡â€ŒغŒ ظˆغŒط±ظˆط³â€Œظ‡ط§ ($totalThreats)", fontWeight = FontWeight.Bold) }
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
            title = { Text("ط­ط°ظپ ظ‡ظ…ظ‡â€ŒغŒ ظˆغŒط±ظˆط³â€Œظ‡ط§طں", color = Red) },
            text = {
                Text(
                    "${fileThreats.size} ظپط§غŒظ„ ظˆغŒط±ظˆط³غŒ ظ…ط³طھظ‚غŒظ… ط­ط°ظپ ظ…غŒâ€Œط´ظˆط¯ ظˆ ${appThreats.size} ط¨ط±ظ†ط§ظ…ظ‡ ط¨ط±ط§غŒ ط­ط°ظپ ط¨ظ‡ طھط£غŒغŒط¯ ط®ظˆط¯طھ ظ…غŒâ€Œط±ط³ط¯.",
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
                }) { Text("ط­ط°ظپ", color = Red) }
            },
            dismissButton = { TextButton(onClick = { confirmAll = false }) { Text("ظ„ط؛ظˆ", color = Neon) } }
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
        threats > 0 -> "â›” ع¯ظˆط´غŒ ط´ظ…ط§ $threats ظˆغŒط±ظˆط³ ط¯ط§ط±ط¯"
        sus > 0 -> "âڑ  $sus ظ…ظˆط±ط¯ ظ…ط´ع©ظˆع© ظ¾غŒط¯ط§ ط´ط¯"
        else -> "âœ… ع†غŒط²غŒ ظ¾غŒط¯ط§ ظ†ط´ط¯ط› ع¯ظˆط´غŒ ط³ط§ظ„ظ… ط§ط³طھ"
    }
    Panel(color) {
        Text(head, color = color, fontWeight = FontWeight.Bold, fontSize = 17.sp)
        if (st.wasStopped) Body("ط§ط³ع©ظ† ط±ط§ ظ…طھظˆظ‚ظپ ع©ط±ط¯غŒط› ظ†طھغŒط¬ظ‡â€ŒغŒ ظ†ط§ظ‚طµ ط§ط³طھ.", Amber)
        Body("${r.scanned} ط¨ط±ظ†ط§ظ…ظ‡ ط¨ط±ط±ط³غŒ ط´ط¯" + (if (r.heavy) " ظˆ ${st.filesSeen} ظپط§غŒظ„" else "") + " ($secs ط«ط§ظ†غŒظ‡ ط¨ط±ط§غŒ ط¨ط±ظ†ط§ظ…ظ‡â€Œظ‡ط§)")
        if (threats + sus > 0) Dim("ط¨ط±ط§غŒ ظ‡ط± ظ…ظˆط±ط¯ ظ…غŒâ€Œطھظˆط§ظ†غŒ ط­ط°ظپطŒ ظ‚ط±ظ†ط·غŒظ†ظ‡ غŒط§ آ«ظ†ط§ط¯غŒط¯ظ‡ ط¨ع¯غŒط±آ» ط±ط§ ط¨ط²ظ†غŒ.")
    }
}

@Composable
private fun FindingCard(f: Finding, onRemove: () -> Unit, onIgnore: () -> Unit) {
    val c = levelColor(f.level)
    Panel(c) {
        Text("${levelFa(f.level)} آ· ${f.label}", color = c, fontWeight = FontWeight.Bold, fontSize = 16.sp)
        Text(f.pkg, color = Dimmed, fontFamily = Mono, fontSize = 11.sp)
        f.reasons.forEach { Body("â€¢ $it") }
        Body(advice(f), Amber)
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(
                onClick = onRemove,
                colors = ButtonDefaults.buttonColors(containerColor = c, contentColor = Color.Black)
            ) { Text(if (f.system) "ط؛غŒط±ظپط¹ط§ظ„â€Œط³ط§ط²غŒ" else "ط­ط°ظپ") }
            OutlinedButton(onClick = onIgnore) { Text("ظ†ط§ط¯غŒط¯ظ‡ ط¨ع¯غŒط±") }
        }
    }
}

@Composable
private fun FileFindingCard(f: FileFinding, onQuarantine: () -> Unit, onDelete: () -> Unit, onIgnore: () -> Unit) {
    val c = levelColor(f.level)
    Panel(c) {
        Text("${levelFa(f.level)} آ· ${f.name}", color = c, fontWeight = FontWeight.Bold, fontSize = 16.sp)
        Text(f.path, color = Dimmed, fontFamily = Mono, fontSize = 10.sp)
        Dim(humanSize(f.size))
        f.reasons.forEach { Body("â€¢ $it") }
        Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            Button(
                onClick = onDelete,
                colors = ButtonDefaults.buttonColors(containerColor = c, contentColor = Color.Black)
            ) { Text("ط­ط°ظپ") }
            OutlinedButton(onClick = onQuarantine) { Text("ظ‚ط±ظ†ط·غŒظ†ظ‡") }
            OutlinedButton(onClick = onIgnore) { Text("ظ†ط§ط¯غŒط¯ظ‡") }
        }
    }
}

@Composable
private fun ReportCard(st: AvState, r: ScanReport) {
    Panel {
        Title("ع¯ط²ط§ط±ط´ ط¹ظ…ظ„ع©ط±ط¯")
        val sigCount = Signatures.hashes.size + Signatures.packages.size
        Body("âœ” ظ¾ط§غŒع¯ط§ظ‡ ط§ظ…ط¶ط§: $sigCount ط§ظ…ط¶ط§" + if (sigCount == 0) " (ط®ط§ظ„غŒط› ظپط¹ظ„ط§ظ‹ ط±ظپطھط§ط±غŒ)" else "")
        Body("âœ” ط¨ط±ظ†ط§ظ…ظ‡â€Œظ‡ط§غŒ ظ¾ظ„غŒâ€Œط§ط³طھظˆط± ظˆ ط³غŒط³طھظ…غŒ ظپظ‚ط· ط¨ط§ ط§ظ…ط¶ط§غŒ ظˆغŒط±ظˆط³ ط´ظ†ط§ط³ط§غŒغŒ ظ…غŒâ€Œط´ظˆظ†ط¯ط› ظ…ط¬ظˆط² طھظ†ظ‡ط§ ظ‡ط±ع¯ط² ظ‡ط´ط¯ط§ط± ظ†ظ…غŒâ€Œط¯ظ‡ط¯ (طھظ„ع¯ط±ط§ظ… ظˆ ظ…ط«ظ„ ط¢ظ† ط§ظ…ظ†â€Œط§ظ†ط¯).")
        Body("âœ” ط¨ط±ظ†ط§ظ…ظ‡â€ŒغŒ ظ†طµط¨â€Œط´ط¯ظ‡ ط§ط² ظ…ظ†ط¨ط¹ ظ†ط§ط´ظ†ط§ط³: ظ…ط¬ظˆط²ظ‡ط§ + ط¯ط³طھط±ط³غŒâ€Œظ¾ط°غŒط±غŒ + ظ…ط¯غŒط± ط¯ط³طھع¯ط§ظ‡ + ط®ظˆط§ظ†ط¯ظ† ط§ط¹ظ„ط§ظ† + ظ¾ظ†ظ‡ط§ظ† ط¨ظˆط¯ظ†.")
        if (r.heavy) {
            Body("âœ” ظ‡ط´ SHA-256 ظ‡ظ…ظ‡â€ŒغŒ APKظ‡ط§غŒ ظ†طµط¨â€Œط´ط¯ظ‡")
            Body("âœ” ع¯ط´طھظ† ع©ظ„ ط­ط§ظپط¸ظ‡: ${st.filesSeen} ظپط§غŒظ„ (EICAR/ط§ظ…ط¶ط§طŒ ظ¾ط³ظˆظ†ط¯ ط¯ظˆع¯ط§ظ†ظ‡طŒ ظپط§غŒظ„ ط§ط¬ط±ط§غŒغŒ ط¨ط§ ظ¾ط³ظˆظ†ط¯ ط¬ط¹ظ„غŒطŒ APK ظ†طµط¨â€Œظ†ط´ط¯ظ‡ ط¨ط§ ظ…ط¬ظˆط² ظ¾ط±ط®ط·ط±)")
            Dim("ظ¾ظˆط´ظ‡â€Œظ‡ط§غŒ Android/data ظˆ Android/obb ط±ط§ ط®ظˆط¯ ط§ظ†ط¯ط±ظˆغŒط¯ ظ‚ظپظ„ ع©ط±ط¯ظ‡ ظˆ ظ‚ط§ط¨ظ„ ط§ط³ع©ظ† ظ†غŒط³طھظ†ط¯.")
        } else {
            Dim("ط§ط³ع©ظ† ط³ط¨ع© ظپظ‚ط· ط¨ط±ظ†ط§ظ…ظ‡â€Œظ‡ط§ ط±ط§ ظ…غŒâ€Œط¨غŒظ†ط¯ط› ط¨ط±ط§غŒ ظپط§غŒظ„â€Œظ‡ط§ آ«ط§ط³ع©ظ† ط³ظ†ع¯غŒظ†آ» ط±ط§ ط¨ط²ظ†.")
        }
        Dim("ط§ظ…طھغŒط§ط² ط±ظپطھط§ط±غŒ â‰¥ غ¸ ظ…ط´ع©ظˆع© ظˆ â‰¥ غ±غ´ ظˆغŒط±ظˆط³ ط§ط³طھ. ظ‡ط´ط¯ط§ط± غŒط¹ظ†غŒ آ«ط¨ط±ط±ط³غŒ ع©ظ†آ»طŒ ظ†ظ‡ ط­ع©ظ… ظ‚ط·ط¹غŒ.")
    }
}

@Composable
private fun HealthCard() {
    val ctx = LocalContext.current
    val h = remember { DeviceHealth.snapshot(ctx) }
    Panel {
        Title("ط³ظ„ط§ظ…طھ ط¯ط³طھع¯ط§ظ‡")
        Body("ط¨ط§طھط±غŒ: ${h.battery}%" + if (h.charging) " âڑ، ط¯ط± ط­ط§ظ„ ط´ط§ط±عک" else "")
        Body("ط­ط§ظپط¸ظ‡â€ŒغŒ ط¢ط²ط§ط¯: ${String.format(Locale.US, "%.1f", h.storageFreeGb)} ط§ط² ${String.format(Locale.US, "%.1f", h.storageTotalGb)} ع¯غŒع¯")
        Body("RAM ط¢ط²ط§ط¯: ${h.ramFreeMb} ط§ط² ${h.ramTotalMb} ظ…ع¯")
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
        Glow("[ ط§ط¨ط²ط§ط±ظ‡ط§ ]")

        Panel {
            Title("ط¨ط±ط±ط³غŒ ظ„غŒظ†ع©: ط³ط§ظ„ظ…ظ‡ غŒط§ ظ†ظ‡طں")
            OutlinedTextField(
                value = url, onValueChange = { url = it }, singleLine = true,
                label = { Text("ظ„غŒظ†ع© ط±ط§ ط§غŒظ†ط¬ط§ ط¨ع†ط³ط¨ط§ظ†") }, modifier = Modifier.fillMaxWidth()
            )
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(onClick = { clip.getText()?.text?.let { url = it.trim() } }) { Text("ط¬ط§غŒâ€Œع¯ط°ط§ط±غŒ") }
                Button(onClick = { if (url.isNotBlank()) urlRes = UrlChecker.check(url.trim()) }) { Text(">_ ط¨ط±ط±ط³غŒ") }
            }
        }
        urlRes?.let { r ->
            val c = levelColor(r.level)
            Panel(c) {
                Text(
                    when (r.level) {
                        Level.CLEAN -> "âœ… ط¸ط§ظ‡ط±ط§ظ‹ ط³ط§ظ„ظ…"
                        Level.SUSPICIOUS -> "âڑ  ظ…ط´ع©ظˆع©"
                        Level.THREAT -> "â›” ط®ط·ط±ظ†ط§ع© (ط§ط­طھظ…ط§ظ„ ظپغŒط´غŒظ†ع¯)"
                    },
                    color = c, fontWeight = FontWeight.Bold, fontSize = 18.sp
                )
                r.host?.let { Text(it, color = Dimmed, fontFamily = Mono, fontSize = 12.sp) }
                r.reasons.forEach { Body("â€¢ $it") }
                Dim("ط§ظ…طھغŒط§ط² ط±غŒط³ع©: ${r.score}. ط§غŒظ† ط¨ط±ط±ط³غŒ ط¸ط§ظ‡ط±غŒ ط§ط³طھ ظˆ طھط¶ظ…غŒظ† ط§ظ…ظ†غŒطھ ظ†غŒط³طھط› ظ„غŒظ†ع© ظ†ط§ط´ظ†ط§ط³ ط±ط§ ط¨ط§ ط§ط­طھغŒط§ط· ط¨ط§ط² ع©ظ†.")
            }
        }

        Panel {
            Title("ط§ط³ع©ظ† غŒع© ظپط§غŒظ„")
            Body("ظ‡ط± ظپط§غŒظ„غŒ ط±ط§ ط§ظ†طھط®ط§ط¨ ع©ظ†ط› ظ‡ط´ SHA-256 ظˆ ط§ظ„ع¯ظˆظ‡ط§غŒ ظ…ط´ع©ظˆع© ط¨ط±ط±ط³غŒ ظ…غŒâ€Œط´ظˆط¯. ظپط§غŒظ„ ط§ط² ع¯ظˆط´غŒ ط®ط§ط±ط¬ ظ†ظ…غŒâ€Œط´ظˆط¯.")
            Button(onClick = { picker.launch(arrayOf("*/*")) }, enabled = !fileBusy) {
                Text(if (fileBusy) "ط¯ط± ط­ط§ظ„ ط§ط³ع©ظ†â€¦" else ">_ ط§ظ†طھط®ط§ط¨ ظپط§غŒظ„")
            }
        }
        if (fileErr) Panel(Amber) { Body("ظپط§غŒظ„ ط®ظˆط§ظ†ط¯ظ‡ ظ†ط´ط¯.", Amber) }
        fileRes?.let { r ->
            val c = levelColor(r.level)
            Panel(c) {
                Text("${levelFa(r.level)} آ· ${r.name}", color = c, fontWeight = FontWeight.Bold, fontSize = 16.sp)
                Dim(humanSize(r.size))
                if (r.reasons.isEmpty()) Body("ظ‡غŒع† ظ†ط´ط§ظ†ظ‡â€ŒغŒ ظ…ط´ع©ظˆع©غŒ ظ¾غŒط¯ط§ ظ†ط´ط¯.") else r.reasons.forEach { Body("â€¢ $it") }
                Text("SHA256 ${r.sha256}", color = Dimmed, fontFamily = Mono, fontSize = 10.sp)
            }
        }

        Panel {
            Title("ط§ظ…ظ†غŒطھ Wi-Fi")
            Body("ظ†ظˆط¹ ط±ظ…ط²ظ†ع¯ط§ط±غŒ ط´ط¨ع©ظ‡â€Œط§غŒ ع©ظ‡ ط¨ظ‡ ط¢ظ† ظˆطµظ„غŒ ط±ط§ ط¨ط±ط±ط³غŒ ظ…غŒâ€Œع©ظ†ط¯.")
            Button(onClick = { wifi = WifiAudit.check(ctx) }) { Text(">_ ط¨ط±ط±ط³غŒ Wi-Fi") }
        }
        wifi?.let { w ->
            val c = levelColor(w.level)
            Panel(c) {
                Text(w.label, color = c, fontWeight = FontWeight.Bold, fontSize = 16.sp)
                if (w.note.isNotEmpty()) Body(w.note)
            }
        }

        Panel {
            Title("ظ…ظ…غŒط²غŒ ط­ط±غŒظ… ط®طµظˆطµغŒ")
            Body("ع©ط¯ط§ظ… ط¨ط±ظ†ط§ظ…ظ‡â€Œظ‡ط§ ظ…ط¬ظˆط² ظ…غŒع©ط±ظˆظپظ†طŒ ط¯ظˆط±ط¨غŒظ†طŒ ظ…ظˆظ‚ط¹غŒطھ ظˆ ظ¾غŒط§ظ…ع© ط±ط§ ظˆط§ظ‚ط¹ط§ظ‹ ع¯ط±ظپطھظ‡â€Œط§ظ†ط¯.")
            Button(
                enabled = !privBusy,
                onClick = {
                    privBusy = true
                    scope.launch {
                        priv = withContext(Dispatchers.Default) { try { PrivacyAudit.run(ctx) } catch (e: Exception) { null } }
                        privBusy = false
                    }
                }
            ) { Text(if (privBusy) "ط¯ط± ط­ط§ظ„ ط¨ط±ط±ط³غŒâ€¦" else ">_ ط§ط¬ط±ط§غŒ ظ…ظ…غŒط²غŒ") }
        }
        priv?.let { p ->
            Panel {
                @Composable
                fun Section(name: String, list: List<String>) {
                    Text("$name (${list.size})", color = Cyan, fontWeight = FontWeight.Bold, fontSize = 13.sp)
                    Body(if (list.isEmpty()) "â€”" else list.take(10).joinToString("طŒ ") + if (list.size > 10) " â€¦" else "")
                }
                Section("ظ…غŒع©ط±ظˆظپظ†", p.mic)
                Section("ط¯ظˆط±ط¨غŒظ†", p.camera)
                Section("ظ…ظˆظ‚ط¹غŒطھ ظ…ع©ط§ظ†غŒ", p.location)
                Section("ظ¾غŒط§ظ…ع©", p.sms)
                Dim("ظپظ‚ط· ط¨ط±ظ†ط§ظ…ظ‡â€Œظ‡ط§غŒ ط؛غŒط±ط³غŒط³طھظ…غŒ. ظ…ط¬ظˆط² ط§ط¶ط§ظپغŒ ط±ط§ ط§ط² طھظ†ط¸غŒظ…ط§طھ ع¯ظˆط´غŒ â†گ ط¨ط±ظ†ط§ظ…ظ‡â€Œظ‡ط§ â†گ ظ…ط¬ظˆط²ظ‡ط§ ط¨ط¨ظ†ط¯.")
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
        Glow("[ ظ‚ط±ظ†ط·غŒظ†ظ‡ ]")
        Dim("ظپط§غŒظ„â€Œظ‡ط§غŒ ظ…ط´ع©ظˆع© ط§غŒظ†ط¬ط§ ط§ظ…ظ† ظˆ ط؛غŒط±ظپط¹ط§ظ„ ظ†ع¯ظ‡ ط¯ط§ط´طھظ‡ ظ…غŒâ€Œط´ظˆظ†ط¯. ظ…غŒâ€Œطھظˆط§ظ†غŒ ط¨ط§ط²ع¯ط±ط¯ط§ظ†غŒ ع©ظ†غŒ غŒط§ ط¨ط±ط§غŒ ظ‡ظ…غŒط´ظ‡ ط­ط°ظپ.")
        if (items.isEmpty()) Panel { Body("ظ‚ط±ظ†ط·غŒظ†ظ‡ ط®ط§ظ„غŒ ط§ط³طھ.") }
        items.forEach { it ->
            key(it.id) {
                Panel(Amber) {
                    Text(it.path.substringAfterLast('/'), color = Amber, fontWeight = FontWeight.Bold)
                    Text(it.path, color = Dimmed, fontFamily = Mono, fontSize = 10.sp)
                    Dim(humanSize(it.size))
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedButton(onClick = {
                            scope.launch { withContext(Dispatchers.IO) { Quarantine.restore(ctx, it) }; tick++ }
                        }) { Text("ط¨ط§ط²ع¯ط±ط¯ط§ظ†غŒ") }
                        Button(
                            onClick = { scope.launch { withContext(Dispatchers.IO) { Quarantine.deleteForever(ctx, it) }; tick++ } },
                            colors = ButtonDefaults.buttonColors(containerColor = Red, contentColor = Color.Black)
                        ) { Text("ط­ط°ظپ ط¯ط§ط¦ظ…غŒ") }
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
        Glow("[ ظˆط¶ط¹غŒطھ ]")

        Panel {
            Title("ط­ط§ظ„طھ ع©ط§ط±")
            Body("âœ” ط§ط³ع©ظ† ط¯ط³طھغŒ + ط¨ط±ط±ط³غŒ ط³ط¨ع© ظ¾ط³â€Œط²ظ…غŒظ†ظ‡ (WorkManagerط› ط¨ط§ ظ…ط­ط¯ظˆط¯غŒطھâ€Œظ‡ط§غŒ ط§ظ†ط¯ط±ظˆغŒط¯).")
            Body("âœ” طھط­ظ„غŒظ„â€Œظ‡ط§ ط±ظˆغŒ ط¯ط³طھع¯ط§ظ‡ ط§ظ†ط¬ط§ظ… ظ…غŒâ€Œط´ظˆظ†ط¯ط› ط¨ط±ظ†ط§ظ…ظ‡ ط¯ط§ط¯ظ‡â€Œط§غŒ ط¨ط±ط§غŒ ط³ط±ظˆط± ط§ط±ط³ط§ظ„ ظ†ظ…غŒâ€Œع©ظ†ط¯.")
            Body(if (FileSweep.hasAccess(ctx)) "âœ” ط¯ط³طھط±ط³غŒ ط¨ظ‡ ظپط§غŒظ„â€Œظ‡ط§ ط¯ط§ط¯ظ‡ ط´ط¯ظ‡ (ط§ط³ع©ظ† ط³ظ†ع¯غŒظ† ط¢ظ…ط§ط¯ظ‡ ط§ط³طھ)" else "âœ– ط¯ط³طھط±ط³غŒ ط¨ظ‡ ظپط§غŒظ„â€Œظ‡ط§ ط¯ط§ط¯ظ‡ ظ†ط´ط¯ظ‡ (ط¨ط±ط§غŒ ط§ط³ع©ظ† ط³ظ†ع¯غŒظ† ظ„ط§ط²ظ… ط§ط³طھ)", if (FileSweep.hasAccess(ctx)) Soft else Amber)
            Body(if (usage) "âœ” ظ¾ط§غŒط´ ظ…طµط±ظپ ط¨ط±ظ†ط§ظ…ظ‡â€Œظ‡ط§ ظپط¹ط§ظ„ ط§ط³طھ" else "âœ– ظ¾ط§غŒط´ ظ…طµط±ظپ: ط¯ط³طھط±ط³غŒ ظ†ط¯ط§ط¯ظ‡â€Œط§غŒ", if (usage) Soft else Amber)
            if (!usage) OutlinedButton(onClick = { UsageMonitor.openSettings(ctx) }) { Text("ظپط¹ط§ظ„â€Œط³ط§ط²غŒ Usage access") }
            OutlinedButton(onClick = { tick++ }) { Text("ط¨ظ‡â€Œط±ظˆط²ط±ط³ط§ظ†غŒ ظˆط¶ط¹غŒطھ") }
        }

        if (heavy.isNotEmpty()) {
            Panel(Amber) {
                Title("ط¨ط±ظ†ط§ظ…ظ‡â€Œظ‡ط§غŒ ظ¾ط±ظ…طµط±ظپ (غ²غ´ ط³ط§ط¹طھ ع¯ط°ط´طھظ‡)", Amber)
                heavy.forEach { Body("${appLabel(ctx, it.pkg)} آ· ${it.minutes} ط¯ظ‚غŒظ‚ظ‡ ط¯ط± ظ¾غŒط´â€Œط²ظ…غŒظ†ظ‡") }
                Dim("ط§ظ†ط¯ط±ظˆغŒط¯ ط¯ط±طµط¯ ط¨ط§طھط±غŒ ظ‡ط± ط¨ط±ظ†ط§ظ…ظ‡ ط±ط§ ظ†ظ…غŒâ€Œط¯ظ‡ط¯ط› ط²ظ…ط§ظ† ظ¾غŒط´â€Œط²ظ…غŒظ†ظ‡ ظ…ط¹غŒط§ط± ط§ط³طھ.")
            }
        }

        Panel {
            Title("طھط§ط±غŒط®ع†ظ‡â€ŒغŒ ط§ط³ع©ظ†")
            if (history.isEmpty()) Body("ظ‡ظ†ظˆط² ط§ط³ع©ظ†غŒ ط§ظ†ط¬ط§ظ… ظ†ط´ط¯ظ‡.") else history.forEach { Body(it) }
        }

        Panel {
            Title("ع†ط±ط§ ع¯ظˆط´غŒ ظ…غŒâ€Œع¯ظˆغŒط¯ CyberGuard ط®ط·ط±ظ†ط§ع© ط§ط³طھطں")
            Body("ظ…ط¹ظ…ظˆظ„ط§ظ‹ ظ‡ط´ط¯ط§ط± ط§ط´طھط¨ط§ظ‡ ط§ط³طھ: ط¨ط±ظ†ط§ظ…ظ‡ ط¨ط§ ع©ظ„غŒط¯ ط¯غŒط¨ط§ع¯ ط³ط§ط®طھظ‡ ط´ط¯ظ‡طŒ ط§ط² ظ¾ظ„غŒâ€Œط§ط³طھظˆط± ظ†غŒط§ظ…ط¯ظ‡ ظˆ ظ…ط¬ظˆط²ظ‡ط§غŒغŒ ظ…غŒâ€Œط®ظˆط§ظ‡ط¯ ع©ظ‡ ط¢ظ†طھغŒâ€ŒظˆغŒط±ظˆط³â€Œظ‡ط§ ظ‡ظ… ظ„ط§ط²ظ… ط¯ط§ط±ظ†ط¯. ط¨ط±ط§غŒ ط§ط³طھظپط§ط¯ظ‡â€ŒغŒ ط´ط®طµغŒ آ«More details â†گ Install anywayآ» ط±ط§ ط¨ط²ظ†.")
        }

        Panel {
            Title("ظ†ط§ط¯غŒط¯ظ‡â€Œع¯ط±ظپطھظ‡â€Œظ‡ط§")
            OutlinedButton(onClick = { Store.clearIgnored(ctx); tick++ }) {
                Text("ظ¾ط§ع©â€Œع©ط±ط¯ظ† ظ„غŒط³طھ (${Store.ignored(ctx).size})")
            }
        }
        Spacer(Modifier.height(12.dp))
    }
}
