package com.cyberguard.av

import android.Manifest
import android.os.Build
import android.os.Bundle
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
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
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
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

private val Neon = Color(0xFF00FF41)
private val Red = Color(0xFFFF003C)
private val Amber = Color(0xFFFFD000)
private val Mono = FontFamily.Monospace

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme(
                colorScheme = darkColorScheme(
                    primary = Neon, onPrimary = Color.Black, background = Color.Black,
                    surface = Color(0xFF020A05), onBackground = Neon, onSurface = Neon
                )
            ) {
                Surface(color = Color.Black, modifier = Modifier.fillMaxSize()) { Screen() }
            }
        }
    }
}

private fun levelColor(l: Level) = when (l) { Level.THREAT -> Red; Level.SUSPICIOUS -> Amber; Level.CLEAN -> Neon }

@Composable
private fun Radar(scanning: Boolean, label: String, color: Color) {
    val t = rememberInfiniteTransition(label = "radar")
    val angle by t.animateFloat(0f, 360f, infiniteRepeatable(tween(1600, easing = LinearEasing)), label = "angle")
    Box(Modifier.size(220.dp), contentAlignment = Alignment.Center) {
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

@Composable
private fun Screen() {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    var heavy by remember { mutableStateOf(false) }
    var scanning by remember { mutableStateOf(false) }
    var progress by remember { mutableStateOf(0) }
    var current by remember { mutableStateOf("") }
    var results by remember { mutableStateOf<List<Finding>?>(null) }
    var url by remember { mutableStateOf("") }
    var urlRes by remember { mutableStateOf<UrlChecker.Result?>(null) }

    val notifPerm = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { }
    LaunchedEffect(Unit) {
        if (Build.VERSION.SDK_INT >= 33) notifPerm.launch(Manifest.permission.POST_NOTIFICATIONS)
    }

    val bad = results?.any { it.level == Level.THREAT } == true
    val radarColor = if (bad) Red else Neon
    val label = when {
        scanning -> "$progress%"
        results == null -> "OK"
        results!!.isEmpty() -> "100"
        else -> "!"
    }

    LazyColumn(
        Modifier.fillMaxSize().statusBarsPadding().padding(16.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        item { Text("CYBERGUARD//v0.1", color = Neon, fontFamily = Mono, fontSize = 24.sp, fontWeight = FontWeight.Bold) }
        item { Radar(scanning, label, radarColor) }
        item { Text(if (scanning) current else "NO MERCY FOR MALWARE", color = Color(0xFF3FA062), fontFamily = Mono, fontSize = 12.sp, maxLines = 1) }
        item {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                FilterChip(selected = !heavy, onClick = { heavy = false }, label = { Text("اسکن سبک") })
                FilterChip(selected = heavy, onClick = { heavy = true }, label = { Text("اسکن سنگین") })
            }
        }
        item {
            Button(
                enabled = !scanning, modifier = Modifier.fillMaxWidth(),
                onClick = {
                    scanning = true; results = null; progress = 0
                    scope.launch {
                        val found = withContext(Dispatchers.Default) {
                            Scanner.scanAll(ctx, heavy) { d, t, p -> progress = d * 100 / t; current = p }
                        }
                        results = found; scanning = false
                        found.filter { it.level != Level.CLEAN }.forEach {
                            Notifier.alert(ctx, it.pkg.hashCode(), it.label, it.reasons.joinToString(" · "))
                        }
                    }
                }
            ) { Text(">_ شروع اسکن", fontFamily = Mono) }
        }

        results?.let { list ->
            if (list.isEmpty()) item { Text("چیزی پیدا نشد. سیستم امن است.", color = Neon) }
            items(list) { f ->
                val c = levelColor(f.level)
                OutlinedCard(border = BorderStroke(1.dp, c), modifier = Modifier.fillMaxWidth()) {
                    Column(Modifier.padding(12.dp)) {
                        Text("${f.label}  [${f.level}]", color = c, fontWeight = FontWeight.Bold)
                        Text(f.pkg, color = Color(0xFF3FA062), fontFamily = Mono, fontSize = 11.sp)
                        Text(f.reasons.joinToString(" · "), color = Color(0xFFB8FFC8), fontSize = 12.sp)
                    }
                }
            }
        }

        item {
            OutlinedTextField(
                value = url, onValueChange = { url = it }, singleLine = true,
                label = { Text("بررسی لینک") }, modifier = Modifier.fillMaxWidth()
            )
        }
        item {
            OutlinedButton(onClick = { urlRes = UrlChecker.check(url.trim()) }, modifier = Modifier.fillMaxWidth()) {
                Text(">_ اسکن لینک", fontFamily = Mono)
            }
        }
        urlRes?.let { r ->
            item { Text("${r.level} · score ${r.score}\n${r.reasons.joinToString(" · ")}", color = levelColor(r.level)) }
        }

        item {
            OutlinedButton(onClick = { UsageMonitor.openSettings(ctx) }, modifier = Modifier.fillMaxWidth()) {
                Text("فعال‌سازی پایش مصرف (Usage access)")
            }
        }
    }
}
