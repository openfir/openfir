// SPDX-License-Identifier: Apache-2.0
package io.openfir.app

import android.app.Activity
import android.content.Intent
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.net.Uri
import android.os.Bundle
import android.provider.OpenableColumns
import android.text.InputType
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.EditText
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.Switch
import android.widget.TextView
import android.widget.Toast
import org.json.JSONObject
import java.io.File
import java.io.FileOutputStream

/**
 * OpenFIR Native Android Client (Android 8–15+ / API 26–35).
 * 100% pure Kotlin + Android Platform SDK (ZERO AndroidX, ZERO Material, ZERO Compose, ZERO third-party libs).
 * Implements the unified "Obsidian Frost x Neon Aurora" Web3 Glassmorphism UI.
 */
class MainActivity : Activity() {

    private var currentTab = 0 // 0=PUSH, 1=PULL, 2=SERVER, 3=AUDIT
    private var transportIdx = 0 // 0=auto, 1=udp, 2=tcp
    private var activeJob = 0L
    private var serverHandle = 0L

    private lateinit var statusPill: TextView
    private lateinit var tabBtns: List<Button>
    private lateinit var modeBtns: List<Button>
    private lateinit var cardHeader: TextView

    private lateinit var serverFieldWrap: View
    private lateinit var serverInput: EditText
    private lateinit var listenFieldWrap: View
    private lateinit var listenInput: EditText
    private lateinit var secretFieldWrap: View
    private lateinit var secretInput: EditText
    private lateinit var fileFieldWrap: View
    private lateinit var fileLabel: TextView
    private lateinit var fileInput: EditText
    private lateinit var browseBtn: Button
    private lateinit var dirFieldWrap: View
    private lateinit var dirInput: EditText
    private lateinit var transportWrap: View
    private lateinit var overwriteWrap: View
    private lateinit var overwriteSwitch: Switch
    private lateinit var auditInfoView: TextView
    private lateinit var serverInfoView: TextView
    private lateinit var ctaBtn: Button

    private lateinit var progressText: TextView
    private lateinit var progressBar: NeonProgressBar
    private lateinit var kpiGoodput: TextView
    private lateinit var kpiWire: TextView
    private lateinit var kpiCas: TextView
    private lateinit var kpiFec: TextView
    private lateinit var sparkline: NeonSparklineView
    private lateinit var merkleView: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.statusBarColor = FrostColors.BG_VOID
        window.navigationBarColor = FrostColors.BG_VOID

        setContentView(buildRoot())
        val outDir = File(filesDir, "openfir_data").apply { mkdirs() }
        dirInput.setText(outDir.absolutePath)
        serverInput.setText("127.0.0.1:9900")
        listenInput.setText(":9900")
        secretInput.setText(OpenFIRCore.keygen())

        OpenFIRCore.setCallback { handle, json -> onCoreEvent(handle, json) }
        applyTabState()
    }

    override fun onDestroy() {
        OpenFIRCore.setCallback(null)
        if (activeJob != 0L) OpenFIRCore.cancelTransfer(activeJob)
        if (serverHandle != 0L) OpenFIRCore.stopServer(serverHandle)
        super.onDestroy()
    }

    private fun pillBg(start: Int, end: Int, radiusDp: Float = 12f): GradientDrawable =
        GradientDrawable(GradientDrawable.Orientation.LEFT_RIGHT, intArrayOf(start, end)).apply {
            cornerRadius = dp(radiusDp)
        }

    private fun inputBg(): GradientDrawable =
        GradientDrawable().apply {
            setColor(FrostColors.GLASS_INPUT)
            cornerRadius = dp(10f)
            setStroke(dpInt(1), Color.argb(46, 255, 255, 255))
        }

    private fun buildRoot(): View {
        val frame = FrameLayout(this)
        frame.addView(
            AuroraBackdropView(this),
            FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT)
        )

        val scroll = ScrollView(this).apply { isFillViewport = true }
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dpInt(14), dpInt(16), dpInt(14), dpInt(28))
        }

        // 1. Header Frosted Strip
        val header = FrostCardLayout(this, elevated = true, activeRim = true, radiusDp = 18f).apply {
            setPadding(dpInt(14), dpInt(12), dpInt(14), dpInt(12))
        }
        val topRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }
        val brand = TextView(this).apply {
            text = "◆ OPENFIR"
            setTextColor(FrostColors.TEXT_PRI)
            textSize = 18f
            typeface = Typeface.DEFAULT_BOLD
        }
        val ver = TextView(this).apply {
            text = " v2.0 FROST"
            setTextColor(FrostColors.CYAN)
            textSize = 11f
            typeface = Typeface.MONOSPACE
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
        }
        statusPill = TextView(this).apply {
            text = "● IDLE"
            setTextColor(FrostColors.TEXT_SEC)
            textSize = 11f
            typeface = Typeface.MONOSPACE
            background = inputBg()
            setPadding(dpInt(10), dpInt(5), dpInt(10), dpInt(5))
        }
        topRow.addView(brand)
        topRow.addView(ver)
        topRow.addView(statusPill)
        header.addView(topRow)

        val tabsRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            setPadding(0, dpInt(10), 0, 0)
        }
        val labels = listOf("PUSH", "PULL", "SERVER", "AUDIT")
        tabBtns = labels.mapIndexed { idx, lbl ->
            Button(this).apply {
                text = lbl
                textSize = 12f
                typeface = Typeface.DEFAULT_BOLD
                isAllCaps = false
                setPadding(dpInt(6), dpInt(8), dpInt(6), dpInt(8))
                setOnClickListener {
                    currentTab = idx
                    applyTabState()
                }
            }.also { btn ->
                tabsRow.addView(btn, LinearLayout.LayoutParams(0, dpInt(36), 1f).apply {
                    if (idx > 0) marginStart = dpInt(6)
                })
            }
        }
        header.addView(tabsRow)
        root.addView(header, lpMatchWrap(14))

        // 2. Primary Frosted Control Card
        val ctrlCard = FrostCardLayout(this, elevated = false, activeRim = true, radiusDp = 20f).apply {
            setPadding(dpInt(16), dpInt(14), dpInt(16), dpInt(16))
        }
        cardHeader = TextView(this).apply {
            text = "PUSH · HYBRID UPLOAD"
            setTextColor(FrostColors.CYAN)
            textSize = 12.5f
            typeface = Typeface.MONOSPACE
            setPadding(0, 0, 0, dpInt(8))
        }
        ctrlCard.addView(cardHeader)

        val (srvWrap, srvEt) = makeField("SERVER ENDPOINT (host:port)", "127.0.0.1:9900", null)
        serverFieldWrap = srvWrap; serverInput = srvEt
        ctrlCard.addView(srvWrap)

        val (lsnWrap, lsnEt) = makeField("DUAL-STACK LISTEN ADDR (:9900)", ":9900", null)
        listenFieldWrap = lsnWrap; listenInput = lsnEt
        ctrlCard.addView(lsnWrap)

        val keygenBtn = makeChip("KEYGEN", FrostColors.VIOLET) {
            secretInput.setText(OpenFIRCore.keygen())
            Toast.makeText(this, "Generated 256-bit key", Toast.LENGTH_SHORT).show()
        }
        val (secWrap, secEt) = makeField("256-BIT SHARED SECRET", "64-hex or pass:...", keygenBtn)
        secretFieldWrap = secWrap; secretInput = secEt
        ctrlCard.addView(secWrap)

        browseBtn = makeChip("PICK", FrostColors.CYAN) { launchFilePicker() }
        val (fWrap, fEt, fLbl) = makeFieldWithLabel("LOCAL FILE (SAF Picker)", "Tap PICK or enter path", browseBtn)
        fileFieldWrap = fWrap; fileInput = fEt; fileLabel = fLbl
        ctrlCard.addView(fWrap)

        val (dWrap, dEt) = makeField("STORAGE / OUTPUT DIRECTORY", "", null)
        dirFieldWrap = dWrap; dirInput = dEt
        ctrlCard.addView(dWrap)

        // Transport Mode Pills
        val trBox = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(0, dpInt(8), 0, dpInt(6))
        }
        trBox.addView(TextView(this).apply {
            text = "TRANSPORT DATA PLANE"
            setTextColor(FrostColors.TEXT_SEC)
            textSize = 11f
            setPadding(0, 0, 0, dpInt(6))
        })
        val mRow = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        modeBtns = listOf("AUTO HYBRID", "UDP GSO", "TLS 1.3 TCP").mapIndexed { idx, lbl ->
            Button(this).apply {
                text = lbl
                textSize = 11f
                typeface = Typeface.DEFAULT_BOLD
                isAllCaps = false
                setOnClickListener {
                    transportIdx = idx
                    updateModePills()
                }
            }.also { b ->
                mRow.addView(b, LinearLayout.LayoutParams(0, dpInt(36), 1f).apply {
                    if (idx > 0) marginStart = dpInt(6)
                })
            }
        }
        trBox.addView(mRow)
        transportWrap = trBox
        ctrlCard.addView(trBox)

        val ovRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(0, dpInt(6), 0, dpInt(8))
        }
        overwriteSwitch = Switch(this).apply { isChecked = true }
        val ovLbl = TextView(this).apply {
            text = "Allow Overwrite · 4 TLS Lanes · 1000 MiB/s"
            setTextColor(FrostColors.TEXT_SEC)
            textSize = 12f
            setPadding(dpInt(8), 0, 0, 0)
        }
        ovRow.addView(overwriteSwitch)
        ovRow.addView(ovLbl)
        overwriteWrap = ovRow
        ctrlCard.addView(ovRow)

        serverInfoView = TextView(this).apply {
            text = "Server standby — ready to bind TLS 1.3 + UDP"
            setTextColor(FrostColors.TEXT_SEC)
            textSize = 12f
            typeface = Typeface.MONOSPACE
            setPadding(0, dpInt(8), 0, dpInt(10))
        }
        ctrlCard.addView(serverInfoView)

        auditInfoView = TextView(this).apply {
            text = "• Suite 1: 4 MiB Hybrid Auto Push + Pull (DEFLATE/Zero/Raw)\n" +
                   "• Suite 2: 17B Shift-Resistant Rabin CDC CAS\n" +
                   "• Suite 3: 10% Burst-Loss Pure UDP + GF(256) RS FEC\n" +
                   "• Suite 4: ISP UDP Blackhole -> TLS 1.3 TCP Auto-Failover\n\n" +
                   "Zero third-party UI libraries · Apache-2.0 clean-room engine"
            setTextColor(FrostColors.TEXT_SEC)
            textSize = 12f
            setPadding(0, dpInt(4), 0, dpInt(12))
        }
        ctrlCard.addView(auditInfoView)

        ctaBtn = Button(this).apply {
            text = "LAUNCH HYBRID PUSH"
            setTextColor(FrostColors.BG_VOID)
            textSize = 14f
            typeface = Typeface.DEFAULT_BOLD
            isAllCaps = false
            setOnClickListener { triggerCta() }
        }
        ctrlCard.addView(ctaBtn, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dpInt(46)).apply {
            topMargin = dpInt(8)
        })
        root.addView(ctrlCard, lpMatchWrap(14))

        // 3. Live Telemetry Frosted Card
        val teleCard = FrostCardLayout(this, elevated = false, activeRim = false, radiusDp = 20f).apply {
            setPadding(dpInt(16), dpInt(14), dpInt(16), dpInt(16))
        }
        teleCard.addView(TextView(this).apply {
            text = "LIVE TELEMETRY · ZERO-COPY ENGINE"
            setTextColor(FrostColors.VIOLET)
            textSize = 12.5f
            typeface = Typeface.MONOSPACE
            setPadding(0, 0, 0, dpInt(8))
        })

        progressText = TextView(this).apply {
            text = "0.0% · 0 B / 0 B · STANDBY"
            setTextColor(FrostColors.TEXT_PRI)
            textSize = 13f
            typeface = Typeface.MONOSPACE
            setPadding(0, 0, 0, dpInt(6))
        }
        teleCard.addView(progressText)

        progressBar = NeonProgressBar(this)
        teleCard.addView(progressBar, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dpInt(11)).apply {
            bottomMargin = dpInt(12)
        })

        // 2x2 Frosted KPI Micro-Tiles
        val kRow1 = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        val (k1Card, k1Val) = makeKpiTile("GOODPUT", "0.00 MiB/s", FrostColors.CYAN)
        val (k2Card, k2Val) = makeKpiTile("WIRE I/O", "U:0 B T:0 B", FrostColors.TEXT_MONO)
        kpiGoodput = k1Val; kpiWire = k2Val
        kRow1.addView(k1Card, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply { marginEnd = dpInt(5) })
        kRow1.addView(k2Card, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply { marginStart = dpInt(5) })
        teleCard.addView(kRow1, lpMatchWrap(10))

        val kRow2 = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        val (k3Card, k3Val) = makeKpiTile("CDC CAS / DEDUP", "CAS 0 · Z 0 · D 0", FrostColors.MINT)
        val (k4Card, k4Val) = makeKpiTile("GF(256) RS FEC", "Rec 0 · FO 0", FrostColors.TEXT_PRI)
        kpiCas = k3Val; kpiFec = k4Val
        kRow2.addView(k3Card, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply { marginEnd = dpInt(5) })
        kRow2.addView(k4Card, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply { marginStart = dpInt(5) })
        teleCard.addView(kRow2, lpMatchWrap(12))

        // Sparkline Card
        val spCard = FrostCardLayout(this, elevated = true, activeRim = false, radiusDp = 14f).apply {
            setPadding(dpInt(12), dpInt(10), dpInt(12), dpInt(10))
        }
        spCard.addView(TextView(this).apply {
            text = "REAL-TIME THROUGHPUT SPARKLINE (MiB/s)"
            setTextColor(FrostColors.TEXT_SEC)
            textSize = 10.5f
            typeface = Typeface.MONOSPACE
            setPadding(0, 0, 0, dpInt(4))
        })
        sparkline = NeonSparklineView(this)
        spCard.addView(sparkline, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dpInt(82)))
        teleCard.addView(spCard, lpMatchWrap(12))

        merkleView = TextView(this).apply {
            text = "Ready · Hybrid TLS 1.3 + UDP GSO/GF(256) RS + Rabin CDC"
            setTextColor(FrostColors.TEXT_SEC)
            textSize = 11.5f
            typeface = Typeface.MONOSPACE
            background = inputBg()
            setPadding(dpInt(10), dpInt(9), dpInt(10), dpInt(9))
        }
        teleCard.addView(merkleView, lpMatchWrap(0))

        root.addView(teleCard, lpMatchWrap(0))
        scroll.addView(root)
        frame.addView(scroll, FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT))
        return frame
    }

    private fun lpMatchWrap(bottomDp: Int): LinearLayout.LayoutParams =
        LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
            bottomMargin = dpInt(bottomDp)
        }

    private fun makeChip(title: String, tint: Int, onClick: () -> Unit): Button =
        Button(this).apply {
            text = title
            setTextColor(FrostColors.TEXT_PRI)
            textSize = 11f
            typeface = Typeface.DEFAULT_BOLD
            isAllCaps = false
            background = GradientDrawable().apply {
                setColor(Color.argb(85, Color.red(tint), Color.green(tint), Color.blue(tint)))
                cornerRadius = dp(10f)
                setStroke(dpInt(1), tint)
            }
            setPadding(dpInt(12), 0, dpInt(12), 0)
            setOnClickListener { onClick() }
        }

    private fun makeField(label: String, hintText: String, trailing: View?): Pair<View, EditText> {
        val (wrap, et, _) = makeFieldWithLabel(label, hintText, trailing)
        return wrap to et
    }

    private fun makeFieldWithLabel(label: String, hintText: String, trailing: View?): Triple<View, EditText, TextView> {
        val box = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(0, dpInt(4), 0, dpInt(4))
        }
        val tv = TextView(this).apply {
            text = label
            setTextColor(FrostColors.TEXT_SEC)
            textSize = 11f
            setPadding(0, 0, 0, dpInt(4))
        }
        val row = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }
        val et = EditText(this).apply {
            hint = hintText
            setHintTextColor(FrostColors.TEXT_MUTED)
            setTextColor(FrostColors.TEXT_MONO)
            textSize = 13f
            typeface = Typeface.MONOSPACE
            isSingleLine = true
            background = inputBg()
            setPadding(dpInt(12), dpInt(9), dpInt(12), dpInt(9))
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
        }
        row.addView(et, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        if (trailing != null) {
            row.addView(trailing, LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, dpInt(40)).apply {
                marginStart = dpInt(8)
            })
        }
        box.addView(tv)
        box.addView(row)
        return Triple(box, et, tv)
    }

    private fun makeKpiTile(label: String, initial: String, color: Int): Pair<FrostCardLayout, TextView> {
        val card = FrostCardLayout(this, elevated = true, activeRim = false, radiusDp = 14f).apply {
            setPadding(dpInt(12), dpInt(10), dpInt(12), dpInt(10))
        }
        card.addView(TextView(this).apply {
            text = label
            setTextColor(FrostColors.TEXT_SEC)
            textSize = 10f
        })
        val tv = TextView(this).apply {
            text = initial
            setTextColor(color)
            textSize = 12.5f
            typeface = Typeface.MONOSPACE
            setPadding(0, dpInt(4), 0, 0)
        }
        card.addView(tv)
        return card to tv
    }

    private fun applyTabState() {
        tabBtns.forEachIndexed { i, b ->
            val act = (i == currentTab)
            b.setTextColor(if (act) FrostColors.BG_VOID else FrostColors.TEXT_SEC)
            b.background = if (act) pillBg(FrostColors.CYAN, FrostColors.ACCENT_END, 18f) else inputBg()
        }
        updateModePills()

        val isPush = currentTab == 0
        val isPull = currentTab == 1
        val isSrv  = currentTab == 2
        val isAud  = currentTab == 3

        cardHeader.text = when (currentTab) {
            0 -> "PUSH · HYBRID UPLOAD"
            1 -> "PULL · MERKLE DOWNLOAD"
            2 -> "SERVER · DUAL-STACK TLS 1.3 + UDP"
            else -> "AUDIT · 4-SUITE PROTOCOL VERIFICATION"
        }
        serverFieldWrap.visibility = if (isPush || isPull) View.VISIBLE else View.GONE
        listenFieldWrap.visibility = if (isSrv) View.VISIBLE else View.GONE
        secretFieldWrap.visibility = if (!isAud) View.VISIBLE else View.GONE
        fileFieldWrap.visibility   = if (isPush || isPull) View.VISIBLE else View.GONE
        fileLabel.text = if (isPush) "LOCAL FILE (SAF Picker)" else "REMOTE FILE / DIR NAME"
        browseBtn.visibility = if (isPush) View.VISIBLE else View.GONE
        dirFieldWrap.visibility    = if (isPull || isSrv) View.VISIBLE else View.GONE
        transportWrap.visibility   = if (isPush || isPull) View.VISIBLE else View.GONE
        overwriteWrap.visibility   = if (!isAud) View.VISIBLE else View.GONE
        serverInfoView.visibility  = if (isSrv) View.VISIBLE else View.GONE
        auditInfoView.visibility   = if (isAud) View.VISIBLE else View.GONE

        updateCtaButton()
    }

    private fun updateModePills() {
        modeBtns.forEachIndexed { i, b ->
            val act = (i == transportIdx)
            b.setTextColor(if (act) FrostColors.BG_VOID else FrostColors.TEXT_SEC)
            b.background = if (act) pillBg(FrostColors.CYAN, FrostColors.ACCENT_END, 10f) else inputBg()
        }
    }

    private fun updateCtaButton() {
        val isStop = (currentTab == 2 && serverHandle != 0L) || (currentTab != 2 && activeJob != 0L)
        ctaBtn.text = when {
            currentTab == 2 && serverHandle != 0L -> "STOP DUAL-STACK SERVER"
            currentTab == 2 -> "START DUAL-STACK SERVER"
            activeJob != 0L -> "CANCEL ACTIVE TRANSFER"
            currentTab == 0 -> "LAUNCH HYBRID PUSH"
            currentTab == 1 -> "LAUNCH MERKLE PULL"
            else -> "RUN 4-SUITE PROTOCOL AUDIT"
        }
        ctaBtn.background = when {
            isStop -> pillBg(FrostColors.ROSE, FrostColors.MAGENTA, 12f)
            currentTab == 2 -> pillBg(FrostColors.MINT, FrostColors.CYAN, 12f)
            else -> pillBg(FrostColors.CYAN, FrostColors.ACCENT_END, 12f)
        }
    }

    private fun launchFilePicker() {
        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "*/*"
        }
        @Suppress("DEPRECATION")
        startActivityForResult(intent, REQ_PICK_FILE)
    }

    @Deprecated("Standard SAF file picker callback")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == REQ_PICK_FILE && resultCode == RESULT_OK) {
            val uri = data?.data ?: return
            val staged = stageUriToCache(uri)
            if (staged != null) {
                fileInput.setText(staged.absolutePath)
                Toast.makeText(this, "Selected: ${staged.name}", Toast.LENGTH_SHORT).show()
            }
        }
    }

    private fun stageUriToCache(uri: Uri): File? {
        var name = "upload_${System.currentTimeMillis()}.bin"
        contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { c ->
            if (c.moveToFirst()) {
                val idx = c.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                if (idx >= 0) c.getString(idx)?.takeIf { it.isNotBlank() }?.let { name = it }
            }
        }
        val safe = name.replace(Regex("[^A-Za-z0-9._-]"), "_")
        val out = File(cacheDir, safe)
        return try {
            contentResolver.openInputStream(uri)?.use { inp ->
                FileOutputStream(out).use { fos -> inp.copyTo(fos) }
            }
            out
        } catch (_: Exception) {
            null
        }
    }

    private fun triggerCta() {
        if (currentTab == 2) {
            if (serverHandle != 0L) {
                OpenFIRCore.stopServer(serverHandle)
                serverHandle = 0L
                serverInfoView.text = "Server stopped"
                serverInfoView.setTextColor(FrostColors.TEXT_SEC)
                statusPill.text = "● IDLE"
                statusPill.setTextColor(FrostColors.TEXT_SEC)
                updateCtaButton()
                return
            }
            val cfg = JSONObject().apply {
                put("listen", listenInput.text.toString().trim())
                put("dir", dirInput.text.toString().trim())
                put("secret", secretInput.text.toString().trim())
                put("overwrite", overwriteSwitch.isChecked)
                put("max_sessions", 64)
            }.toString()
            serverHandle = OpenFIRCore.startServer(cfg)
            updateCtaButton()
            return
        }

        if (activeJob != 0L) {
            OpenFIRCore.cancelTransfer(activeJob)
            activeJob = 0L
            statusPill.text = "● IDLE"
            statusPill.setTextColor(FrostColors.TEXT_SEC)
            updateCtaButton()
            return
        }

        sparkline.reset()
        progressBar.setPercent(0.0)
        merkleView.setTextColor(FrostColors.TEXT_SEC)

        if (currentTab == 3) {
            merkleView.text = "Running 4-Suite Enterprise Protocol Audit..."
            activeJob = OpenFIRCore.startSelftest()
            updateCtaButton()
            return
        }

        val modes = arrayOf("auto", "udp", "tcp")
        val cfg = JSONObject().apply {
            put("op", if (currentTab == 0) "push" else "pull")
            put("server", serverInput.text.toString().trim())
            put("secret", secretInput.text.toString().trim())
            put("file", fileInput.text.toString().trim())
            put("dir", dirInput.text.toString().trim())
            put("transport", modes[transportIdx % 3])
            put("tcp_streams", 4)
            put("max_mbps", 1000)
            put("overwrite", overwriteSwitch.isChecked)
        }.toString()
        val h = OpenFIRCore.startTransfer(cfg)
        if (h != 0L) activeJob = h
        updateCtaButton()
    }

    private fun fmtBytes(b: Long): String = when {
        b >= 1_073_741_824L -> String.format("%.2f GiB", b / 1_073_741_824.0)
        b >= 1_048_576L     -> String.format("%.2f MiB", b / 1_048_576.0)
        b >= 1024L          -> String.format("%.1f KiB", b / 1024.0)
        else                -> "$b B"
    }

    private fun onCoreEvent(handle: Long, json: String) {
        val obj = try { JSONObject(json) } catch (_: Exception) { return }
        val op = obj.optString("op", "")
        val phase = obj.optString("phase", "")
        val msg = obj.optString("message", "")

        if (op == "server") {
            if (phase == "listening") {
                serverInfoView.text = msg
                serverInfoView.setTextColor(FrostColors.MINT)
                statusPill.text = "◉ SERVER LIVE"
                statusPill.setTextColor(FrostColors.MINT)
            } else if (phase == "error") {
                serverHandle = 0L
                serverInfoView.text = "ERROR: $msg"
                serverInfoView.setTextColor(FrostColors.ROSE)
                statusPill.text = "✕ ERROR"
                statusPill.setTextColor(FrostColors.ROSE)
            }
            updateCtaButton()
            return
        }

        if (handle != 0L && activeJob != 0L && handle != activeJob) return

        val pct = obj.optDouble("percent", 0.0)
        val done = obj.optLong("bytes_done", 0L)
        val total = obj.optLong("total_bytes", 0L)
        val lane = obj.optString("active_lane", "STANDBY")
        val goodput = obj.optDouble("goodput_mbps", 0.0)
        val instant = obj.optDouble("instant_mbps", 0.0)
        val udpB = obj.optLong("wire_udp_bytes", 0L)
        val tcpB = obj.optLong("wire_tcp_bytes", 0L)
        val cas = obj.optInt("cas_blocks", 0)
        val zero = obj.optInt("zero_blocks", 0)
        val comp = obj.optInt("compressed_blocks", 0)
        val fecRec = obj.optInt("fec_recovered", 0)
        val fo = obj.optInt("udp_fallback_blocks", 0)
        val rtt = obj.optDouble("rtt_ms", 0.0)
        val merkle = obj.optString("merkle_root_hex", "")

        progressBar.setPercent(pct)
        progressText.text = String.format("%.1f%% · %s / %s · %s", pct, fmtBytes(done), fmtBytes(total), lane)
        kpiGoodput.text = String.format("%.2f MiB/s", goodput)
        kpiWire.text = "U:${fmtBytes(udpB)} T:${fmtBytes(tcpB)}"
        kpiCas.text = "CAS $cas · Z $zero · D $comp"
        kpiFec.text = String.format("Rec %d · FO %d · %.1fms", fecRec, fo, rtt)
        kpiFec.setTextColor(if (fecRec > 0 || fo > 0) FrostColors.AMBER else FrostColors.TEXT_PRI)

        if (phase == "transferring" || phase == "done") {
            sparkline.pushSample(if (instant > 0.01) instant else goodput)
        }

        when (phase) {
            "done" -> {
                activeJob = 0L
                statusPill.text = "✓ MERKLE VERIFIED"
                statusPill.setTextColor(FrostColors.MINT)
                merkleView.text = if (merkle.isNotEmpty()) "✓ MERKLE SHA-256: $merkle" else msg
                merkleView.setTextColor(FrostColors.MINT)
            }
            "error" -> {
                activeJob = 0L
                statusPill.text = "✕ ERROR"
                statusPill.setTextColor(FrostColors.ROSE)
                merkleView.text = "ERROR: $msg"
                merkleView.setTextColor(FrostColors.ROSE)
            }
            "transferring", "handshake" -> {
                statusPill.text = "◈ STREAM ACTIVE"
                statusPill.setTextColor(FrostColors.CYAN)
                if (msg.isNotEmpty()) {
                    merkleView.text = msg
                    merkleView.setTextColor(FrostColors.TEXT_SEC)
                }
            }
        }
        updateCtaButton()
    }

    companion object {
        private const val REQ_PICK_FILE = 4401
    }
}
