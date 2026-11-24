// SPDX-License-Identifier: Apache-2.0
package io.openfir.app

import android.content.Context
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.LinearGradient
import android.graphics.Paint
import android.graphics.Path
import android.graphics.RadialGradient
import android.graphics.RectF
import android.graphics.RenderEffect
import android.graphics.Shader
import android.os.Build
import android.os.SystemClock
import android.util.TypedValue
import android.view.View
import android.widget.LinearLayout
import kotlin.math.cos
import kotlin.math.max
import kotlin.math.min
import kotlin.math.sin

object FrostColors {
    val BG_VOID      = Color.parseColor("#070913")
    val CYAN         = Color.parseColor("#00F0FF")
    val VIOLET       = Color.parseColor("#8B5CF6")
    val ACCENT_END   = Color.parseColor("#7C3AED")
    val MAGENTA      = Color.parseColor("#EC4899")
    val GLASS_SURF   = Color.argb(164, 17, 23, 42)
    val GLASS_ELEV   = Color.argb(196, 26, 35, 62)
    val GLASS_INPUT  = Color.argb(206, 10, 15, 29)
    val MINT         = Color.parseColor("#10F9A0")
    val AMBER        = Color.parseColor("#FFB020")
    val ROSE         = Color.parseColor("#FF4D8D")
    val TEXT_PRI     = Color.parseColor("#F8FAFC")
    val TEXT_SEC     = Color.parseColor("#94A3B8")
    val TEXT_MUTED   = Color.parseColor("#64748B")
    val TEXT_MONO    = Color.parseColor("#7DD3FC")
}

fun Context.dp(v: Float): Float =
    TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, v, resources.displayMetrics)

fun Context.dpInt(v: Int): Int = dp(v.toFloat()).toInt()

/**
 * Hardware-accelerated animated Web3 Obsidian Aurora plasma backdrop.
 * Uses native Android 12+ RenderEffect.createBlurEffect for authentic optical frosting.
 */
class AuroraBackdropView(context: Context) : View(context) {
    private val paint = Paint(Paint.ANTI_ALIAS_FLAG)
    private val t0 = SystemClock.uptimeMillis()

    init {
        if (Build.VERSION.SDK_INT >= 31) {
            setRenderEffect(RenderEffect.createBlurEffect(28f, 28f, Shader.TileMode.CLAMP))
        }
    }

    override fun onDraw(canvas: Canvas) {
        val w = width.toFloat().coerceAtLeast(1f)
        val h = height.toFloat().coerceAtLeast(1f)
        val t = (SystemClock.uptimeMillis() - t0) / 1000.0

        canvas.drawColor(FrostColors.BG_VOID)

        drawOrb(
            canvas,
            (w * (0.20 + 0.08 * sin(t * 0.45))).toFloat(),
            (h * (0.18 + 0.06 * cos(t * 0.37))).toFloat(),
            max(w, h) * 0.55f,
            Color.argb(95, 0, 240, 255)
        )
        drawOrb(
            canvas,
            (w * (0.82 + 0.08 * cos(t * 0.32))).toFloat(),
            (h * (0.78 + 0.07 * sin(t * 0.41))).toFloat(),
            max(w, h) * 0.60f,
            Color.argb(105, 139, 92, 246)
        )
        drawOrb(
            canvas,
            (w * (0.58 + 0.09 * sin(t * 0.27 + 1.2))).toFloat(),
            (h * (0.34 + 0.07 * cos(t * 0.30))).toFloat(),
            max(w, h) * 0.42f,
            Color.argb(54, 236, 72, 153)
        )
        postInvalidateDelayed(33L)
    }

    private fun drawOrb(canvas: Canvas, cx: Float, cy: Float, radius: Float, centerCol: Int) {
        paint.shader = RadialGradient(
            cx, cy, radius,
            intArrayOf(centerCol, Color.TRANSPARENT),
            floatArrayOf(0f, 1f),
            Shader.TileMode.CLAMP
        )
        canvas.drawCircle(cx, cy, radius, paint)
    }
}

/**
 * Custom Frosted Glass Card with top specular sheen & 1.3dp Cyan-to-Violet neon rim.
 */
class FrostCardLayout(
    context: Context,
    private val elevated: Boolean = false,
    private val activeRim: Boolean = false,
    private val radiusDp: Float = 18f
) : LinearLayout(context) {
    private val fillPaint = Paint(Paint.ANTI_ALIAS_FLAG)
    private val sheenPaint = Paint(Paint.ANTI_ALIAS_FLAG)
    private val rimPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply { style = Paint.Style.STROKE }
    private val rect = RectF()
    private val sheenRect = RectF()

    init {
        orientation = VERTICAL
        setWillNotDraw(false)
    }

    override fun onDraw(canvas: Canvas) {
        val r = context.dp(radiusDp)
        val inset = context.dp(0.8f)
        rect.set(inset, inset, width - inset, height - inset)

        fillPaint.color = if (elevated) FrostColors.GLASS_ELEV else FrostColors.GLASS_SURF
        canvas.drawRoundRect(rect, r, r, fillPaint)

        sheenRect.set(rect.left, rect.top, rect.right, min(rect.bottom, rect.top + context.dp(42f)))
        sheenPaint.shader = LinearGradient(
            0f, sheenRect.top, 0f, sheenRect.bottom,
            Color.argb(24, 255, 255, 255), Color.TRANSPARENT, Shader.TileMode.CLAMP
        )
        canvas.drawRoundRect(sheenRect, r, r, sheenPaint)

        rimPaint.strokeWidth = context.dp(if (activeRim) 1.3f else 1.0f)
        rimPaint.shader = LinearGradient(
            rect.left, rect.top, rect.right, rect.bottom,
            if (activeRim) Color.argb(195, 0, 240, 255) else Color.argb(58, 190, 238, 255),
            if (activeRim) Color.argb(175, 139, 92, 246) else Color.argb(40, 139, 92, 246),
            Shader.TileMode.CLAMP
        )
        canvas.drawRoundRect(rect, r, r, rimPaint)
        super.onDraw(canvas)
    }
}

class NeonProgressBar(context: Context) : View(context) {
    private var percent: Float = 0f
    private val trackPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply { color = FrostColors.GLASS_INPUT }
    private val fillPaint = Paint(Paint.ANTI_ALIAS_FLAG)
    private val rect = RectF()
    private val fillRect = RectF()

    fun setPercent(p: Double) {
        percent = p.toFloat().coerceIn(0f, 100f)
        invalidate()
    }

    override fun onDraw(canvas: Canvas) {
        val r = height * 0.5f
        rect.set(0f, 0f, width.toFloat(), height.toFloat())
        canvas.drawRoundRect(rect, r, r, trackPaint)
        val fw = (width * percent / 100f).coerceAtLeast(if (percent > 0f) height.toFloat() else 0f)
        if (fw > 0f) {
            fillRect.set(0f, 0f, fw, height.toFloat())
            fillPaint.shader = LinearGradient(
                0f, 0f, width.toFloat().coerceAtLeast(1f), 0f,
                FrostColors.CYAN, FrostColors.ACCENT_END, Shader.TileMode.CLAMP
            )
            canvas.drawRoundRect(fillRect, r, r, fillPaint)
        }
    }
}

class NeonSparklineView(context: Context) : View(context) {
    private val samples = DoubleArray(60)
    private val strokePaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        strokeCap = Paint.Cap.ROUND
        strokeJoin = Paint.Join.ROUND
    }
    private val areaPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply { style = Paint.Style.FILL }
    private val strokePath = Path()
    private val areaPath = Path()

    fun pushSample(mbps: Double) {
        System.arraycopy(samples, 1, samples, 0, samples.size - 1)
        samples[samples.size - 1] = max(0.0, mbps)
        invalidate()
    }

    fun reset() {
        samples.fill(0.0)
        invalidate()
    }

    override fun onDraw(canvas: Canvas) {
        val w = width.toFloat()
        val h = height.toFloat()
        if (w < 10f || h < 10f) return

        var maxV = 1.0
        for (v in samples) if (v > maxV) maxV = v

        strokePath.reset()
        areaPath.reset()
        areaPath.moveTo(0f, h)

        for (i in samples.indices) {
            val x = w * i / (samples.size - 1)
            val norm = (samples[i] / maxV).coerceIn(0.0, 1.0).toFloat()
            val y = h - context.dp(4f) - norm * (h - context.dp(10f))
            if (i == 0) {
                strokePath.moveTo(x, y)
                areaPath.lineTo(x, y)
            } else {
                strokePath.lineTo(x, y)
                areaPath.lineTo(x, y)
            }
        }
        areaPath.lineTo(w, h)
        areaPath.close()

        areaPaint.shader = LinearGradient(
            0f, 0f, 0f, h,
            Color.argb(85, 0, 240, 255), Color.argb(5, 139, 92, 246), Shader.TileMode.CLAMP
        )
        canvas.drawPath(areaPath, areaPaint)

        strokePaint.strokeWidth = context.dp(2.2f)
        strokePaint.shader = LinearGradient(
            0f, 0f, w, 0f, FrostColors.CYAN, FrostColors.VIOLET, Shader.TileMode.CLAMP
        )
        canvas.drawPath(strokePath, strokePaint)
    }
}
