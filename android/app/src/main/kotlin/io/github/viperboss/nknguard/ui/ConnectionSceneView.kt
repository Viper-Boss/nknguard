package io.github.viperboss.nknguard.ui

import android.content.Context
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.graphics.RadialGradient
import android.graphics.Shader
import android.provider.Settings
import android.view.View
import kotlin.math.sin

/** Lightweight native animation; no bitmaps, network requests or disk writes. */
class ConnectionSceneView(context: Context) : View(context) {
    var online = false
    var pending = false
    var relay = false
    private val paint = Paint(Paint.ANTI_ALIAS_FLAG)
    private val scale = resources.displayMetrics.density
    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)
        val w = width.toFloat()
        val y = height * .46f
        val left = w * .2f
        val right = w * .8f
        val radius = 26 * scale
        val color = Color.parseColor(if (online) "#4DE2BE" else if (pending) "#F3BD68" else "#7085A4")
        paint.shader = RadialGradient(w / 2, y, w * .48f, intArrayOf(Color.argb(38, 77, 226, 190), Color.TRANSPARENT), null, Shader.TileMode.CLAMP)
        canvas.drawCircle(w / 2, y, w * .48f, paint)
        paint.shader = null
        paint.color = Color.parseColor("#294359")
        paint.strokeWidth = 2 * scale
        canvas.drawLine(left + radius, y, right - radius, y, paint)
        val animate = (online || pending) && Settings.Global.getFloat(context.contentResolver, Settings.Global.ANIMATOR_DURATION_SCALE, 1f) > 0
        if (animate) {
            val phase = (android.os.SystemClock.uptimeMillis() % 2400) / 2400f
            paint.color = color
            for (i in 0..2) {
                val progress = (phase + i / 3f) % 1f
                canvas.drawCircle(left + radius + (right - left - 2 * radius) * progress, y, 3 * scale, paint)
            }
        }
        for (x in listOf(left, right)) {
            paint.color = Color.parseColor("#162E42")
            paint.style = Paint.Style.FILL
            canvas.drawCircle(x, y, radius, paint)
            paint.color = color
            paint.style = Paint.Style.STROKE
            paint.strokeWidth = 1.5f * scale
            canvas.drawCircle(x, y, radius, paint)
            if (online) {
                paint.alpha = 45
                canvas.drawCircle(x, y, radius + (5 + 2 * sin(android.os.SystemClock.uptimeMillis() / 600.0)).toFloat() * scale, paint)
                paint.alpha = 255
            }
            val halfW = if (x == left) 7 * scale else 12 * scale
            canvas.drawRoundRect(x - halfW, y - 12 * scale, x + halfW, y + 12 * scale, 3 * scale, 3 * scale, paint)
            canvas.drawLine(x - halfW + 3 * scale, y + 6 * scale, x + halfW - 3 * scale, y + 6 * scale, paint)
            paint.style = Paint.Style.FILL
        }
        paint.color = Color.parseColor("#A9C0D2")
        paint.textSize = 12 * scale
        paint.textAlign = Paint.Align.CENTER
        canvas.drawText("这台手机", left, y + radius + 24 * scale, paint)
        canvas.drawText("我的 NAS", right, y + radius + 24 * scale, paint)
        paint.textSize = 10 * scale
        paint.color = color
        canvas.drawText(if (online) if (relay) "NKN 加密中继" else "WireGuard 安全直连" else if (pending) "正在建立安全通道" else "随时连接你的文件", w / 2, y - 14 * scale, paint)
        contentDescription = if (online) if (relay) "NKN 中继已连接" else "直连已连接" else "连接未建立"
        if (animate && windowVisibility == VISIBLE) postInvalidateDelayed(33)
    }
}
