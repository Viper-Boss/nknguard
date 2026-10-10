package io.github.viperboss.nknguard.ui

import android.animation.ValueAnimator
import android.content.Context
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.graphics.Path
import android.graphics.RadialGradient
import android.graphics.RectF
import android.graphics.Shader
import android.graphics.Typeface
import android.provider.Settings
import android.view.View
import android.view.animation.DecelerateInterpolator
import kotlin.math.cos
import kotlin.math.sin

/** Qualitative mapping observation, not a NAT1-4 or reachability measurement. */
class NatGaugeView(context: Context) : View(context) {
    private val paint = Paint(Paint.ANTI_ALIAS_FLAG)
    private val colors = listOf("#5BDDAA", "#77D4BC", "#EFC470", "#ED8285").map(Color::parseColor)
    private var angle = 0f
    private var needleColor = Color.parseColor("#7E91A9")
    private var label = "尚未测定"
    private var detail = "连接后自动探测"
    private var state = "unknown"
    private var animator: ValueAnimator? = null

    fun update(behaviour: String) {
        val key = behaviour.takeIf { it in setOf("open", "endpoint-independent", "address-dependent") } ?: "unknown"
        if (key == state) return
        state = key
        val target: Float
        when (key) {
            "open" -> { target = 76f; label = "公网 · 无地址转换"; detail = "防火墙仍可能限制直连"; needleColor = colors[0] }
            "endpoint-independent" -> { target = 34f; label = "映射稳定"; detail = "锥型具体类别尚未测定"; needleColor = colors[1] }
            "address-dependent" -> { target = -72f; label = "映射随目标变化"; detail = "对称型映射特征 · 直连较难"; needleColor = colors[3] }
            else -> { target = 0f; label = "尚未测定"; detail = "连接后自动探测"; needleColor = Color.parseColor("#7E91A9") }
        }
        contentDescription = "NAT 映射条件：$label。$detail。入站过滤尚未测量。"
        animator?.cancel()
        if (isShown && Settings.Global.getFloat(context.contentResolver, Settings.Global.ANIMATOR_DURATION_SCALE, 1f) > 0) {
            animator = ValueAnimator.ofFloat(angle, target).apply {
                duration = 900
                interpolator = DecelerateInterpolator(2f)
                addUpdateListener { angle = it.animatedValue as Float; invalidate() }
                start()
            }
        } else { angle = target; invalidate() }
    }

    override fun onDetachedFromWindow() { animator?.cancel(); super.onDetachedFromWindow() }
    override fun onMeasure(widthMeasureSpec: Int, heightMeasureSpec: Int) {
        val w = MeasureSpec.getSize(widthMeasureSpec)
        setMeasuredDimension(w, resolveSize((w * .75f).toInt(), heightMeasureSpec))
    }
    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)
        // Use a shared 320-unit design; all typography scales with the device font preference.
        val scale = width / 320f
        if (scale <= 0) return
        val font = resources.configuration.fontScale.coerceAtMost(1.5f)
        canvas.save()
        canvas.scale(scale, scale)
        paint.shader = RadialGradient(160f, 145f, 120f, intArrayOf(Color.argb(18, 125, 220, 197), Color.TRANSPARENT), null, Shader.TileMode.CLAMP)
        canvas.drawCircle(160f, 145f, 120f, paint)
        paint.shader = null
        paint.style = Paint.Style.STROKE
        paint.strokeWidth = 25f
        paint.color = Color.parseColor("#203144")
        canvas.drawArc(RectF(48f, 33f, 272f, 257f), 180f, 180f, false, paint)
        paint.strokeWidth = 13f
        paint.strokeCap = Paint.Cap.ROUND
        colors.forEachIndexed { i, color ->
            paint.color = color
            canvas.drawArc(RectF(48f, 33f, 272f, 257f), 183f + (3 - i) * 45, 39f, false, paint)
        }
        paint.strokeCap = Paint.Cap.BUTT
        paint.strokeWidth = 1f
        paint.color = Color.parseColor("#456078")
        for (i in 0..24) {
            val a = Math.PI + i * Math.PI / 24
            val inner = if (i % 3 == 0) 124f else 129f
            canvas.drawLine(160 + inner * cos(a).toFloat(), 145 + inner * sin(a).toFloat(), 160 + 133 * cos(a).toFloat(), 145 + 133 * sin(a).toFloat(), paint)
        }
        paint.color = Color.parseColor("#273A4D")
        canvas.drawArc(RectF(70f, 55f, 250f, 235f), 180f, 180f, false, paint)
        paint.style = Paint.Style.FILL
        canvas.save()
        canvas.rotate(angle, 160f, 145f)
        paint.color = needleColor
        canvas.drawPath(Path().apply { moveTo(160f, 63f); lineTo(156f, 139f); lineTo(160f, 151f); lineTo(164f, 139f); close() }, paint)
        paint.color = Color.parseColor("#122437")
        canvas.drawCircle(160f, 145f, 10f, paint)
        paint.color = needleColor
        canvas.drawCircle(160f, 145f, 4f, paint)
        canvas.restore()
        paint.typeface = Typeface.DEFAULT
        paint.textSize = 11f * font
        paint.color = Color.parseColor("#839AB3")
        paint.textAlign = Paint.Align.LEFT
        canvas.drawText("较受限", 30f, 173f, paint)
        paint.textAlign = Paint.Align.RIGHT
        canvas.drawText("较易直连", 290f, 173f, paint)
        paint.textAlign = Paint.Align.CENTER
        paint.typeface = Typeface.DEFAULT_BOLD
        paint.color = needleColor
        paint.textSize = 20f * font
        canvas.drawText(label, 160f, 202f, paint)
        paint.typeface = Typeface.DEFAULT
        paint.color = Color.parseColor("#839AB3")
        paint.textSize = 11f * font
        canvas.drawText(detail, 160f, 224f, paint)
        canvas.restore()
    }
}
