package io.github.viperboss.nknguard.ui

import android.animation.ValueAnimator
import android.content.Context
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.LinearGradient
import android.graphics.Paint
import android.graphics.Path
import android.graphics.RectF
import android.graphics.Shader
import android.view.View
import android.view.animation.LinearInterpolator

/** A visual guide; decoding still uses the full camera frame. */
internal class ScanOverlayView(context: Context) : View(context) {
    private val density = resources.displayMetrics.density
    private val paint = Paint(Paint.ANTI_ALIAS_FLAG)
    private val frame = RectF()
    private val accent = Color.rgb(87, 224, 177)
    private var progress = 0f
    private var success = false
    private var requested = false
    private var animator: ValueAnimator? = null
    var topReserved = 72f * density
        set(value) { field = value; invalidate() }
    var bottomReserved = 160f * density
        set(value) { field = value; invalidate() }

    fun startScanning() { requested = true; updateAnimation() }
    fun stopScanning() { requested = false; animator?.cancel(); animator = null }
    fun showSuccess() { success = true; stopScanning(); invalidate() }

    private fun updateAnimation() {
        animator?.cancel()
        animator = null
        if (!requested || success || !isAttachedToWindow || !isShown || !ValueAnimator.areAnimatorsEnabled()) {
            invalidate()
            return
        }
        animator = ValueAnimator.ofFloat(0f, 1f).apply {
            duration = 2200L
            repeatCount = ValueAnimator.INFINITE
            interpolator = LinearInterpolator()
            addUpdateListener { progress = it.animatedValue as Float; invalidate() }
            start()
        }
    }

    override fun onAttachedToWindow() { super.onAttachedToWindow(); updateAnimation() }
    override fun onDetachedFromWindow() { animator?.cancel(); animator = null; super.onDetachedFromWindow() }
    override fun onWindowVisibilityChanged(visibility: Int) { super.onWindowVisibilityChanged(visibility); updateAnimation() }

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)
        val available = (height - topReserved - bottomReserved).coerceAtLeast(0f)
        val side = minOf(width * 0.78f, 320f * density, available * 0.88f)
        if (side <= 0f) return
        val left = (width - side) / 2f
        val top = topReserved + (available - side) / 2f
        frame.set(left, top, left + side, top + side)

        paint.shader = null
        paint.style = Paint.Style.FILL
        paint.color = 0x99000000.toInt()
        canvas.drawRect(0f, 0f, width.toFloat(), frame.top, paint)
        canvas.drawRect(0f, frame.bottom, width.toFloat(), height.toFloat(), paint)
        canvas.drawRect(0f, frame.top, frame.left, frame.bottom, paint)
        canvas.drawRect(frame.right, frame.top, width.toFloat(), frame.bottom, paint)

        paint.style = Paint.Style.STROKE
        paint.strokeWidth = density
        paint.color = 0x66FFFFFF
        canvas.drawRect(frame, paint)
        paint.color = accent
        paint.strokeWidth = 3f * density
        paint.strokeCap = Paint.Cap.SQUARE
        val corner = minOf(24f * density, side / 6f)
        val corners = Path().apply {
            moveTo(frame.left, frame.top + corner); lineTo(frame.left, frame.top); lineTo(frame.left + corner, frame.top)
            moveTo(frame.right - corner, frame.top); lineTo(frame.right, frame.top); lineTo(frame.right, frame.top + corner)
            moveTo(frame.right, frame.bottom - corner); lineTo(frame.right, frame.bottom); lineTo(frame.right - corner, frame.bottom)
            moveTo(frame.left + corner, frame.bottom); lineTo(frame.left, frame.bottom); lineTo(frame.left, frame.bottom - corner)
        }
        canvas.drawPath(corners, paint)

        if (success) {
            paint.strokeWidth = 5f * density
            paint.strokeCap = Paint.Cap.ROUND
            paint.strokeJoin = Paint.Join.ROUND
            canvas.drawPath(Path().apply {
                moveTo(frame.centerX() - side * 0.18f, frame.centerY())
                lineTo(frame.centerX() - side * 0.04f, frame.centerY() + side * 0.13f)
                lineTo(frame.centerX() + side * 0.21f, frame.centerY() - side * 0.15f)
            }, paint)
            return
        }
        val y = frame.top + side * (0.04f + progress * 0.92f)
        val trailTop = maxOf(frame.top, y - 48f * density)
        paint.style = Paint.Style.FILL
        paint.shader = LinearGradient(0f, trailTop, 0f, y, Color.TRANSPARENT, 0x4457E0B1, Shader.TileMode.CLAMP)
        canvas.drawRect(frame.left + density, trailTop, frame.right - density, y, paint)
        paint.shader = null
        paint.color = accent
        paint.strokeWidth = 2f * density
        canvas.drawLine(frame.left + 6f * density, y, frame.right - 6f * density, y, paint)
    }
}
