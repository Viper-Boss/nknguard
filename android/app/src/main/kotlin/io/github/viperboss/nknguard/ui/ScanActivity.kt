package io.github.viperboss.nknguard.ui

import android.app.Activity
import android.content.Intent
import android.graphics.Color
import android.graphics.ImageFormat
import android.graphics.BitmapFactory
import android.graphics.Matrix
import android.graphics.Rect
import android.graphics.SurfaceTexture
import android.hardware.camera2.CameraCaptureSession
import android.hardware.camera2.CameraCharacteristics
import android.hardware.camera2.CameraDevice
import android.hardware.camera2.CameraManager
import android.hardware.camera2.CaptureRequest
import android.media.ImageReader
import android.os.Bundle
import android.os.Handler
import android.os.HandlerThread
import android.util.Size
import android.view.Gravity
import android.view.Surface
import android.view.TextureView
import android.widget.FrameLayout
import android.widget.TextView
import android.widget.Button
import android.widget.LinearLayout
import com.google.zxing.PlanarYUVLuminanceSource
import com.google.zxing.RGBLuminanceSource
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Scans the pairing QR code with Camera2 and ZXing. Only the luminance plane
 * of each frame is read; nothing is stored. The result must start with
 * nknguard:// — anything else keeps the scanner running.
 */
class ScanActivity : Activity() {
    private lateinit var preview: TextureView
    private lateinit var hint: TextView
    private var thread: HandlerThread? = null
    private var handler: Handler? = null
    private var camera: CameraDevice? = null
    private var session: CameraCaptureSession? = null
    private var reader: ImageReader? = null
    private val done = AtomicBoolean(false)
    @Volatile private var generation = 0
    private var lastFrameAt = 0L
    private var previewSurface: Surface? = null
    private var request: CaptureRequest.Builder? = null
    private var activeArray: Rect? = null
    private var maxZoom = 1f
    private var zoom = 1f
    private var torch = false
    private var flashAvailable = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        preview = TextureView(this)
        hint = TextView(this).apply {
            text = "将 NAS 面板上的配对二维码放入画面"
            setTextColor(Color.WHITE)
            setBackgroundColor(0x99000000.toInt())
            textSize = 16f
            gravity = Gravity.CENTER
            setPadding(24, 32, 24, 32)
        }
        setContentView(FrameLayout(this).apply {
            setBackgroundColor(Color.BLACK)
            addView(preview, FrameLayout.LayoutParams(FrameLayout.LayoutParams.MATCH_PARENT, FrameLayout.LayoutParams.MATCH_PARENT))
            addView(LinearLayout(this@ScanActivity).apply {
                orientation = LinearLayout.VERTICAL
                setBackgroundColor(0x99000000.toInt())
                addView(hint)
                addView(LinearLayout(this@ScanActivity).apply {
                    gravity = Gravity.CENTER
                    addView(Button(this@ScanActivity).apply { text = "放大 1×"; setOnClickListener {
                        zoom = if (zoom >= minOf(2f, maxZoom)) 1f else minOf(2f, maxZoom)
                        text = "放大 ${zoom}×"
                        handler?.post { updateRequest() }
                    } })
                    addView(Button(this@ScanActivity).apply { text = "补光"; setOnClickListener {
                        if (!flashAvailable) { fail("此相机不支持补光"); return@setOnClickListener }
                        torch = !torch
                        handler?.post { updateRequest() }
                    } })
                    addView(Button(this@ScanActivity).apply { text = "从相册识别"; setOnClickListener {
                        @Suppress("DEPRECATION")
                        startActivityForResult(Intent(Intent.ACTION_OPEN_DOCUMENT).apply { type = "image/*"; addCategory(Intent.CATEGORY_OPENABLE) }, 1)
                    } })
                })
            }, FrameLayout.LayoutParams(FrameLayout.LayoutParams.MATCH_PARENT, FrameLayout.LayoutParams.WRAP_CONTENT, Gravity.BOTTOM))
        })
    }

    override fun onResume() {
        super.onResume()
        generation++
        thread = HandlerThread("nkg-scan").also { it.start() }
        handler = Handler(thread!!.looper)
        if (preview.isAvailable) {
            open()
        } else {
            preview.surfaceTextureListener = object : TextureView.SurfaceTextureListener {
                override fun onSurfaceTextureAvailable(texture: SurfaceTexture, width: Int, height: Int) = open()
                override fun onSurfaceTextureSizeChanged(texture: SurfaceTexture, width: Int, height: Int) {}
                override fun onSurfaceTextureDestroyed(texture: SurfaceTexture) = true
                override fun onSurfaceTextureUpdated(texture: SurfaceTexture) {}
            }
        }
    }

    override fun onPause() {
        generation++
        preview.surfaceTextureListener = null
        close()
        thread?.quitSafely()
        thread = null
        handler = null
        super.onPause()
    }

    private fun fail(message: String) {
        runOnUiThread { hint.text = message }
    }

    private fun open() {
        if (handler == null || isFinishing || done.get()) return
        val openedGeneration = generation
        val manager = getSystemService(CameraManager::class.java) ?: return fail("没有可用的相机")
        try {
            val id = manager.cameraIdList.firstOrNull {
                manager.getCameraCharacteristics(it).get(CameraCharacteristics.LENS_FACING) == CameraCharacteristics.LENS_FACING_BACK
            } ?: manager.cameraIdList.firstOrNull() ?: return fail("没有可用的相机")
            val characteristics = manager.getCameraCharacteristics(id)
            activeArray = characteristics.get(CameraCharacteristics.SENSOR_INFO_ACTIVE_ARRAY_SIZE)
            maxZoom = characteristics.get(CameraCharacteristics.SCALER_AVAILABLE_MAX_DIGITAL_ZOOM) ?: 1f
            flashAvailable = characteristics.get(CameraCharacteristics.FLASH_INFO_AVAILABLE) == true
            val map = characteristics.get(CameraCharacteristics.SCALER_STREAM_CONFIGURATION_MAP) ?: return fail("相机不可用")
            val previewSizes = (map.getOutputSizes(SurfaceTexture::class.java) ?: emptyArray()).toSet()
            val sharedSizes = (map.getOutputSizes(ImageFormat.YUV_420_888) ?: emptyArray()).filter { it in previewSizes }
            if (sharedSizes.isEmpty()) return fail("此相机不支持扫码预览，请从相册识别")
            val size = chooseSize(sharedSizes.toTypedArray())
            val sensor = characteristics.get(CameraCharacteristics.SENSOR_ORIENTATION) ?: 90
            runOnUiThread { fitPreview(size, sensor) }
            reader = ImageReader.newInstance(size.width, size.height, ImageFormat.YUV_420_888, 2).apply {
                setOnImageAvailableListener({ source -> decode(source) }, handler)
            }
            manager.openCamera(id, object : CameraDevice.StateCallback() {
                override fun onOpened(device: CameraDevice) {
                    if (openedGeneration != generation) { device.close(); return }
                    camera = device
                    startSession(device, size, characteristics, openedGeneration)
                }
                override fun onDisconnected(device: CameraDevice) = device.close()
                override fun onError(device: CameraDevice, error: Int) {
                    device.close()
                    fail("相机打开失败（$error）；可以返回改用“粘贴配对内容”")
                }
            }, handler)
        } catch (error: SecurityException) {
            fail("没有相机权限")
        } catch (error: Exception) {
            fail("相机不可用：${error.message}")
        }
    }

    private fun chooseSize(sizes: Array<Size>): Size {
        // About 1280x720 decodes a dashboard QR code quickly without
        // overloading slower phones.
        return sizes.filter { it.width <= 1920 && it.height <= 1080 }
            .minByOrNull { Math.abs(it.width * it.height - 1280 * 720) }
            ?: sizes.firstOrNull() ?: Size(1280, 720)
    }

    private fun fitPreview(size: Size, sensorDegrees: Int) {
        val texture = preview.surfaceTexture ?: return
        texture.setDefaultBufferSize(size.width, size.height)
        val viewWidth = preview.width.toFloat()
        val viewHeight = preview.height.toFloat()
        if (viewWidth == 0f || viewHeight == 0f) return
        // The activity is portrait; a sensor mounted at 90 or 270 degrees
        // delivers landscape buffers. Scale to fill without distortion.
        @Suppress("DEPRECATION")
        val displayDegrees = when (windowManager.defaultDisplay.rotation) { Surface.ROTATION_90 -> 90; Surface.ROTATION_180 -> 180; Surface.ROTATION_270 -> 270; else -> 0 }
        val rotation = (sensorDegrees + displayDegrees) % 360
        val rotated = rotation % 180 != 0
        val bufferWidth = if (rotated) size.height.toFloat() else size.width.toFloat()
        val bufferHeight = if (rotated) size.width.toFloat() else size.height.toFloat()
        val scale = maxOf(viewWidth / bufferWidth, viewHeight / bufferHeight)
        val matrix = Matrix()
        val cx = viewWidth / 2f
        val cy = viewHeight / 2f
        // TextureView already applies sensor orientation. Undo its stretch,
        // then account only for display rotation and scale uniformly.
        matrix.setScale(bufferWidth / viewWidth, bufferHeight / viewHeight, cx, cy)
        matrix.postRotate(-displayDegrees.toFloat(), cx, cy)
        matrix.postScale(scale, scale, cx, cy)
        preview.setTransform(matrix)
    }

    private fun startSession(device: CameraDevice, size: Size, characteristics: CameraCharacteristics, openedGeneration: Int) {
        val texture = preview.surfaceTexture ?: return
        texture.setDefaultBufferSize(size.width, size.height)
        val surface = Surface(texture)
        previewSurface = surface
        val readerSurface = reader?.surface ?: return
        @Suppress("DEPRECATION")
        device.createCaptureSession(listOf(surface, readerSurface), object : CameraCaptureSession.StateCallback() {
            override fun onConfigured(configured: CameraCaptureSession) {
                if (openedGeneration != generation) { configured.close(); return }
                session = configured
                request = device.createCaptureRequest(CameraDevice.TEMPLATE_PREVIEW).apply {
                    addTarget(surface)
                    addTarget(readerSurface)
                    val modes = characteristics.get(CameraCharacteristics.CONTROL_AF_AVAILABLE_MODES) ?: intArrayOf()
                    val mode = when {
                        modes.contains(CaptureRequest.CONTROL_AF_MODE_CONTINUOUS_PICTURE) -> CaptureRequest.CONTROL_AF_MODE_CONTINUOUS_PICTURE
                        modes.contains(CaptureRequest.CONTROL_AF_MODE_AUTO) -> CaptureRequest.CONTROL_AF_MODE_AUTO
                        else -> CaptureRequest.CONTROL_AF_MODE_OFF
                    }
                    set(CaptureRequest.CONTROL_AF_MODE, mode)
                }
                updateRequest()
                if (request?.get(CaptureRequest.CONTROL_AF_MODE) == CaptureRequest.CONTROL_AF_MODE_AUTO) {
                    runCatching {
                        request?.set(CaptureRequest.CONTROL_AF_TRIGGER, CaptureRequest.CONTROL_AF_TRIGGER_START)
                        request?.let { configured.capture(it.build(), null, handler) }
                    }
                    request?.set(CaptureRequest.CONTROL_AF_TRIGGER, CaptureRequest.CONTROL_AF_TRIGGER_IDLE)
                }
            }
            override fun onConfigureFailed(failed: CameraCaptureSession) = fail("相机预览启动失败")
        }, handler)
    }

    private fun decode(source: ImageReader) {
        val image = runCatching { source.acquireLatestImage() }.getOrNull() ?: return
        try {
            if (done.get()) return
            val now = android.os.SystemClock.elapsedRealtime()
            if (now - lastFrameAt < 250) return
            lastFrameAt = now
            val plane = image.planes[0]
            val crop = image.cropRect
            val width = crop.width()
            val height = crop.height()
            val luminance = PairQrDecoder.luminance(plane.buffer, width, height, plane.rowStride, plane.pixelStride, crop.left, crop.top)
            val text = PairQrDecoder.decode(PlanarYUVLuminanceSource(luminance, width, height, 0, 0, width, height, false))
            if (text == null) return
            accept(text)
        } catch (_: Exception) {
        } finally {
            image.close()
        }
    }

    private fun close() {
        runCatching { session?.close() }
        runCatching { camera?.close() }
        runCatching { reader?.close() }
        runCatching { previewSurface?.release() }
        previewSurface = null
        request = null
        session = null
        camera = null
        reader = null
    }

    companion object {
        const val EXTRA_TEXT = "text"
    }

    private fun updateRequest() {
        val builder = request ?: return
        val capture = session ?: return
        activeArray?.let { bounds ->
            val halfWidth = (bounds.width() / (2f * zoom)).toInt()
            val halfHeight = (bounds.height() / (2f * zoom)).toInt()
            builder.set(CaptureRequest.SCALER_CROP_REGION, Rect(bounds.centerX() - halfWidth, bounds.centerY() - halfHeight, bounds.centerX() + halfWidth, bounds.centerY() + halfHeight))
        }
        if (flashAvailable) builder.set(CaptureRequest.FLASH_MODE, if (torch) CaptureRequest.FLASH_MODE_TORCH else CaptureRequest.FLASH_MODE_OFF)
        runCatching { capture.setRepeatingRequest(builder.build(), null, handler) }.onFailure { fail("相机配置失败，请尝试从相册识别") }
    }

    private fun accept(text: String) {
        if (isFinishing || isDestroyed) return
        if (!text.startsWith("nknguard://pair/v1?")) { fail("这不是 NKNGuard 配对二维码"); return }
        if (done.compareAndSet(false, true)) runOnUiThread {
            setResult(RESULT_OK, Intent().putExtra(EXTRA_TEXT, text))
            finish()
        }
    }

    @Deprecated("Activity result API without AndroidX")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode != 1 || resultCode != RESULT_OK) return
        val uri = data?.data ?: return
        Thread {
            try {
                val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
                contentResolver.openInputStream(uri)?.use { BitmapFactory.decodeStream(it, null, bounds) }
                require(bounds.outWidth > 0 && bounds.outHeight > 0)
                val options = BitmapFactory.Options().apply {
                    inSampleSize = 1
                    while (bounds.outWidth / inSampleSize > 2048 || bounds.outHeight / inSampleSize > 2048) inSampleSize *= 2
                }
                val bitmap = contentResolver.openInputStream(uri)?.use { BitmapFactory.decodeStream(it, null, options) } ?: error("图片无法读取")
                try {
                    val pixels = IntArray(bitmap.width * bitmap.height)
                    bitmap.getPixels(pixels, 0, bitmap.width, 0, 0, bitmap.width, bitmap.height)
                    val text = PairQrDecoder.decode(RGBLuminanceSource(bitmap.width, bitmap.height, pixels))
                    if (text == null) fail("图片中未找到二维码；请保存完整二维码（包含白边）再试") else accept(text)
                } finally { bitmap.recycle() }
            } catch (_: Exception) { fail("无法识别图片，请使用完整二维码或粘贴配对链接") }
        }.start()
    }
}
