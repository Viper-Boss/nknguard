package io.github.viperboss.nknguard.ui

import android.app.Activity
import android.content.Intent
import android.graphics.Color
import android.graphics.ImageFormat
import android.graphics.Matrix
import android.graphics.RectF
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
import com.google.zxing.BarcodeFormat
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.MultiFormatReader
import com.google.zxing.NotFoundException
import com.google.zxing.PlanarYUVLuminanceSource
import com.google.zxing.common.HybridBinarizer
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
    private val decoder = MultiFormatReader().apply {
        setHints(mapOf(DecodeHintType.POSSIBLE_FORMATS to listOf(BarcodeFormat.QR_CODE), DecodeHintType.TRY_HARDER to true))
    }

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
            addView(hint, FrameLayout.LayoutParams(FrameLayout.LayoutParams.MATCH_PARENT, FrameLayout.LayoutParams.WRAP_CONTENT, Gravity.BOTTOM))
        })
    }

    override fun onResume() {
        super.onResume()
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
        val manager = getSystemService(CameraManager::class.java) ?: return fail("没有可用的相机")
        try {
            val id = manager.cameraIdList.firstOrNull {
                manager.getCameraCharacteristics(it).get(CameraCharacteristics.LENS_FACING) == CameraCharacteristics.LENS_FACING_BACK
            } ?: manager.cameraIdList.firstOrNull() ?: return fail("没有可用的相机")
            val characteristics = manager.getCameraCharacteristics(id)
            val map = characteristics.get(CameraCharacteristics.SCALER_STREAM_CONFIGURATION_MAP) ?: return fail("相机不可用")
            val size = chooseSize(map.getOutputSizes(ImageFormat.YUV_420_888) ?: emptyArray())
            val sensor = characteristics.get(CameraCharacteristics.SENSOR_ORIENTATION) ?: 90
            runOnUiThread { fitPreview(size, sensor) }
            reader = ImageReader.newInstance(size.width, size.height, ImageFormat.YUV_420_888, 2).apply {
                setOnImageAvailableListener({ source -> decode(source) }, handler)
            }
            manager.openCamera(id, object : CameraDevice.StateCallback() {
                override fun onOpened(device: CameraDevice) {
                    camera = device
                    startSession(device, size)
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
        val rotated = sensorDegrees % 180 != 0
        val bufferWidth = if (rotated) size.height.toFloat() else size.width.toFloat()
        val bufferHeight = if (rotated) size.width.toFloat() else size.height.toFloat()
        val scale = maxOf(viewWidth / bufferWidth, viewHeight / bufferHeight)
        val matrix = Matrix()
        val view = RectF(0f, 0f, viewWidth, viewHeight)
        val buffer = RectF(0f, 0f, bufferWidth * scale, bufferHeight * scale)
        buffer.offset(view.centerX() - buffer.centerX(), view.centerY() - buffer.centerY())
        matrix.setRectToRect(view, buffer, Matrix.ScaleToFit.FILL)
        preview.setTransform(matrix)
    }

    private fun startSession(device: CameraDevice, size: Size) {
        val texture = preview.surfaceTexture ?: return
        texture.setDefaultBufferSize(size.width, size.height)
        val previewSurface = Surface(texture)
        val readerSurface = reader?.surface ?: return
        @Suppress("DEPRECATION")
        device.createCaptureSession(listOf(previewSurface, readerSurface), object : CameraCaptureSession.StateCallback() {
            override fun onConfigured(configured: CameraCaptureSession) {
                session = configured
                val request = device.createCaptureRequest(CameraDevice.TEMPLATE_PREVIEW).apply {
                    addTarget(previewSurface)
                    addTarget(readerSurface)
                    set(CaptureRequest.CONTROL_AF_MODE, CaptureRequest.CONTROL_AF_MODE_CONTINUOUS_PICTURE)
                }
                runCatching { configured.setRepeatingRequest(request.build(), null, handler) }
            }
            override fun onConfigureFailed(failed: CameraCaptureSession) = fail("相机预览启动失败")
        }, handler)
    }

    private fun decode(source: ImageReader) {
        val image = source.acquireLatestImage() ?: return
        try {
            if (done.get()) return
            val plane = image.planes[0]
            val width = image.width
            val height = image.height
            val rowStride = plane.rowStride
            val buffer = plane.buffer
            val luminance = ByteArray(width * height)
            if (rowStride == width) {
                buffer.get(luminance, 0, luminance.size.coerceAtMost(buffer.remaining()))
            } else {
                for (row in 0 until height) {
                    buffer.position(row * rowStride)
                    buffer.get(luminance, row * width, width.coerceAtMost(buffer.remaining()))
                }
            }
            val bitmap = BinaryBitmap(HybridBinarizer(PlanarYUVLuminanceSource(luminance, width, height, 0, 0, width, height, false)))
            val text = try {
                decoder.decodeWithState(bitmap).text
            } catch (_: NotFoundException) {
                null
            } finally {
                decoder.reset()
            }
            if (text == null) return
            if (!text.startsWith("nknguard://")) {
                fail("这不是 NKNGuard 配对二维码")
                return
            }
            if (done.compareAndSet(false, true)) {
                runOnUiThread {
                    setResult(RESULT_OK, Intent().putExtra(EXTRA_TEXT, text))
                    finish()
                }
            }
        } catch (_: Exception) {
        } finally {
            image.close()
        }
    }

    private fun close() {
        runCatching { session?.close() }
        runCatching { camera?.close() }
        runCatching { reader?.close() }
        session = null
        camera = null
        reader = null
    }

    companion object {
        const val EXTRA_TEXT = "text"
    }
}
