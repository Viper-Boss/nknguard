package io.github.viperboss.nknguard.ui

import com.google.zxing.*
import com.google.zxing.common.GlobalHistogramBinarizer
import com.google.zxing.common.HybridBinarizer
import java.nio.ByteBuffer

/** Shared by camera and gallery. No camera/Android dependency, so it is testable. */
internal object PairQrDecoder {
    fun luminance(buffer: ByteBuffer, width: Int, height: Int, rowStride: Int, pixelStride: Int, left: Int = 0, top: Int = 0): ByteArray {
        require(width > 0 && height > 0 && rowStride > 0 && pixelStride > 0)
        val input = buffer.duplicate()
        val origin = input.position()
        val output = ByteArray(Math.multiplyExact(width, height))
        for (y in 0 until height) {
            for (x in 0 until width) {
                output[y * width + x] = input.get(origin + (top + y) * rowStride + (left + x) * pixelStride)
            }
        }
        return output
    }

    fun decode(source: LuminanceSource): String? {
        val hints = mapOf(DecodeHintType.POSSIBLE_FORMATS to listOf(BarcodeFormat.QR_CODE), DecodeHintType.TRY_HARDER to true)
        for (candidate in listOf(source, source.invert())) {
            for (binarizer in listOf(HybridBinarizer(candidate), GlobalHistogramBinarizer(candidate))) {
                val reader = MultiFormatReader()
                try { return reader.decode(BinaryBitmap(binarizer), hints).text.trim() }
                catch (_: ReaderException) { }
                finally { reader.reset() }
            }
        }
        return null
    }
}
