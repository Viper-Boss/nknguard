package io.github.viperboss.nknguard.ui

import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.PlanarYUVLuminanceSource
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel
import org.junit.Assert.*
import org.junit.Test
import java.nio.ByteBuffer

class PairQrDecoderTest {
    private val payload = "nknguard://pair/v1?data=" + "Abcd1234_-".repeat(70)
    private val size = 768

    private fun qr(): ByteArray {
        val bits = QRCodeWriter().encode(payload, BarcodeFormat.QR_CODE, size, size,
            mapOf(EncodeHintType.ERROR_CORRECTION to ErrorCorrectionLevel.M, EncodeHintType.MARGIN to 4))
        return ByteArray(size * size) { i -> if (bits[i % size, i / size]) 0 else 255.toByte() }
    }

    private fun decode(bytes: ByteArray) = PairQrDecoder.decode(
        PlanarYUVLuminanceSource(bytes, size, size, 0, 0, size, size, false))

    @Test fun densePairLinkSurvivesRotationAndInversion() {
        var bytes = qr()
        repeat(4) {
            assertEquals(payload, decode(bytes))
            assertEquals(payload, decode(ByteArray(bytes.size) { i -> (255 - (bytes[i].toInt() and 255)).toByte() }))
            val original = bytes
            bytes = ByteArray(original.size) { i -> original[(size - 1 - i % size) * size + i / size] }
        }
    }

    @Test fun cameraPaddingPixelStrideCropAndBufferPositionPreserveQr() {
        val expected = qr()
        val stride = (size + 8) * 2
        val origin = 7
        val buffer = ByteBuffer.allocate(origin + stride * (size + 4))
        for (y in 0 until size) for (x in 0 until size)
            buffer.put(origin + (y + 2) * stride + (x + 3) * 2, expected[y * size + x])
        buffer.position(origin)
        val extracted = PairQrDecoder.luminance(buffer, size, size, stride, 2, 3, 2)
        assertArrayEquals(expected, extracted)
        assertEquals(origin, buffer.position())
        assertEquals(payload, decode(extracted))
    }

    @Test fun blankImageDoesNotPair() {
        assertNull(decode(ByteArray(size * size) { 255.toByte() }))
    }
}
