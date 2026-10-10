package io.github.viperboss.nknguard.ui

import android.content.ContentProvider
import android.content.ContentValues
import android.database.Cursor
import android.database.MatrixCursor
import android.net.Uri
import android.os.ParcelFileDescriptor
import android.provider.OpenableColumns
import java.io.File
import java.io.FileNotFoundException

// The installer receives a temporary read grant for this one verified APK.
class UpdateProvider : ContentProvider() {
    override fun onCreate() = true
    private fun file(uri: Uri): File {
        if (uri.path != "/latest.apk") throw FileNotFoundException()
        return File(requireNotNull(context).cacheDir, "updates/latest.apk")
    }
    override fun getType(uri: Uri): String { file(uri); return "application/vnd.android.package-archive" }
    override fun openFile(uri: Uri, mode: String): ParcelFileDescriptor {
        if (mode != "r") throw FileNotFoundException("read only")
        return ParcelFileDescriptor.open(file(uri), ParcelFileDescriptor.MODE_READ_ONLY)
    }
    override fun query(uri: Uri, projection: Array<out String>?, selection: String?, selectionArgs: Array<out String>?, sortOrder: String?): Cursor {
        val f = file(uri)
        val columns = projection ?: arrayOf(OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE)
        return MatrixCursor(columns).apply { addRow(columns.map { when (it) { OpenableColumns.DISPLAY_NAME -> "NKNGuard-update.apk"; OpenableColumns.SIZE -> f.length(); else -> null } }.toTypedArray()) }
    }
    override fun insert(uri: Uri, values: ContentValues?): Uri = throw UnsupportedOperationException()
    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<out String>?): Int = throw UnsupportedOperationException()
    override fun update(uri: Uri, values: ContentValues?, selection: String?, selectionArgs: Array<out String>?): Int = throw UnsupportedOperationException()
}
