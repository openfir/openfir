// SPDX-License-Identifier: Apache-2.0
package io.openfir.app

import android.os.Handler
import android.os.Looper

/**
 * Zero-dependency Kotlin bridge to libopenfir_core.so + libopenfir_jni.so.
 */
object OpenFIRCore {
    private val mainHandler = Handler(Looper.getMainLooper())

    @Volatile
    private var uiCallback: ((Long, String) -> Unit)? = null

    private val nativeListener = object {
        @Suppress("unused")
        fun onCoreEvent(handle: Long, json: String) {
            mainHandler.post {
                uiCallback?.invoke(handle, json)
            }
        }
    }

    init {
        System.loadLibrary("openfir_core")
        System.loadLibrary("openfir_jni")
        nativeSetListener(nativeListener)
    }

    fun setCallback(cb: ((Long, String) -> Unit)?) {
        uiCallback = cb
    }

    fun version(): String = nativeVersion()
    fun keygen(): String = nativeKeygen()
    fun startTransfer(configJson: String): Long = nativeTransferStart(configJson)
    fun cancelTransfer(handle: Long) = nativeTransferCancel(handle)
    fun startServer(configJson: String): Long = nativeServerStart(configJson)
    fun stopServer(handle: Long) = nativeServerStop(handle)
    fun startSelftest(): Long = nativeSelftestStart()

    private external fun nativeSetListener(listener: Any?)
    private external fun nativeVersion(): String
    private external fun nativeKeygen(): String
    private external fun nativeTransferStart(configJson: String): Long
    private external fun nativeTransferCancel(handle: Long)
    private external fun nativeServerStart(configJson: String): Long
    private external fun nativeServerStop(handle: Long)
    private external fun nativeSelftestStart(): Long
}
