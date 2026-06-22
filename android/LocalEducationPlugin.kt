package com.example.shenliyuan.education

import android.content.Context
import io.flutter.plugin.common.BinaryMessenger
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.Closeable

class LocalEducationPlugin(
    context: Context,
    messenger: BinaryMessenger,
) : MethodChannel.MethodCallHandler, Closeable {
    private val channel = MethodChannel(
        messenger,
        "sylulive/local_education",
    )
    private val scope = CoroutineScope(
        SupervisorJob() + Dispatchers.Default,
    )
    private val recognizer = CaptchaOnnxRecognizer(context)

    init {
        channel.setMethodCallHandler(this)
    }

    override fun onMethodCall(
        call: MethodCall,
        result: MethodChannel.Result,
    ) {
        when (call.method) {
            "recognizeCaptcha" -> recognizeCaptcha(call, result)
            else -> result.notImplemented()
        }
    }

    private fun recognizeCaptcha(
        call: MethodCall,
        result: MethodChannel.Result,
    ) {
        val bytes = call.argument<ByteArray>("bytes")
        if (bytes == null || bytes.isEmpty()) {
            result.error(
                "INVALID_ARGUMENT",
                "bytes 不能为空",
                null,
            )
            return
        }

        scope.launch {
            val recognition = runCatching {
                recognizer.recognize(bytes)
            }

            withContext(Dispatchers.Main) {
                recognition.fold(
                    onSuccess = result::success,
                    onFailure = { error ->
                        result.error(
                            "CAPTCHA_RECOGNITION_FAILED",
                            error.message ?: "验证码识别失败",
                            null,
                        )
                    },
                )
            }
        }
    }

    override fun close() {
        channel.setMethodCallHandler(null)
        scope.cancel()
        recognizer.close()
    }
}
