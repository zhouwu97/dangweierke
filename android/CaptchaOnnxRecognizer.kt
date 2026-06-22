package com.example.shenliyuan.education

import ai.onnxruntime.OnnxTensor
import ai.onnxruntime.OrtEnvironment
import ai.onnxruntime.OrtSession
import android.content.Context
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import org.json.JSONObject
import java.io.Closeable
import java.nio.FloatBuffer

class CaptchaOnnxRecognizer(
    context: Context,
) : Closeable {
    private val environment: OrtEnvironment = OrtEnvironment.getEnvironment()

    private val metadata = context.assets
        .open("model_meta.json")
        .bufferedReader()
        .use { JSONObject(it.readText()) }

    private val inputHeight = metadata.getInt("input_height")
    private val inputWidth = metadata.getInt("input_width")
    private val captchaLength = metadata.getInt("captcha_length")
    private val classCount = metadata.getInt("class_count")
    private val normalizationMean =
        metadata.getDouble("normalization_mean").toFloat()
    private val normalizationStd =
        metadata.getDouble("normalization_std").toFloat()
    private val inputName = metadata.getString("input_name")
    private val outputName = metadata.getString("output_name")

    private val labels: List<String> = context.assets
        .open("labels.txt")
        .bufferedReader()
        .use { reader ->
            reader.readLines()
                .map(String::trim)
                .filter(String::isNotEmpty)
        }

    private val session: OrtSession = environment.createSession(
        context.assets.open("captcha.onnx").use { it.readBytes() },
        OrtSession.SessionOptions().apply {
            setIntraOpNumThreads(1)
            setInterOpNumThreads(1)
            setOptimizationLevel(
                OrtSession.SessionOptions.OptLevel.ALL_OPT,
            )
        },
    )

    init {
        require(labels.size == classCount) {
            "labels.txt 数量 ${labels.size} 与模型 class_count=$classCount 不一致"
        }
    }

    fun recognize(imageBytes: ByteArray): String {
        val decoded = BitmapFactory.decodeByteArray(
            imageBytes,
            0,
            imageBytes.size,
        ) ?: error("无法解析验证码图片")

        val scaled = Bitmap.createScaledBitmap(
            decoded,
            inputWidth,
            inputHeight,
            true,
        )

        try {
            val input = bitmapToNchwGrayscale(scaled)
            OnnxTensor.createTensor(
                environment,
                FloatBuffer.wrap(input),
                longArrayOf(
                    1L,
                    1L,
                    inputHeight.toLong(),
                    inputWidth.toLong(),
                ),
            ).use { tensor ->
                session.run(mapOf(inputName to tensor)).use { result ->
                    val value = result.get(outputName)
                        .orElseThrow { IllegalStateException("模型缺少输出 $outputName") }
                        .value

                    @Suppress("UNCHECKED_CAST")
                    val logits = value as? Array<Array<FloatArray>>
                        ?: error("模型输出类型异常: ${value::class.java.name}")

                    require(logits.size == 1)
                    require(logits[0].size == captchaLength)

                    return buildString(captchaLength) {
                        logits[0].forEach { position ->
                            require(position.size == classCount)
                            val index = argmax(position)
                            append(labels[index])
                        }
                    }
                }
            }
        } finally {
            if (scaled !== decoded) {
                scaled.recycle()
            }
            decoded.recycle()
        }
    }

    private fun bitmapToNchwGrayscale(bitmap: Bitmap): FloatArray {
        val pixels = IntArray(inputWidth * inputHeight)
        bitmap.getPixels(
            pixels,
            0,
            inputWidth,
            0,
            0,
            inputWidth,
            inputHeight,
        )

        return FloatArray(pixels.size) { index ->
            val pixel = pixels[index]
            val red = (pixel shr 16) and 0xFF
            val green = (pixel shr 8) and 0xFF
            val blue = pixel and 0xFF

            val grayscale = (
                0.299f * red +
                    0.587f * green +
                    0.114f * blue
                ) / 255f

            (grayscale - normalizationMean) / normalizationStd
        }
    }

    private fun argmax(values: FloatArray): Int {
        var bestIndex = 0
        var bestValue = Float.NEGATIVE_INFINITY
        values.forEachIndexed { index, value ->
            if (value > bestValue) {
                bestValue = value
                bestIndex = index
            }
        }
        return bestIndex
    }

    override fun close() {
        session.close()
        // OrtEnvironment 是进程级单例，通常不在单个识别器中关闭。
    }
}
