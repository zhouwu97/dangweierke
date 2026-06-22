import 'dart:typed_data';

import 'package:flutter/services.dart';

class LocalEducation {
  static const MethodChannel _channel = MethodChannel(
    'sylulive/local_education',
  );

  static Future<String> recognizeCaptcha(Uint8List bytes) async {
    final result = await _channel.invokeMethod<String>(
      'recognizeCaptcha',
      <String, Object>{
        'bytes': bytes,
      },
    );

    if (result == null || result.isEmpty) {
      throw StateError('本地验证码识别返回空结果');
    }
    return result;
  }
}

// 二课本地登录中的使用示例：
//
// final captchaResponse = await dio.get<List<int>>(
//   captchaUrl,
//   options: Options(responseType: ResponseType.bytes),
// );
// final bytes = Uint8List.fromList(captchaResponse.data!);
// final code = await LocalEducation.recognizeCaptcha(bytes);
//
// 然后把 code 和同一 Cookie Session、同一登录页的
// __VIEWSTATE / __EVENTVALIDATION 一起提交。
// OCR 失败或服务器返回“验证码错误”时，重新下载新验证码；
// 最多自动尝试 2～3 次，之后展示图片让用户手动输入。
