from __future__ import annotations

import torch
from torch import nn


class TinyCaptchaNet(nn.Module):
    """
    固定长度验证码多位置分类网络。

    输入:
        [N, 1, H, W]

    输出:
        [N, captcha_length, class_count]
    """

    def __init__(
        self,
        captcha_length: int,
        class_count: int,
    ) -> None:
        super().__init__()
        self.captcha_length = captcha_length
        self.class_count = class_count

        self.features = nn.Sequential(
            nn.Conv2d(1, 32, kernel_size=3, padding=1, bias=False),
            nn.BatchNorm2d(32),
            nn.ReLU(inplace=True),
            nn.MaxPool2d(2),

            nn.Conv2d(32, 64, kernel_size=3, padding=1, bias=False),
            nn.BatchNorm2d(64),
            nn.ReLU(inplace=True),
            nn.MaxPool2d(2),

            nn.Conv2d(64, 96, kernel_size=3, padding=1, bias=False),
            nn.BatchNorm2d(96),
            nn.ReLU(inplace=True),

            nn.Conv2d(96, 128, kernel_size=3, padding=1, bias=False),
            nn.BatchNorm2d(128),
            nn.ReLU(inplace=True),
        )

        # 保留横向字符顺序，将输出宽度固定为验证码长度。
        self.position_pool = nn.AdaptiveAvgPool2d((1, captcha_length))
        self.classifier = nn.Sequential(
            nn.LayerNorm(128),
            nn.Dropout(0.15),
            nn.Linear(128, class_count),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        x = self.features(x)
        x = self.position_pool(x)
        x = x.squeeze(2).transpose(1, 2)
        return self.classifier(x)
