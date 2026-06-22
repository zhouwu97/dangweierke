from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import onnxruntime as ort
from PIL import Image


def preprocess(
    image_path: Path,
    height: int,
    width: int,
    mean: float,
    std: float,
) -> np.ndarray:
    with Image.open(image_path) as image:
        image = image.convert("L")
        image = image.resize((width, height), Image.Resampling.BILINEAR)
        array = np.asarray(image, dtype=np.float32) / 255.0

    array = (array - mean) / std
    return array[None, None, :, :]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="测试 captcha.onnx")
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--labels", type=Path, required=True)
    parser.add_argument("--meta", type=Path, required=True)
    parser.add_argument("--image", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    labels = [
        line.strip()
        for line in args.labels.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    meta = json.loads(args.meta.read_text(encoding="utf-8"))

    input_tensor = preprocess(
        args.image,
        meta["input_height"],
        meta["input_width"],
        meta["normalization_mean"],
        meta["normalization_std"],
    )

    session = ort.InferenceSession(
        str(args.model),
        providers=["CPUExecutionProvider"],
    )
    logits = session.run(
        [meta["output_name"]],
        {meta["input_name"]: input_tensor},
    )[0]

    indices = logits.argmax(axis=-1)[0]
    code = "".join(labels[int(index)] for index in indices)

    probabilities = np.exp(logits - logits.max(axis=-1, keepdims=True))
    probabilities /= probabilities.sum(axis=-1, keepdims=True)
    confidence = probabilities.max(axis=-1)[0]

    print("识别结果:", code)
    print(
        "各字符置信度:",
        ", ".join(f"{value:.2%}" for value in confidence),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
