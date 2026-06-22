from __future__ import annotations

import argparse
import csv
import json
import math
import random
import string
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Sequence

import numpy as np
import onnx
import onnxruntime as ort
import torch
from PIL import Image
from torch import nn
from torch.utils.data import DataLoader, Dataset, Subset
from torchvision import transforms

from captcha_model import TinyCaptchaNet


@dataclass(frozen=True)
class ModelMeta:
    input_height: int
    input_width: int
    captcha_length: int
    class_count: int
    normalization_mean: float = 0.5
    normalization_std: float = 0.5
    layout: str = "NCHW"
    input_name: str = "input"
    output_name: str = "logits"


def seed_everything(seed: int) -> None:
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)


def ordered_charset(labels: Sequence[str]) -> list[str]:
    seen = set("".join(labels))
    preferred = string.digits + string.ascii_uppercase + string.ascii_lowercase
    ordered = [char for char in preferred if char in seen]
    ordered.extend(sorted(seen.difference(ordered)))
    return ordered


class CaptchaDataset(Dataset):
    def __init__(
        self,
        dataset_dir: Path,
        samples: list[tuple[str, str]],
        char_to_index: dict[str, int],
        transform,
    ) -> None:
        self.dataset_dir = dataset_dir
        self.samples = samples
        self.char_to_index = char_to_index
        self.transform = transform

    def __len__(self) -> int:
        return len(self.samples)

    def __getitem__(self, index: int):
        relative, label = self.samples[index]
        path = self.dataset_dir / relative
        with Image.open(path) as image:
            image = image.convert("RGB")
            tensor = self.transform(image)
        target = torch.tensor(
            [self.char_to_index[char] for char in label],
            dtype=torch.long,
        )
        return tensor, target


def read_reviewed_samples(
    dataset_dir: Path,
) -> list[tuple[str, str]]:
    labels_path = dataset_dir / "labels.csv"
    if not labels_path.exists():
        raise FileNotFoundError(
            f"找不到 {labels_path}，请先运行 label_ui.py 审核标签"
        )

    samples: list[tuple[str, str]] = []
    with labels_path.open("r", encoding="utf-8-sig", newline="") as fp:
        for row in csv.DictReader(fp):
            if row.get("reviewed") != "1":
                continue
            image = (row.get("image") or "").strip()
            label = (row.get("label") or "").strip()
            if not image or not label:
                continue
            if not (dataset_dir / image).exists():
                print(f"[WARN] 图片不存在，跳过: {image}")
                continue
            samples.append((image, label))

    if not samples:
        raise RuntimeError("没有人工审核通过的样本")
    return samples


def split_indices(
    count: int,
    val_ratio: float,
    seed: int,
) -> tuple[list[int], list[int]]:
    indices = list(range(count))
    rng = random.Random(seed)
    rng.shuffle(indices)

    val_count = max(1, int(round(count * val_ratio)))
    val_count = min(val_count, count - 1)
    return indices[val_count:], indices[:val_count]


def metrics(
    logits: torch.Tensor,
    target: torch.Tensor,
) -> tuple[int, int, int, int]:
    prediction = logits.argmax(dim=-1)
    char_correct = int((prediction == target).sum().item())
    char_total = int(target.numel())
    exact_correct = int((prediction == target).all(dim=1).sum().item())
    exact_total = int(target.shape[0])
    return char_correct, char_total, exact_correct, exact_total


@torch.no_grad()
def evaluate(
    model: nn.Module,
    loader: DataLoader,
    criterion: nn.Module,
    device: torch.device,
) -> dict[str, float]:
    model.eval()
    loss_sum = 0.0
    sample_count = 0
    char_correct = char_total = exact_correct = exact_total = 0

    for images, target in loader:
        images = images.to(device, non_blocking=True)
        target = target.to(device, non_blocking=True)
        logits = model(images)
        loss = criterion(
            logits.reshape(-1, logits.shape[-1]),
            target.reshape(-1),
        )

        batch = target.shape[0]
        loss_sum += float(loss.item()) * batch
        sample_count += batch

        current = metrics(logits, target)
        char_correct += current[0]
        char_total += current[1]
        exact_correct += current[2]
        exact_total += current[3]

    return {
        "loss": loss_sum / max(1, sample_count),
        "char_accuracy": char_correct / max(1, char_total),
        "exact_accuracy": exact_correct / max(1, exact_total),
    }


def export_onnx(
    model: nn.Module,
    output_dir: Path,
    meta: ModelMeta,
    labels: list[str],
) -> None:
    model = model.cpu().eval()
    dummy = torch.zeros(
        1,
        1,
        meta.input_height,
        meta.input_width,
        dtype=torch.float32,
    )

    onnx_path = output_dir / "captcha.onnx"
    torch.onnx.export(
        model,
        dummy,
        onnx_path,
        input_names=[meta.input_name],
        output_names=[meta.output_name],
        dynamic_axes={
            meta.input_name: {0: "batch"},
            meta.output_name: {0: "batch"},
        },
        opset_version=17,
        do_constant_folding=True,
        dynamo=False,
    )

    checked = onnx.load(str(onnx_path))
    onnx.checker.check_model(checked)

    session = ort.InferenceSession(
        str(onnx_path),
        providers=["CPUExecutionProvider"],
    )
    ort_output = session.run(
        [meta.output_name],
        {meta.input_name: dummy.numpy()},
    )[0]
    torch_output = model(dummy).detach().numpy()

    max_diff = float(np.max(np.abs(ort_output - torch_output)))
    if max_diff > 1e-4:
        raise RuntimeError(
            f"PyTorch 与 ONNX 输出差异过大: max_diff={max_diff}"
        )

    (output_dir / "labels.txt").write_text(
        "\n".join(labels) + "\n",
        encoding="utf-8",
    )
    (output_dir / "model_meta.json").write_text(
        json.dumps(asdict(meta), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    print(f"[OK] ONNX 已导出: {onnx_path}")
    print(f"[OK] PyTorch/ONNX 最大输出差异: {max_diff:.8f}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="训练固定长度二课验证码模型并导出 ONNX"
    )
    parser.add_argument("--dataset", type=Path, default=Path("data"))
    parser.add_argument("--output", type=Path, default=Path("output"))
    parser.add_argument("--epochs", type=int, default=50)
    parser.add_argument("--batch-size", type=int, default=64)
    parser.add_argument("--learning-rate", type=float, default=1e-3)
    parser.add_argument("--weight-decay", type=float, default=1e-4)
    parser.add_argument("--val-ratio", type=float, default=0.15)
    parser.add_argument("--input-height", type=int, default=48)
    parser.add_argument("--input-width", type=int, default=160)
    parser.add_argument("--patience", type=int, default=10)
    parser.add_argument("--seed", type=int, default=20260622)
    parser.add_argument("--workers", type=int, default=0)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    seed_everything(args.seed)

    if not 0 < args.val_ratio < 0.5:
        raise ValueError("--val-ratio 应位于 0 和 0.5 之间")

    samples = read_reviewed_samples(args.dataset)
    if len(samples) < 20:
        raise RuntimeError("审核样本少于 20 张，无法进行有意义的训练/验证划分")
    lengths = {len(label) for _, label in samples}
    if len(lengths) != 1:
        raise RuntimeError(f"标签长度不一致: {sorted(lengths)}")
    captcha_length = lengths.pop()

    labels = [label for _, label in samples]
    charset = ordered_charset(labels)
    if len(charset) < 2:
        raise RuntimeError("字符类别少于 2 个，无法训练")

    char_to_index = {char: index for index, char in enumerate(charset)}

    train_transform = transforms.Compose(
        [
            transforms.Grayscale(num_output_channels=1),
            transforms.Resize(
                (args.input_height, args.input_width),
                interpolation=transforms.InterpolationMode.BILINEAR,
            ),
            transforms.RandomAffine(
                degrees=3,
                translate=(0.03, 0.05),
                scale=(0.96, 1.04),
                fill=255,
            ),
            transforms.ToTensor(),
            transforms.Normalize(mean=(0.5,), std=(0.5,)),
        ]
    )
    val_transform = transforms.Compose(
        [
            transforms.Grayscale(num_output_channels=1),
            transforms.Resize(
                (args.input_height, args.input_width),
                interpolation=transforms.InterpolationMode.BILINEAR,
            ),
            transforms.ToTensor(),
            transforms.Normalize(mean=(0.5,), std=(0.5,)),
        ]
    )

    train_indices, val_indices = split_indices(
        len(samples),
        args.val_ratio,
        args.seed,
    )
    train_dataset = Subset(
        CaptchaDataset(
            args.dataset,
            samples,
            char_to_index,
            train_transform,
        ),
        train_indices,
    )
    val_dataset = Subset(
        CaptchaDataset(
            args.dataset,
            samples,
            char_to_index,
            val_transform,
        ),
        val_indices,
    )

    device = torch.device(
        "cuda" if torch.cuda.is_available() else "cpu"
    )
    pin_memory = device.type == "cuda"

    train_loader = DataLoader(
        train_dataset,
        batch_size=args.batch_size,
        shuffle=True,
        num_workers=args.workers,
        pin_memory=pin_memory,
    )
    val_loader = DataLoader(
        val_dataset,
        batch_size=args.batch_size,
        shuffle=False,
        num_workers=args.workers,
        pin_memory=pin_memory,
    )

    model = TinyCaptchaNet(
        captcha_length=captcha_length,
        class_count=len(charset),
    ).to(device)
    criterion = nn.CrossEntropyLoss(label_smoothing=0.02)
    optimizer = torch.optim.AdamW(
        model.parameters(),
        lr=args.learning_rate,
        weight_decay=args.weight_decay,
    )
    scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(
        optimizer,
        mode="max",
        factor=0.5,
        patience=3,
        min_lr=1e-6,
    )

    args.output.mkdir(parents=True, exist_ok=True)
    checkpoint_path = args.output / "best.pt"

    best_exact = -1.0
    epochs_without_improvement = 0

    print(
        f"样本={len(samples)} 训练={len(train_indices)} 验证={len(val_indices)} "
        f"长度={captcha_length} 字符类别={len(charset)} 设备={device}"
    )
    print("字符集:", "".join(charset))

    for epoch in range(1, args.epochs + 1):
        model.train()
        train_loss_sum = 0.0
        train_count = 0
        train_char_correct = train_char_total = 0
        train_exact_correct = train_exact_total = 0

        for images, target in train_loader:
            images = images.to(device, non_blocking=True)
            target = target.to(device, non_blocking=True)

            optimizer.zero_grad(set_to_none=True)
            logits = model(images)
            loss = criterion(
                logits.reshape(-1, logits.shape[-1]),
                target.reshape(-1),
            )
            loss.backward()
            nn.utils.clip_grad_norm_(model.parameters(), max_norm=5.0)
            optimizer.step()

            batch = target.shape[0]
            train_loss_sum += float(loss.item()) * batch
            train_count += batch

            current = metrics(logits.detach(), target)
            train_char_correct += current[0]
            train_char_total += current[1]
            train_exact_correct += current[2]
            train_exact_total += current[3]

        val = evaluate(model, val_loader, criterion, device)
        train_loss = train_loss_sum / max(1, train_count)
        train_char = train_char_correct / max(1, train_char_total)
        train_exact = train_exact_correct / max(1, train_exact_total)

        scheduler.step(val["exact_accuracy"])
        current_lr = optimizer.param_groups[0]["lr"]

        print(
            f"Epoch {epoch:03d} | "
            f"lr={current_lr:.2e} | "
            f"train_loss={train_loss:.4f} "
            f"train_char={train_char:.4%} "
            f"train_exact={train_exact:.4%} | "
            f"val_loss={val['loss']:.4f} "
            f"val_char={val['char_accuracy']:.4%} "
            f"val_exact={val['exact_accuracy']:.4%}"
        )

        if val["exact_accuracy"] > best_exact:
            best_exact = val["exact_accuracy"]
            epochs_without_improvement = 0
            torch.save(
                {
                    "state_dict": model.state_dict(),
                    "captcha_length": captcha_length,
                    "charset": charset,
                    "input_height": args.input_height,
                    "input_width": args.input_width,
                    "val_metrics": val,
                },
                checkpoint_path,
            )
            print(f"[BEST] 已保存 {checkpoint_path}")
        else:
            epochs_without_improvement += 1
            if epochs_without_improvement >= args.patience:
                print("[STOP] 验证集完整准确率长期未提升")
                break

    checkpoint = torch.load(
        checkpoint_path,
        map_location="cpu",
        weights_only=False,
    )
    best_model = TinyCaptchaNet(
        captcha_length=checkpoint["captcha_length"],
        class_count=len(checkpoint["charset"]),
    )
    best_model.load_state_dict(checkpoint["state_dict"])

    meta = ModelMeta(
        input_height=checkpoint["input_height"],
        input_width=checkpoint["input_width"],
        captcha_length=checkpoint["captcha_length"],
        class_count=len(checkpoint["charset"]),
    )
    export_onnx(
        best_model,
        args.output,
        meta,
        checkpoint["charset"],
    )
    print(
        f"训练完成，最佳验证集完整准确率: "
        f"{checkpoint['val_metrics']['exact_accuracy']:.4%}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
