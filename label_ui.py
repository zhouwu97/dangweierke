from __future__ import annotations

import argparse
import csv
import re
import tkinter as tk
from pathlib import Path
from tkinter import messagebox, ttk

from PIL import Image, ImageTk


LABEL_PATTERN = re.compile(r"^[0-9A-Za-z]+$")


class LabelStore:
    def __init__(self, dataset_dir: Path) -> None:
        self.dataset_dir = dataset_dir
        self.manifest_path = dataset_dir / "manifest.csv"
        self.labels_path = dataset_dir / "labels.csv"

        if not self.manifest_path.exists():
            raise FileNotFoundError(f"找不到 {self.manifest_path}")

        self.manifest = self._read_manifest()
        self.labels = self._read_labels()

    def _read_manifest(self) -> list[dict[str, str]]:
        with self.manifest_path.open(
            "r",
            encoding="utf-8-sig",
            newline="",
        ) as fp:
            return list(csv.DictReader(fp))

    def _read_labels(self) -> dict[str, dict[str, str]]:
        if not self.labels_path.exists():
            return {}

        with self.labels_path.open(
            "r",
            encoding="utf-8-sig",
            newline="",
        ) as fp:
            return {
                row["image"]: row
                for row in csv.DictReader(fp)
                if row.get("image")
            }

    def save_label(self, image: str, label: str) -> None:
        self.labels[image] = {
            "image": image,
            "label": label,
            "reviewed": "1",
        }
        self.flush()

    def flush(self) -> None:
        with self.labels_path.open(
            "w",
            encoding="utf-8-sig",
            newline="",
        ) as fp:
            writer = csv.DictWriter(
                fp,
                fieldnames=("image", "label", "reviewed"),
            )
            writer.writeheader()
            for image in sorted(self.labels):
                writer.writerow(self.labels[image])


class LabelApp:
    def __init__(
        self,
        root: tk.Tk,
        store: LabelStore,
        expected_length: int,
    ) -> None:
        self.root = root
        self.store = store
        self.expected_length = expected_length
        self.index = self._first_unreviewed_index()
        self.photo: ImageTk.PhotoImage | None = None

        root.title("SYLU 二课验证码标签审核")
        root.geometry("760x440")
        root.minsize(620, 360)

        self.status_var = tk.StringVar()
        self.path_var = tk.StringVar()
        self.label_var = tk.StringVar()

        container = ttk.Frame(root, padding=18)
        container.pack(fill=tk.BOTH, expand=True)

        ttk.Label(
            container,
            textvariable=self.status_var,
            font=("Microsoft YaHei UI", 12, "bold"),
        ).pack(anchor=tk.W)

        ttk.Label(
            container,
            textvariable=self.path_var,
        ).pack(anchor=tk.W, pady=(5, 12))

        self.image_label = ttk.Label(container, anchor=tk.CENTER)
        self.image_label.pack(fill=tk.BOTH, expand=True)

        bottom = ttk.Frame(container)
        bottom.pack(fill=tk.X, pady=(14, 0))

        ttk.Label(bottom, text="验证码：").pack(side=tk.LEFT)
        self.entry = ttk.Entry(
            bottom,
            textvariable=self.label_var,
            width=18,
            font=("Consolas", 18),
        )
        self.entry.pack(side=tk.LEFT, padx=(4, 12))

        ttk.Button(
            bottom,
            text="保存并下一张 (Enter)",
            command=self.save_and_next,
        ).pack(side=tk.LEFT, padx=4)

        ttk.Button(
            bottom,
            text="跳过 (→)",
            command=self.next_image,
        ).pack(side=tk.LEFT, padx=4)

        ttk.Button(
            bottom,
            text="上一张 (←)",
            command=self.previous_image,
        ).pack(side=tk.LEFT, padx=4)

        root.bind("<Return>", lambda _: self.save_and_next())
        root.bind("<Right>", lambda _: self.next_image())
        root.bind("<Left>", lambda _: self.previous_image())

        self.render()

    def _first_unreviewed_index(self) -> int:
        for index, row in enumerate(self.store.manifest):
            existing = self.store.labels.get(row["image"])
            if not existing or existing.get("reviewed") != "1":
                return index
        return 0

    def _current(self) -> dict[str, str]:
        return self.store.manifest[self.index]

    def render(self) -> None:
        if not self.store.manifest:
            messagebox.showinfo("提示", "manifest.csv 中没有样本")
            self.root.destroy()
            return

        row = self._current()
        image_path = self.store.dataset_dir / row["image"]
        if not image_path.exists():
            messagebox.showerror("文件缺失", str(image_path))
            self.next_image()
            return

        image = Image.open(image_path).convert("RGB")
        image.thumbnail((620, 230), Image.Resampling.NEAREST)
        self.photo = ImageTk.PhotoImage(image)
        self.image_label.configure(image=self.photo)

        existing = self.store.labels.get(row["image"], {})
        initial = existing.get("label") or row.get("suggestion") or ""
        self.label_var.set(initial)

        reviewed = sum(
            1
            for item in self.store.labels.values()
            if item.get("reviewed") == "1"
        )
        self.status_var.set(
            f"第 {self.index + 1}/{len(self.store.manifest)} 张 · "
            f"已审核 {reviewed} 张"
        )
        self.path_var.set(row["image"])

        self.entry.focus_set()
        self.entry.selection_range(0, tk.END)

    def save_and_next(self) -> None:
        label = self.label_var.get().strip()

        if len(label) != self.expected_length:
            messagebox.showwarning(
                "标签长度不正确",
                f"标签必须是 {self.expected_length} 位，当前是 {len(label)} 位。",
            )
            return

        if not LABEL_PATTERN.fullmatch(label):
            messagebox.showwarning(
                "标签字符不正确",
                "目前只接受数字和英文字母。",
            )
            return

        self.store.save_label(self._current()["image"], label)
        self.next_image()

    def next_image(self) -> None:
        self.index = (self.index + 1) % len(self.store.manifest)
        self.render()

    def previous_image(self) -> None:
        self.index = (self.index - 1) % len(self.store.manifest)
        self.render()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="人工审核验证码标签")
    parser.add_argument("--dataset", type=Path, default=Path("data"))
    parser.add_argument("--length", type=int, default=4)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    store = LabelStore(args.dataset)
    root = tk.Tk()
    LabelApp(root, store, args.length)
    root.mainloop()


if __name__ == "__main__":
    main()
