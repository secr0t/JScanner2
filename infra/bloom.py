import hashlib
import math
import mmap
import os
from typing import Generator


class DiskBloomFilter:
    """
    基于磁盘映射的持久化布隆过滤器
    """

    def __init__(
        self,
        filepath: str,
        capacity: int = 10_000_000,
        error_rate: float = 0.001
    ):
        self.filepath = filepath
        self.size = int(- (capacity * math.log(error_rate)) / (math.log(2) ** 2))
        self.hash_count = int((self.size / capacity) * math.log(2))
        self.byte_size = (self.size + 7) // 8

        os.makedirs(os.path.dirname(filepath), exist_ok=True)

        # 文件不存在则创建零填充文件
        if not os.path.exists(filepath):
            with open(filepath, "wb") as f:
                f.write(b'\x00' * self.byte_size)

        self.file = open(filepath, "r+b")
        self.mm = mmap.mmap(self.file.fileno(), 0)

    def _get_hashes(self, item: str) -> Generator[int, None, None]:
        item_encoded = item.encode("utf8")
        md5 = int(hashlib.md5(item_encoded).hexdigest(), 16)
        sha1 = int(hashlib.sha1(item_encoded).hexdigest(), 16)
        for i in range(self.hash_count):
            yield (md5 + i * sha1) % self.size

    def add(self, item: str) -> bool:
        """添加元素，返回True表示新增，False表示已存在"""
        if self.contains(item):
            return False
        for pos in self._get_hashes(item):
            byte_index = pos // 8
            bit_index = pos % 8
            self.mm[byte_index] |= (1 << bit_index)
        return True

    def contains(self, item: str) -> bool:
        """检查元素可能存在（True）或肯定不存在（False）"""
        for pos in self._get_hashes(item):
            byte_index = pos // 8
            bit_index = pos % 8
            if not (self.mm[byte_index] & (1 << bit_index)):
                return False
        return True

    def clear(self):
        """清空过滤器（用于与 DB 生命周期对齐，避免旧去重记录压掉新库结果）"""
        try:
            self.mm.seek(0)
            self.mm.write(b'\x00' * self.byte_size)
            self.mm.flush()
        except Exception:
            pass

    def close(self):
        """关闭文件句柄，数据已自动持久化到磁盘"""
        try:
            self.mm.close()
            self.file.close()
        except Exception:
            pass