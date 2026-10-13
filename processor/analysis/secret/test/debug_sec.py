#!/usr/bin/env python3
"""
SecretMathScorer 核心计算逻辑调试脚本
- 零项目依赖，仅依赖 nltk + wordninja
- 支持单字符串 / JSON 列表 / 文件输入
- 输出逐层计算明细：E_raw, length_conf, alpha_only, words, P, base, final
"""

import argparse
import json
import math
import re
import sys
from collections import Counter
from typing import List, Dict, Optional

# 🔥 仅依赖这两个外部库
try:
    import nltk
    from nltk.corpus import words
    import wordninja
except ImportError as e:
    print(f"❌ Missing dependency: {e}\n💡 Run: pip install nltk wordninja")
    sys.exit(1)


# 自动初始化 NLTK（离线模式）
def _init_nltk():
    try:
        words.words()
    except LookupError:
        print("⚠️  NLTK 'words' corpus not found, downloading...")
        nltk.download('words', quiet=True)


# 🔥 极简技术词表（仅用于演示，可按需扩展）
TECH_WORDS = {
    'api', 'http', 'https', 'json', 'xml', 'css', 'html', 'div', 'span', 'click', 'data', 'id',
    'token', 'user', 'admin', 'config', 'env', 'key', 'secret', 'function', 'var', 'let', 'const',
    'return', 'true', 'false', 'null', 'undefined', 'window', 'document', 'console', 'log', 'error',
    'warn', 'info', 'debug', 'test', 'mock', 'stub', 'fake', 'example', 'sample', 'demo', 'temp',
    'tmp', 'cache', 'store', 'db', 'sql', 'mongo', 'redis', 'aws', 'azure', 'gcp', 'google',
    'facebook', 'twitter', 'github', 'gitlab', 'bitbucket', 'npm', 'yarn', 'webpack', 'babel',
    'react', 'vue', 'angular', 'node', 'express', 'django', 'flask', 'spring', 'rails', 'laravel',
    'request', 'response', 'header', 'body', 'query', 'params', 'route', 'path', 'url', 'link',
    'href', 'src', 'alt', 'title', 'class', 'style', 'script', 'meta', 'head', 'body',
    'encrypted', 'decrypt', 'encrypt', 'cipher', 'hash', 'signature', 'credential'
}


class DebugMathScorer:
    """极简版 SecretMathScorer，仅保留核心计算 + 详细调试输出"""

    def __init__(self, weights: Optional[Dict[str, float]] = None):
        _init_nltk()
        self.weights = weights or {'w_e': 0.85, 'w_p': 1.2}
        try:
            nltk_words = set(w.lower() for w in words.words())
            self.valid_words_set = nltk_words.union(TECH_WORDS)
        except:
            self.valid_words_set = TECH_WORDS
        self._log2 = lambda x: math.log2(x) if x > 0 else 0.0

    def _camel_split(self, s: str) -> List[str]:
        parts = re.findall(r'[A-Z]?[a-z]+|[A-Z]+(?=[A-Z]|$)', s)
        return [p.lower() for p in parts if p]

    def _wordninja_split(self, s: str) -> List[str]:
        try:
            return wordninja.split(s)
        except:
            return []

    def calc_E_debug(self, s: str) -> Dict[str, float]:
        """计算熵值，返回详细中间结果"""
        L = len(s)
        if L == 0:
            return {'E_raw': 0.0, 'length_conf': 1.0, 'E_final': 0.0}

        cnt = Counter(s)
        H = -sum((c / L) * self._log2(c / L) for c in cnt.values())
        max_H = self._log2(min(L, len(cnt)))
        E_raw = H / max_H if max_H > 0 else 0.0

        # Sigmoid 长度衰减
        length_conf = 1.0 / (1.0 + math.exp(-0.3 * (L - 12)))
        E_final = E_raw * length_conf

        return {
            'length': L,
            'unique_chars': len(cnt),
            'H': H,
            'max_H': max_H,
            'E_raw': E_raw,
            'length_conf': length_conf,
            'E_final': E_final
        }

    def calc_P_debug(self, s: str) -> Dict[str, any]:
        """计算词典占比，返回详细中间结果"""
        # 1. 提取纯字母（直接处理原始字符串）
        alpha_only = re.sub(r'[^a-zA-Z]', '', s).lower()
        L_alpha = len(alpha_only)

        if L_alpha < 4:
            return {
                'alpha_only': alpha_only,
                'L_alpha': L_alpha,
                'words_wn': [],
                'words_camel': [],
                'valid_words': [],
                'matched_words': [],
                'matched_len': 0,
                'P': 0.0
            }

        # 2. 双路分词
        words_wn = self._wordninja_split(alpha_only)
        words_camel = self._camel_split(alpha_only)
        all_words = list(set(words_wn + words_camel))

        # 3. 过滤 + 词典匹配
        valid_words = [w for w in all_words if len(w) > 3]
        matched_words = [w for w in valid_words if w in self.valid_words_set]
        matched_len = sum(len(w) for w in matched_words)

        P = min(matched_len / L_alpha, 1.0) if L_alpha > 0 else 0.0

        return {
            'alpha_only': alpha_only,
            'L_alpha': L_alpha,
            'words_wn': words_wn,
            'words_camel': words_camel,
            'all_words': all_words,
            'valid_words': valid_words,
            'matched_words': matched_words,
            'matched_len': matched_len,
            'P': P
        }

    def score_debug(self, s: str) -> Dict[str, any]:
        """完整评分流程，返回所有中间结果"""
        # 1. 熵值计算
        e_debug = self.calc_E_debug(s)

        # 2. 词典占比计算
        p_debug = self.calc_P_debug(s)

        # 3. 基础分 + 最终分
        w = self.weights
        base = w['w_e'] * e_debug['E_final'] - w['w_p'] * p_debug['P']
        final = 1.0 / (1.0 + math.exp(-3.5 * (base - 0.45)))

        return {
            'input': s,
            'entropy': e_debug,
            'dictionary': p_debug,
            'weights': w,
            'base_score': base,
            'final_score': final,
            'decision': final >= 0.72  # 默认阈值
        }

    def print_debug(self, result: Dict[str, any]):
        """格式化输出调试信息"""
        s = result['input']
        print(f"\n{'=' * 80}")
        print(f"🔍 Input: '{s}'")
        print(f"{'=' * 80}")

        # 熵值部分
        e = result['entropy']
        print(f"\n📊 Entropy Calculation:")
        print(f"  ├─ Length              : {e['length']}")
        print(f"  ├─ Unique Characters   : {e['unique_chars']}")
        print(f"  ├─ H (Shannon)         : {e['H']:.4f}")
        print(f"  ├─ max_H               : {e['max_H']:.4f}")
        print(f"  ├─ E_raw               : {e['E_raw']:.4f}")
        print(f"  ├─ length_conf (σ)     : {e['length_conf']:.4f}")
        print(f"  └─ E_final             : {e['E_final']:.4f} = {e['E_raw']:.4f} × {e['length_conf']:.4f}")

        # 词典部分
        p = result['dictionary']
        print(f"\n📚 Dictionary Matching:")
        print(f"  ├─ alpha_only          : '{p['alpha_only']}' (L={p['L_alpha']})")
        print(f"  ├─ wordninja split     : {p['words_wn']}")
        print(f"  ├─ camelCase split     : {p['words_camel']}")
        print(f"  ├─ all_words (merged)  : {p['all_words']}")
        print(f"  ├─ valid_words (>3)    : {p['valid_words']}")
        print(f"  ├─ matched_words       : {p['matched_words']}")
        print(f"  ├─ matched_len         : {p['matched_len']}")
        print(f"  └─ P                   : {p['P']:.4f} = {p['matched_len']} / {p['L_alpha']}")

        # 评分部分
        w = result['weights']
        base = result['base_score']
        final = result['final_score']
        print(f"\n⚖️  Scoring:")
        print(f"  ├─ w_e × E_final       : {w['w_e']:.2f} × {e['E_final']:.4f} = {w['w_e'] * e['E_final']:+.4f}")
        print(f"  ├─ w_p × P             : {w['w_p']:.2f} × {p['P']:.4f} = {-w['w_p'] * p['P']:.4f} (neg)")
        print(f"  ├─ Base Score          : {base:+.4f}")
        print(f"  ├─ Sigmoid(β=3.5, μ=0.45)")
        print(f"  └─ Final Score         : {final:.4f}")

        # 决策
        thr = 0.72
        decision = "✅ SECRET" if final >= thr else "❌ benign"
        print(f"\n🎯 Decision (threshold={thr}): {decision}")
        print(f"{'=' * 80}\n")


def main():
    parser = argparse.ArgumentParser(description="Debug SecretMathScorer core logic")
    parser.add_argument('input', nargs='?', help='Single string or JSON list of strings')
    parser.add_argument('--file', '-f', type=str, help='Read inputs from file (one per line)')
    parser.add_argument('--threshold', '-t', type=float, default=0.72, help='Decision threshold (default: 0.72)')
    parser.add_argument('--weights', type=str, help='Custom weights as JSON: {"w_e":0.9, "w_p":1.0}')

    args = parser.parse_args()

    # 加载权重
    weights = {'w_e': 0.85, 'w_p': 1.2}
    if args.weights:
        try:
            weights.update(json.loads(args.weights))
        except:
            print(f"⚠️  Invalid weights JSON, using defaults: {weights}")

    scorer = DebugMathScorer(weights)

    # 收集输入
    inputs = []
    if args.file:
        with open(args.file, 'r', encoding='utf-8') as f:
            inputs = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    elif args.input:
        try:
            parsed = json.loads(args.input)
            if isinstance(parsed, list):
                inputs = parsed
            else:
                inputs = [parsed]
        except:
            inputs = [args.input]
    else:
        print("💡 Usage:")
        print("  python debug_scorer.py \"sk-proj-9aB2xK\"")
        print("  python debug_scorer.py '[\"SHA-256\", \"ABC...9\"]'")
        print("  python debug_scorer.py --file samples.txt")
        return

    # 批量处理
    for s in inputs:
        result = scorer.score_debug(s)
        scorer.print_debug(result)

        # 简单汇总
        if len(inputs) > 1:
            status = "✅" if result['final_score'] >= args.threshold else "❌"
            print(f"{status} '{s[:40]}{'...' if len(s) > 40 else ''}' → {result['final_score']:.4f}")


if __name__ == '__main__':
    main()