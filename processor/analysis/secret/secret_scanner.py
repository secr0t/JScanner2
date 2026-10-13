import json
import math
import os
import re
import sys
import time
from collections import Counter
from typing import List, Dict, Tuple, Any, Optional

import json_repair

from config.scanner_rules import HTTPX_STATIC_EXTENSIONS, EXCLUDED_CONTEXT_PATTERNS, SENSITIVE_KEYWORD_SET, EXCLUDED_LITERAL_VALUES, \
    SECRET_DETECTION_BLACKLIST, WEB_TECHNICAL_WORDS
from config.config import NLTK_DIR
from infra.bloom import DiskBloomFilter
from infra import watchdog
from infra.utils import remove_html_tags
from logger import get_logger
from processor.analysis.secret.prompt import SECRET_PROMPT
from processor.js.context.secret_extractor import SenInfoContextExtractor
from storage.db import SQLiteStorage

logger = get_logger(__name__)


try:
    import wordninja
    import nltk
    from nltk.corpus import wordnet, words

    try:
        from processor.js.format.js_formatter import format_code
    except ImportError:
        from js_formatter import format_code
except ImportError as e:
    sys.stderr.write(f"⚠️  Missing dependency: {e}\n")
    sys.exit(1)


def _init_nltk_offline():
    """纯离线 NLTK 数据初始化"""
    if NLTK_DIR not in nltk.data.path:
        nltk.data.path.insert(0, NLTK_DIR)

    required_data = {
        'wordnet': 'corpora/wordnet',
        'omw-1.4': 'corpora/omw-1.4',
        'words': 'corpora/words'
    }

    for package_name, search_path in required_data.items():
        try:
            nltk.data.find(search_path)
        except LookupError:
            logger.warning(f"[-] NLTK 本地缓存缺失 [{package_name}]，正在下载至：{NLTK_DIR}")
            try:
                os.makedirs(NLTK_DIR, exist_ok=True)
                nltk.download(package_name, download_dir=NLTK_DIR, quiet=True)
            except Exception as e:
                logger.warning(f"❌ NLTK 下载失败 {package_name}: {str(e)}")


class CodeLineFilter:
    def __init__(self, min_string_length=5, min_sensitive_length=5, max_string_length=1000, blacklist: Optional[List[str]] = None):
        self.min_string_length = min_string_length
        self.min_sensitive_length = min_sensitive_length
        self.max_string_length = max_string_length

        self.DEFAULT_BLACKLIST = SECRET_DETECTION_BLACKLIST
        
        combined_blacklist = list(self.DEFAULT_BLACKLIST)
        if blacklist:
            combined_blacklist.extend(blacklist)
        
        self.blacklist = set(combined_blacklist)
        self.blacklist_pattern = re.compile(
            '|'.join(re.escape(item) for item in self.blacklist), 
            re.IGNORECASE
        ) if self.blacklist else None

        self.static_resource_extensions = tuple(HTTPX_STATIC_EXTENSIONS)

    def extract_candidates(self, js_code: str) -> List[Tuple[str, str]]:
        QUOTE_PATTERN = re.compile(r'(["\'])(.*?)\1')  # 提取引号内容
        if not js_code:
            return []
        string_candidates = set()
        for line in js_code.splitlines():
            original_line = line.strip()
            if not original_line or len(original_line) > 3500:
                continue
            if '"' not in original_line and "'" not in original_line:
                continue

            line_lower = original_line.lower()
            is_bad_context = any(ctx in line_lower for ctx in EXCLUDED_CONTEXT_PATTERNS)
            has_sensitive_keyword = any(kw in line_lower for kw in SENSITIVE_KEYWORD_SET)

            if is_bad_context and not has_sensitive_keyword:
                continue

            for _, content in QUOTE_PATTERN.findall(original_line):
                content = content.strip()
                if self._is_valid_content(content, original_line, has_sensitive_keyword):
                    string_candidates.add((content, original_line))
        return list(string_candidates)

    def _is_valid_content(self, content: str, original_line: str, has_sensitive_keyword: bool) -> bool:
        IGNORE_PREFIX_PATTERN = re.compile(
            r'^[\W_]*(chunk-|app-|vendors-|manifest-|data-v-|vue-|bg-|text-|border-|font-|col-|row-|flex-|grid-|btn-|icon-|fa-|el-|mat-)',
            re.IGNORECASE
        )
        re.compile(r'(["\'])(.*?)\1')
        UNICODE_PATTERN = re.compile(r'(\\)+u[0-9a-fA-F]{4}')  # 匹配Unicode转义

        content_len = len(content)
        if content_len > self.max_string_length:
            return False

        if self.blacklist_pattern and self.blacklist_pattern.search(content):
            return False

        if content.lower().endswith(self.static_resource_extensions) and content_len < 50:
            return False

        non_ascii_ratio = sum(1 for c in content if ord(c) > 127) / content_len if content_len > 0 else 0
        if non_ascii_ratio > 0.15:
            return False

        if re.search(r'[\u4e00-\u9fff]{2,}', content):
            return False

        if content.startswith('#') and '-' in content:
            return False


        min_len = self.min_sensitive_length if has_sensitive_keyword else self.min_string_length
        if content_len < min_len:
            return False
        if IGNORE_PREFIX_PATTERN.match(content):
            return False
        if any(c in content for c in [' ', '<', '>', '\\', '__', '(', ')']):
            return False

        special_count = sum(1 for c in content if not c.isalnum())
        if content_len > 0 and (special_count / content_len) > 0.2:
            return False
        if len(UNICODE_PATTERN.findall(content)) >= 3:
            return False
        if sum(1 for c in content if ord(c) > 127) > content_len * 0.3:
            return False
        if content in EXCLUDED_LITERAL_VALUES:
            return False
        if content.isdigit() and content_len < 8:
            return False

        if not has_sensitive_keyword:
            if not any(char in original_line for char in ['=', ':', '{', '(', ',']):
                return False
        return True


class SecretMathScorer:
    """纯数学/统计学驱动的敏感信息评分器 (V6.0 极简双特征版)"""

    _nltk_initialized = False


    def __init__(self, weights: Optional[Dict[str, float]] = None):
        if not SecretMathScorer._nltk_initialized:
            _init_nltk_offline()
            SecretMathScorer._nltk_initialized = True

        self.weights = weights or {'w_e': 0.85, 'w_p': 1.2}
        self._cache = {}
        self._local_logger = get_logger("SecretMathScorer")

        try:
            nltk_words = set(w.lower() for w in words.words())
            self.valid_words_set = nltk_words.union(WEB_TECHNICAL_WORDS)
        except:
            logger.warning("NLTK words loading failed, using TECH_WORDS instead.")
            self.valid_words_set = WEB_TECHNICAL_WORDS

    def _log2(self, x):
        return math.log2(x) if x > 0 else 0.0

    def calc_E(self, s: str) -> float:
        L = len(s)
        if L == 0: return 0.0
        cnt = Counter(s)
        H = -sum((c / L) * self._log2(c / L) for c in cnt.values())
        max_H = self._log2(min(L, len(cnt)))
        E_raw = H / max_H if max_H > 0 else 0.0

        # Sigmoid 曲线：L=7 时系数≈0.4, L=12 时≈0.73, L=20 时≈0.95
        length_confidence = 1.0 / (1.0 + math.exp(-0.3 * (L - 12)))
        return E_raw * length_confidence

    def _camel_split(self, s: str) -> List[str]:
        """驼峰切分：基于原始字符串，保留大小写边界信号"""
        parts = re.findall(r'[A-Z]?[a-z]+|[A-Z]+(?=[A-Z]|$)', s)
        return [p for p in parts if p]  # 不转小写，后续统一处理

    def _wordninja_split(self, s: str) -> List[str]:
        """wordninja 分词，带异常处理"""
        try:
            import wordninja
            return wordninja.split(s)
        except:
            return []

    def calc_P(self, s: str) -> float:
        alpha_only = re.sub(r'[^a-zA-Z]', '', s).lower()
        L_alpha = len(alpha_only)
        if L_alpha < 4: return 0.0

        # 路 1: wordninja 分词
        words_wn = self._wordninja_split(alpha_only)

        # 路 2: 驼峰切分
        words_camel = self._camel_split(alpha_only)

        # 融合：取并集，去重
        all_words = list(set(words_wn + words_camel))

        # 过滤短词 + 词典匹配
        valid_words = [w for w in all_words if len(w) > 3]
        matched_len = sum(len(w) for w in valid_words if w in self.valid_words_set)

        return min(matched_len / L_alpha, 1.0)

    def score(self, s: str) -> Dict[str, float]:
        if s in self._cache: return self._cache[s]

        E = self.calc_E(s)
        P = self.calc_P(s)
        w = self.weights

        # 核心公式不变
        base = w['w_e'] * E - w['w_p'] * P
        final = 1.0 / (1.0 + math.exp(-3.5 * (base - 0.45)))

        res = {'score': final, 'E': E, 'P': P}
        self._cache[s] = res
        return res

class AdvancedSecretFilter:
    def __init__(self, threshold: float = 0.75, weights: Optional[Dict[str, float]] = None):
        self.threshold = threshold
        self.scorer = SecretMathScorer(weights)
        self.code_syntax_indicators = {'${', '||', '&&', '?', '+=', '-=', '===', '!==', '?.', '??', '=>'}
        self.sensitive_keywords = SENSITIVE_KEYWORD_SET
        self._local_logger = get_logger("AdvancedSecretFilter")

    def shannon_entropy(self, data: str) -> float:
        return self.scorer.calc_E(data) * math.log2(len(data)) if len(data) > 0 else 0.0

    def is_secret(self, text: str) -> bool:
        if re.match(r'^\.{0,2}/[a-zA-Z0-9_./-]+$', text): return False
        if not text or len(text) <= 6: return False
        res = self.scorer.score(text)
        score = res['score']

        L = len(text)
        thr = self.threshold * (0.9 if L < 16 else (1.1 if L > 100 else 1.0))

        # 关键词提权
        if any(kw in text.lower() for kw in self.sensitive_keywords):
            score = min(score * 1.2, 1.0)

        result = score >= thr
        return result

    def get_debug_info(self, text: str) -> Dict:
        return self.scorer.score(text)


class LLMSecretVerifier:
    def __init__(self, client, max_retries=2, retry_delay=1.0):
        self.client = client
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self._local_logger = get_logger("LLMSecretVerifier")

    def verify_with_context(self, candidates: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """使用 LLM 验证候选敏感信息"""
        if not candidates:
            return []
        
        return self._verify_with_single_api(candidates)
    
    def _verify_with_single_api(self, candidates: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """单调用逻辑"""
        input_data = self._format_candidates_for_single(candidates)
        analysis_result = self._call_llm(input_data)
        if not analysis_result:
            return []
        return self._parse_and_merge(candidates, analysis_result)
    
    def _format_candidates_for_single(self, candidates: List[Dict[str, Any]]) -> str:
        """格式化多个候选对象用于单次调用"""
        formatted = {}
        for cand in candidates:
            cand_id = str(cand.get("id", ""))
            formatted[cand_id] = {
                "value": cand.get("value", ""),
                "context": cand.get("context", ""),
                "callers": cand.get("callers", [])
            }
        return json.dumps(formatted, ensure_ascii=False, indent=2)

    def _call_llm(self, input_data: str) -> Dict[str, Any]:
        messages = [
            {"role": "system", "content": SECRET_PROMPT},
            {"role": "user", "content": f"Analyze these hardcoded values:\n\n{input_data}"}
        ]
        for attempt in range(self.max_retries + 1):
            try:
                content = self.client.chat(messages=messages, max_tokens=2048, temperature=0.1)
                json_str = self._extract_json(content)
                if json_str: return json_repair.loads(json_str)
                else: self._local_logger.warning(f"⚠️ [LLM] 未找到有效 JSON (Attempt {attempt + 1})")
            except Exception as e:
                self._local_logger.warning(f"⚠️ [LLM] 调用失败 (Attempt {attempt + 1}/{self.max_retries}): {e}")
                if attempt < self.max_retries: time.sleep(self.retry_delay * (attempt + 1))
        self._local_logger.error("❌ [LLM] 所有重试失败...")
        return {}

    def _extract_json(self, content: str) -> Optional[str]:
        try:
            json_repair.loads(content)
            return content
        except json.JSONDecodeError: pass
        match = re.search(r'```json\s*(.*?)\s*```', content, re.DOTALL)
        if match: return match.group(1)
        match = re.search(r'\{.*\}', content, re.DOTALL)
        if match: return match.group()
        return None

    def _parse_and_merge(self, candidates: List[Dict[str, Any]], analysis_result: Dict[str, Any]) -> List[Dict[str, Any]]:
        verified = []
        for cand in candidates:
            cand_id = str(cand.get("id", ""))
            ai_result = analysis_result.get(cand_id, {})
            is_secret = ai_result.get("is_secret", 1)
            result = {
                **cand, "is_secret": bool(is_secret) if isinstance(is_secret, int) else is_secret,
                "secret_type": ai_result.get("secret_type", "unknown"),
                "risk_level": ai_result.get("risk_level", "Low"),
                "confidence": float(ai_result.get("confidence", 0.5)),
                "test_suggestion": ai_result.get("test_suggestion", ""),
                "ai_raw_analysis": {
                    "is_secret": ai_result.get("is_secret", 1),
                    "secret_type": ai_result.get("secret_type", "unknown"),
                    "risk_level": ai_result.get("risk_level", "Low"),
                    "confidence": ai_result.get("confidence", 0.5),
                    "test_suggestion": ai_result.get("test_suggestion", "")
                }
            }
            if result["is_secret"]: verified.append(result)
        return verified


class SensitiveInfoScanner:

    def __init__(self, client, db: Optional[SQLiteStorage] = None, max_ast_analysis=50, max_llm=80):
        self.client = client
        self.db = db
        self.max_ast_analysis = max_ast_analysis
        self.max_llm = max_llm
        self.line_filter = CodeLineFilter()
        self.adv_filter = AdvancedSecretFilter(threshold=0.75)
        self.llm_verifier = LLMSecretVerifier(client)
        self.ast_available = SenInfoContextExtractor is not None
        self._local_logger = get_logger("SensitiveInfoScanner")

    def scan(self, js_code: str, js_url: str = "") -> List[Dict[str, Any]]:
        if not js_code: return []
        watchdog.beat("secret_scan", js_url)     # 每个 JS 文件一次真进展
        js_code = self._preprocess(js_code)
        candidates = self._extract_candidates(js_code)
        # logger.info(f"[SCAN] Extracted {len(candidates)} candidates after math filtering")
        if not candidates: return []
        if self.ast_available: candidates = self._enrich_with_ast(candidates, js_code)
        if len(candidates) > self.max_llm: candidates = self._priority_sort(candidates)[:self.max_llm]
        verified = self._verify_with_llm(candidates)
        if self.db and js_url and verified is not None: self.db.save_sensitive_info(js_url, verified)
        return verified

    def _preprocess(self, js_code: str) -> str:
        js_code = remove_html_tags(js_code)
        try:
            watchdog.beat("secret_format", "prettier")   # 格式化前喂狗，超大JS慢也不误判
            js_code = format_code(js_code, fallback_on_error=True)
        except Exception as e: logger.error(f"⚠️ 代码格式化失败：{e}")
        return js_code

    def _extract_candidates(self, js_code: str) -> List[Dict[str, Any]]:
        raw_candidates = self.line_filter.extract_candidates(js_code)
        candidate_objects = []
        for i, (content, line) in enumerate(raw_candidates):
            if self.adv_filter.is_secret(content):
                if _AI_CANDIDATE_DEDUP.contains(content): continue
                _AI_CANDIDATE_DEDUP.add(content)
                candidate_objects.append({"id": i, "value": content, "original_line": line, "context": "", "callers": []})
        return candidate_objects

    def _enrich_with_ast(self, candidates: List[Dict[str, Any]], js_code: str) -> List[Dict[str, Any]]:
        try:
            extractor = SenInfoContextExtractor(js_code)
            if len(candidates) > self.max_ast_analysis: candidates = self._priority_sort(candidates)[:self.max_ast_analysis]
            for cand in candidates:
                context = extractor.get_full_context(cand["value"])
                cand["context"] = context.get("declaration", "")
                cand["callers"] = context.get("callers", [])
        except Exception as e:
            logger.error(f"⚠️ AST 上下文提取失败：{e}")
        return candidates

    def _priority_sort(self, candidates: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        def priority_score(cand):
            value_lower = cand.get("value", "").lower()
            line_lower = cand.get("original_line", "").lower()
            score = 0
            for kw in SENSITIVE_KEYWORD_SET:
                if kw in value_lower or kw in line_lower: score += 10
            score += int(self.adv_filter.shannon_entropy(cand.get("value", "")) * 2)
            return score
        return sorted(candidates, key=priority_score, reverse=True)

    def _verify_with_llm(self, candidates: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        if not candidates: return []
        logger.info(f"🚀 Sending {len(candidates)} candidates to LLM...")
        batch_size = 20
        all_verified = []
        for i in range(0, len(candidates), batch_size):
            batch = candidates[i:i + batch_size]
            batch_num = i // batch_size + 1
            total_batches = (len(candidates) + batch_size - 1) // batch_size
            logger.info(f"🧠 [LLM] 处理批次 {batch_num}/{total_batches} ({len(batch)} 项)")
            watchdog.beat("secret_llm", f"batch {batch_num}/{total_batches}")
            try:
                verified_batch = self.llm_verifier.verify_with_context(batch)
                if verified_batch is None: continue
                all_verified.extend(verified_batch)
            except Exception as e:
                self._local_logger.error(f"❌ [LLM] 批次 {batch_num} 处理失败：{e}")
                for cand in batch:
                    cand.update({"is_secret": True, "secret_type": "unknown", "risk_level": "Med", "confidence": 0.3,
                                 "test_suggestion": "LLM 分析失败，建议人工审查", "ai_raw_analysis": {"error": str(e)}})
                    all_verified.append(cand)
        final_results = []
        seen_lines = set()
        for res in all_verified:
            line = res.get("original_line", "")
            if line not in seen_lines:
                if _OUTPUT_LINE_DEDUP.contains(line): continue
                _OUTPUT_LINE_DEDUP.add(line)
                seen_lines.add(line)
                final_results.append(res)
        return final_results


def cleanup_bloom_filters():
    _AI_CANDIDATE_DEDUP.close()
    _OUTPUT_LINE_DEDUP.close()
    _WORD_ANALYSIS_DEDUP.close()

_AI_CANDIDATE_DEDUP = DiskBloomFilter("Result/ai_candidates.bloom", capacity=5_000_000)
_OUTPUT_LINE_DEDUP = DiskBloomFilter("Result/output_lines.bloom", capacity=5_000_000)
_WORD_ANALYSIS_DEDUP = DiskBloomFilter("Result/word_analysis.bloom", capacity=10_000_000)