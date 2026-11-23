"""
Bilingual (Indonesian + English) NLP helpers: stopwords, clitic/reduplication normalization,
and lightweight cross-lingual domain synonym mapping for Automated GraphRAG.
"""
from __future__ import annotations

import re
from typing import Dict, List, Set

TOKEN_RE = re.compile(r"[a-z0-9][a-z0-9_-]{1,30}")

STOPWORDS_EN: Set[str] = {
    "the", "and", "for", "that", "this", "with", "from", "are", "was", "were",
    "have", "has", "had", "not", "but", "what", "which", "when", "where", "who",
    "how", "why", "can", "will", "would", "should", "could", "into", "over",
    "under", "between", "through", "during", "before", "after", "above", "below",
    "about", "against", "among", "throughout", "despite", "towards", "upon",
}

STOPWORDS_ID: Set[str] = {
    "yang", "dan", "di", "ke", "dari", "untuk", "dengan", "pada", "adalah", "ini",
    "itu", "atau", "sebagai", "dalam", "oleh", "akan", "telah", "sudah", "dapat",
    "bisa", "tidak", "bukan", "serta", "terhadap", "antara", "tentang", "melalui",
    "selama", "sebelum", "sesudah", "apa", "siapa", "kapan", "dimana", "mengapa",
    "kenapa", "bagaimana", "berapa", "mana", "tersebut", "secara", "agar", "karena",
    "sehingga", "namun", "tetapi", "tapi", "juga", "lagi", "masih", "sedang",
    "sangat", "lebih", "paling", "semua", "seluruh", "setiap", "suatu", "sebuah",
    "para", "yaitu", "yakni", "maupun", "hingga", "sampai", "saat", "ketika",
    "bila", "jika", "apabila", "supaya", "bahwa", "hal", "mereka", "kami", "kita",
    "anda", "hanya", "tanpa", "saja", "harus", "perlu", "belum", "kali", "banyak",
    "sedikit", "sama", "lain", "lainnya", "masing", "punya", "milik", "menjadi",
    "menunjukkan", "memberikan", "memiliki", "melakukan", "terjadi", "membuat",
    "ada", "adanya", "tiap", "bagi", "atas", "demi", "guna", "walau", "walaupun",
    "meski", "meskipun", "pun", "lah", "kah", "ialah", "merupakan",
}

STOPWORDS: Set[str] = STOPWORDS_EN | STOPWORDS_ID

GENERIC_QUERY_WORDS_EN: Set[str] = {
    "what", "which", "who", "whom", "whose", "where", "when", "why", "how",
    "did", "does", "do", "are", "was", "were", "the", "and", "for", "with",
    "impact", "impacted", "affected", "cause", "caused", "between", "across",
    "document", "documents", "report", "reported", "system", "company", "organization",
    "summary", "summarize", "overall", "themes", "trends", "communities", "main",
    "describe", "explain", "list", "show", "tell", "give", "find", "relationship",
}

GENERIC_QUERY_WORDS_ID: Set[str] = {
    "apa", "apakah", "bagaimana", "mengapa", "kenapa", "siapa", "siapakah", "kapan",
    "dimana", "jelaskan", "ringkas", "ringkasan", "rangkum", "rangkuman", "sebutkan",
    "tunjukkan", "berikan", "temukan", "cari", "dampak", "berdampak", "penyebab",
    "menyebabkan", "disebabkan", "sebab", "akibat", "hubungan", "keterkaitan",
    "terkait", "dokumen", "laporan", "sistem", "perusahaan", "organisasi", "regulasi",
    "peraturan", "utama", "keseluruhan", "tema", "tren", "risiko", "komunitas",
    "klaster", "jalur", "rantai", "memengaruhi", "mempengaruhi", "terhadap", "serta",
}

GENERIC_QUERY_WORDS: Set[str] = GENERIC_QUERY_WORDS_EN | GENERIC_QUERY_WORDS_ID

# Bidirectional Indonesian <-> English domain glossary for cross-lingual evidence alignment
_CROSS_LINGUAL_PAIRS = [
    ("insiden", "incident"),
    ("gangguan", "outage"),
    ("gangguan", "disruption"),
    ("penalti", "penalty"),
    ("denda", "penalty"),
    ("denda", "fine"),
    ("ketersediaan", "uptime"),
    ("ketersediaan", "availability"),
    ("peraturan", "regulation"),
    ("regulasi", "regulation"),
    ("kebijakan", "policy"),
    ("akuisisi", "acquired"),
    ("mengakuisisi", "acquired"),
    ("diakuisisi", "acquired"),
    ("pemasok", "vendor"),
    ("pemasok", "supplier"),
    ("pemulihan", "recovery"),
    ("kerugian", "loss"),
    ("kesalahan", "error"),
    ("keterlambatan", "latency"),
    ("latensi", "latency"),
    ("pembayaran", "payment"),
    ("keuangan", "financial"),
    ("kepatuhan", "compliance"),
    ("mitra", "partnered"),
    ("bermitra", "partnered"),
    ("mengoperasikan", "operates"),
    ("dioperasikan", "operates"),
    ("beroperasi", "operated"),
    ("bergantung", "depends"),
    ("dikembangkan", "developed"),
    ("mengembangkan", "developed"),
    ("pengembang", "developer"),
    ("perusahaan", "company"),
    ("perusahaan", "holdings"),
    ("jaringan", "network"),
    ("serat", "fiber"),
    ("menit", "minutes"),
    ("jam", "hours"),
    ("kuartal", "quarter"),
    ("oktober", "october"),
    ("januari", "january"),
    ("februari", "february"),
    ("maret", "march"),
    ("mei", "may"),
    ("juni", "june"),
    ("juli", "july"),
    ("agustus", "august"),
    ("desember", "december"),
    ("juta", "million"),
    ("miliar", "billion"),
    ("persen", "percent"),
    ("layanan", "service"),
    ("pusat", "center"),
    ("wilayah", "region"),
    ("arsitektur", "architecture"),
    ("keamanan", "security"),
    ("klien", "client"),
    ("nasabah", "customer"),
    ("risiko", "risk"),
    ("resiliensi", "resilience"),
    ("ketahanan", "resilience"),
]

CROSS_LINGUAL_SYNONYMS: Dict[str, Set[str]] = {}
for _id_term, _en_term in _CROSS_LINGUAL_PAIRS:
    CROSS_LINGUAL_SYNONYMS.setdefault(_id_term, set()).add(_en_term)
    CROSS_LINGUAL_SYNONYMS.setdefault(_en_term, set()).add(_id_term)


def normalize_token_variants(token: str) -> List[str]:
    """
    Normalize a single lowercase token safely for Indonesian + English matching:
    - preserves original token
    - extracts root from Indonesian reduplication (`dokumen-dokumen` -> `dokumen`)
    - strips Indonesian clitics (`-nya`, `-lah`, `-kah`, `-pun`) for tokens >= 6 chars
    """
    tok = token.strip().lower()
    if not tok:
        return []
    variants: List[str] = [tok]

    if "-" in tok:
        parts = tok.split("-")
        if len(parts) == 2 and parts[0] == parts[1] and len(parts[0]) >= 3 and parts[0] not in STOPWORDS:
            variants.append(parts[0])

    for suffix in ("nya", "lah", "kah", "pun"):
        if len(tok) >= 6 and tok.endswith(suffix):
            root = tok[: -len(suffix)]
            if len(root) >= 3 and root not in STOPWORDS and root not in variants:
                variants.append(root)
                break

    return variants


def tokenize_multilingual(text: str) -> List[str]:
    """Tokenize text into normalized Indonesian + English content terms for BM25 and hashing."""
    raw_tokens = TOKEN_RE.findall(text.lower())
    out: List[str] = []
    for tok in raw_tokens:
        if tok in STOPWORDS or len(tok) < 2:
            continue
        variants = normalize_token_variants(tok)
        primary = variants[-1] if len(variants) > 1 else variants[0]
        if primary not in STOPWORDS:
            out.append(primary)
    return out


def expand_cross_lingual_tokens(tokens: Set[str]) -> Set[str]:
    """Expand a token set with clitic roots and bilingual Indonesian<->English synonyms."""
    expanded: Set[str] = set()
    for tok in tokens:
        for v in normalize_token_variants(tok):
            expanded.add(v)
            if v in CROSS_LINGUAL_SYNONYMS:
                expanded.update(CROSS_LINGUAL_SYNONYMS[v])
    return expanded
