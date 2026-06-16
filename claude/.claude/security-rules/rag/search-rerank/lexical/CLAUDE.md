# CLAUDE.md - Lexical Search Security Rules (BM25, TF-IDF)

Security rules for lexical search implementations including BM25, TF-IDF, and hybrid search systems.

**Prerequisites**: `rules/_core/rag-security.md`, `rules/rag/_core/retrieval-security.md`

**Applies to**: rank-bm25, Elasticsearch BM25, Whoosh, and similar lexical search implementations

---

## Rule: BM25 Query Sanitization

**Level**: `strict`

**When**: Accepting user queries for BM25/lexical search

**Do**: Sanitize and validate query inputs to prevent keyword injection attacks

```python
import re
from typing import List
from rank_bm25 import BM25Okapi

class SecureBM25Search:
    # Whitelist allowed characters
    ALLOWED_PATTERN = re.compile(r'^[\w\s\-\.\,\?\!]+$', re.UNICODE)
    MAX_QUERY_LENGTH = 500
    MAX_TERMS = 50

    # Dangerous patterns that could manipulate ranking
    INJECTION_PATTERNS = [
        r'\b(AND|OR|NOT|TO|FROM)\b',  # Boolean operators
        r'[\[\]\{\}\(\)\*\?\~\^]',     # Lucene special chars
        r'[\"\'\\]',                   # Quote injection
        r'\s{3,}',                     # Excessive whitespace
    ]

    def __init__(self, corpus: List[List[str]]):
        self.bm25 = BM25Okapi(corpus)

    def sanitize_query(self, query: str) -> str:
        """Sanitize query to prevent injection attacks."""
        # Length check
        if len(query) > self.MAX_QUERY_LENGTH:
            raise ValueError(f"Query exceeds maximum length of {self.MAX_QUERY_LENGTH}")

        # Check for injection patterns
        for pattern in self.INJECTION_PATTERNS:
            if re.search(pattern, query, re.IGNORECASE):
                query = re.sub(pattern, ' ', query, flags=re.IGNORECASE)

        # Validate allowed characters
        if not self.ALLOWED_PATTERN.match(query):
            # Remove disallowed characters
            query = re.sub(r'[^\w\s\-\.\,\?\!]', '', query)

        # Normalize whitespace
        query = ' '.join(query.split())

        return query

    def tokenize_query(self, query: str) -> List[str]:
        """Tokenize with term limit."""
        tokens = query.lower().split()
        if len(tokens) > self.MAX_TERMS:
            tokens = tokens[:self.MAX_TERMS]
        return tokens

    def search(self, query: str, top_k: int = 10) -> List[tuple]:
        """Secure search with sanitization."""
        sanitized = self.sanitize_query(query)
        tokens = self.tokenize_query(sanitized)

        if not tokens:
            return []

        scores = self.bm25.get_scores(tokens)
        top_indices = sorted(range(len(scores)),
                            key=lambda i: scores[i],
                            reverse=True)[:top_k]

        return [(idx, scores[idx]) for idx in top_indices]
```

**Don't**: Pass user input directly to BM25 without sanitization

```python
from rank_bm25 import BM25Okapi

# VULNERABLE: No input sanitization
def search(query: str, bm25: BM25Okapi):
    # Direct user input - allows keyword stuffing, injection
    tokens = query.lower().split()
    scores = bm25.get_scores(tokens)
    return scores

# VULNERABLE: Elasticsearch without query sanitization
def es_search(query: str, es_client):
    # Direct injection into Elasticsearch query
    return es_client.search(
        index="documents",
        body={
            "query": {
                "match": {
                    "content": query  # Unvalidated input
                }
            }
        }
    )
```

**Why**: Unsanitized queries enable keyword injection attacks where adversaries craft queries with repeated terms, boolean operators, or special characters to manipulate BM25 scores. Attackers can boost irrelevant documents or suppress legitimate results by exploiting term frequency calculations.

**Refs**: CWE-20 (Improper Input Validation), CWE-943 (Improper Neutralization of Special Elements in Data Query Logic)

---

## Rule: TF-IDF Score Manipulation Prevention

**Level**: `strict`

**When**: Computing TF-IDF scores for document ranking

**Do**: Implement score normalization and anomaly detection to prevent manipulation

```python
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from typing import List, Tuple

class SecureTfidfSearch:
    MAX_TERM_FREQUENCY = 100  # Cap per-document term frequency
    MAX_SCORE_THRESHOLD = 0.95  # Suspiciously high scores
    MIN_DF = 2  # Minimum document frequency
    MAX_DF = 0.85  # Maximum document frequency ratio

    def __init__(self, max_features: int = 10000):
        self.vectorizer = TfidfVectorizer(
            max_features=max_features,
            min_df=self.MIN_DF,
            max_df=self.MAX_DF,
            sublinear_tf=True,  # Dampen term frequency impact
            norm='l2'  # Normalize vectors
        )
        self.tfidf_matrix = None
        self.document_scores = {}

    def fit(self, documents: List[str], document_ids: List[str]):
        """Fit vectorizer with manipulation detection."""
        # Check for term stuffing in documents
        cleaned_docs = []
        for doc_id, doc in zip(document_ids, documents):
            cleaned = self._detect_term_stuffing(doc, doc_id)
            cleaned_docs.append(cleaned)

        self.tfidf_matrix = self.vectorizer.fit_transform(cleaned_docs)
        self.document_ids = document_ids

        # Detect anomalous document scores
        self._detect_score_anomalies()

    def _detect_term_stuffing(self, document: str, doc_id: str) -> str:
        """Detect and mitigate term stuffing attacks."""
        words = document.lower().split()
        word_counts = {}

        for word in words:
            word_counts[word] = word_counts.get(word, 0) + 1

        # Cap excessive term frequencies
        capped_words = []
        current_counts = {}

        for word in words:
            current_counts[word] = current_counts.get(word, 0) + 1
            if current_counts[word] <= self.MAX_TERM_FREQUENCY:
                capped_words.append(word)

        if len(capped_words) < len(words):
            # Log potential manipulation attempt
            print(f"Warning: Term frequency capped for document {doc_id}")

        return ' '.join(capped_words)

    def _detect_score_anomalies(self):
        """Detect documents with anomalously high TF-IDF scores."""
        if self.tfidf_matrix is None:
            return

        # Check for documents with suspicious score distributions
        max_scores = np.max(self.tfidf_matrix.toarray(), axis=1)

        for idx, score in enumerate(max_scores):
            if score > self.MAX_SCORE_THRESHOLD:
                doc_id = self.document_ids[idx]
                self.document_scores[doc_id] = {
                    'max_score': score,
                    'flagged': True
                }
                print(f"Warning: Document {doc_id} has anomalously high TF-IDF score: {score}")

    def search(self, query: str, top_k: int = 10) -> List[Tuple[str, float]]:
        """Search with score validation."""
        query_vec = self.vectorizer.transform([query])
        scores = (self.tfidf_matrix @ query_vec.T).toarray().flatten()

        # Apply penalty to flagged documents
        for idx, doc_id in enumerate(self.document_ids):
            if doc_id in self.document_scores and self.document_scores[doc_id]['flagged']:
                scores[idx] *= 0.5  # Reduce score of suspicious documents

        top_indices = np.argsort(scores)[-top_k:][::-1]

        return [(self.document_ids[i], scores[i]) for i in top_indices]
```

**Don't**: Use raw TF-IDF without normalization or anomaly detection

```python
from sklearn.feature_extraction.text import TfidfVectorizer

# VULNERABLE: No protection against score manipulation
vectorizer = TfidfVectorizer()  # No min_df, max_df limits
tfidf_matrix = vectorizer.fit_transform(documents)

# VULNERABLE: No term frequency caps
def compute_tfidf(documents):
    # Allows term stuffing to inflate scores
    vectorizer = TfidfVectorizer(
        sublinear_tf=False,  # Linear TF allows easy manipulation
        norm=None  # No normalization
    )
    return vectorizer.fit_transform(documents)
```

**Why**: Without normalization and anomaly detection, attackers can stuff documents with repeated terms to artificially inflate TF-IDF scores. This allows malicious content to rank higher than legitimate results, enabling SEO-style attacks on search systems.

**Refs**: CWE-20 (Improper Input Validation), OWASP Information Disclosure

---

## Rule: Index Poisoning Prevention

**Level**: `strict`

**When**: Adding documents to lexical search indices

**Do**: Validate document content and implement integrity checks before indexing

```python
import hashlib
import re
from typing import Dict, List, Optional
from datetime import datetime

class SecureIndexManager:
    MAX_DOCUMENT_SIZE = 100000  # 100KB
    MAX_UNIQUE_TERMS = 5000
    MIN_TERM_LENGTH = 2
    MAX_TERM_LENGTH = 50
    SUSPICIOUS_PATTERNS = [
        r'(.)\1{10,}',  # Repeated characters
        r'(\b\w+\b)(?:\s+\1){5,}',  # Repeated words
        r'[\x00-\x08\x0b\x0c\x0e-\x1f]',  # Control characters
    ]

    def __init__(self):
        self.document_hashes: Dict[str, str] = {}
        self.index_audit_log: List[Dict] = []

    def validate_document(self, doc_id: str, content: str,
                         source: str, user_id: str) -> bool:
        """Validate document before indexing."""
        # Size check
        if len(content.encode('utf-8')) > self.MAX_DOCUMENT_SIZE:
            self._log_rejection(doc_id, "Document exceeds size limit", user_id)
            return False

        # Check for suspicious patterns
        for pattern in self.SUSPICIOUS_PATTERNS:
            if re.search(pattern, content):
                self._log_rejection(doc_id, f"Suspicious pattern detected: {pattern}", user_id)
                return False

        # Term validation
        terms = content.lower().split()
        unique_terms = set(terms)

        if len(unique_terms) > self.MAX_UNIQUE_TERMS:
            self._log_rejection(doc_id, "Excessive unique terms", user_id)
            return False

        # Check term lengths
        for term in unique_terms:
            if len(term) < self.MIN_TERM_LENGTH or len(term) > self.MAX_TERM_LENGTH:
                continue  # Skip invalid terms but don't reject

        # Compute integrity hash
        doc_hash = hashlib.sha256(content.encode()).hexdigest()

        # Check for duplicate content
        if doc_hash in self.document_hashes.values():
            self._log_rejection(doc_id, "Duplicate content detected", user_id)
            return False

        # Store hash for integrity verification
        self.document_hashes[doc_id] = doc_hash

        # Log successful indexing
        self._log_indexing(doc_id, source, user_id, doc_hash)

        return True

    def _log_rejection(self, doc_id: str, reason: str, user_id: str):
        """Log document rejection."""
        self.index_audit_log.append({
            'timestamp': datetime.utcnow().isoformat(),
            'action': 'rejected',
            'doc_id': doc_id,
            'reason': reason,
            'user_id': user_id
        })

    def _log_indexing(self, doc_id: str, source: str,
                     user_id: str, doc_hash: str):
        """Log successful indexing."""
        self.index_audit_log.append({
            'timestamp': datetime.utcnow().isoformat(),
            'action': 'indexed',
            'doc_id': doc_id,
            'source': source,
            'user_id': user_id,
            'hash': doc_hash
        })

    def verify_integrity(self, doc_id: str, content: str) -> bool:
        """Verify document hasn't been tampered with."""
        if doc_id not in self.document_hashes:
            return False

        current_hash = hashlib.sha256(content.encode()).hexdigest()
        return current_hash == self.document_hashes[doc_id]
```

**Don't**: Index documents without validation or integrity tracking

```python
# VULNERABLE: No document validation
def add_to_index(doc_id: str, content: str, index):
    # Direct indexing without checks
    index.add_document(doc_id, content)

# VULNERABLE: No integrity verification
def index_documents(documents: list, whoosh_index):
    writer = whoosh_index.writer()
    for doc in documents:
        # No validation, size limits, or pattern detection
        writer.add_document(
            id=doc['id'],
            content=doc['content']
        )
    writer.commit()
```

**Why**: Index poisoning allows attackers to inject malicious documents that manipulate search results. Without validation, adversaries can add term-stuffed content, duplicate documents, or content with hidden patterns designed to bias rankings toward attacker-controlled results.

**Refs**: CWE-20 (Improper Input Validation), MITRE ATLAS AML.T0020 (Poisoning Attacks)

---

## Rule: Hybrid Search Coordination Security

**Level**: `strict`

**When**: Combining vector and lexical search results

**Do**: Implement secure score normalization and result fusion with validation

```python
import numpy as np
from typing import List, Tuple, Dict
from dataclasses import dataclass

@dataclass
class SearchResult:
    doc_id: str
    score: float
    source: str  # 'vector' or 'lexical'

class SecureHybridSearch:
    def __init__(self, vector_weight: float = 0.5, lexical_weight: float = 0.5):
        if not (0 <= vector_weight <= 1 and 0 <= lexical_weight <= 1):
            raise ValueError("Weights must be between 0 and 1")
        if abs(vector_weight + lexical_weight - 1.0) > 0.01:
            raise ValueError("Weights must sum to 1")

        self.vector_weight = vector_weight
        self.lexical_weight = lexical_weight
        self.score_history: Dict[str, List[float]] = {}

    def normalize_scores(self, scores: List[float], source: str) -> List[float]:
        """Min-max normalize scores to [0, 1] range."""
        if not scores:
            return []

        scores_array = np.array(scores)
        min_score = scores_array.min()
        max_score = scores_array.max()

        if max_score - min_score < 1e-10:
            return [0.5] * len(scores)  # All same score

        normalized = (scores_array - min_score) / (max_score - min_score)

        # Validate normalization
        if np.any(normalized < 0) or np.any(normalized > 1):
            raise ValueError(f"Score normalization failed for {source}")

        return normalized.tolist()

    def reciprocal_rank_fusion(self,
                               vector_results: List[SearchResult],
                               lexical_results: List[SearchResult],
                               k: int = 60) -> List[Tuple[str, float]]:
        """Secure RRF implementation with validation."""
        rrf_scores: Dict[str, float] = {}

        # Process vector results
        for rank, result in enumerate(vector_results):
            if result.doc_id not in rrf_scores:
                rrf_scores[result.doc_id] = 0
            rrf_scores[result.doc_id] += self.vector_weight / (k + rank + 1)

        # Process lexical results
        for rank, result in enumerate(lexical_results):
            if result.doc_id not in rrf_scores:
                rrf_scores[result.doc_id] = 0
            rrf_scores[result.doc_id] += self.lexical_weight / (k + rank + 1)

        # Sort and validate
        sorted_results = sorted(rrf_scores.items(),
                               key=lambda x: x[1],
                               reverse=True)

        # Detect anomalous score distributions
        self._detect_fusion_anomalies(sorted_results)

        return sorted_results

    def linear_combination(self,
                          vector_results: List[SearchResult],
                          lexical_results: List[SearchResult]) -> List[Tuple[str, float]]:
        """Secure linear combination with normalized scores."""
        # Normalize both result sets
        vector_scores = [r.score for r in vector_results]
        lexical_scores = [r.score for r in lexical_results]

        norm_vector = self.normalize_scores(vector_scores, 'vector')
        norm_lexical = self.normalize_scores(lexical_scores, 'lexical')

        # Combine scores
        combined: Dict[str, float] = {}

        for result, norm_score in zip(vector_results, norm_vector):
            combined[result.doc_id] = self.vector_weight * norm_score

        for result, norm_score in zip(lexical_results, norm_lexical):
            if result.doc_id in combined:
                combined[result.doc_id] += self.lexical_weight * norm_score
            else:
                combined[result.doc_id] = self.lexical_weight * norm_score

        # Validate combined scores
        for doc_id, score in combined.items():
            if score < 0 or score > 1:
                raise ValueError(f"Invalid combined score for {doc_id}: {score}")

        return sorted(combined.items(), key=lambda x: x[1], reverse=True)

    def _detect_fusion_anomalies(self, results: List[Tuple[str, float]]):
        """Detect anomalous patterns in fused results."""
        if len(results) < 2:
            return

        scores = [r[1] for r in results]

        # Check for suspicious score clustering
        score_std = np.std(scores)
        if score_std < 0.001:  # All scores nearly identical
            print("Warning: Anomalously uniform fusion scores detected")

        # Check for extreme score gaps
        top_score = scores[0]
        second_score = scores[1] if len(scores) > 1 else 0

        if top_score > 0 and (top_score - second_score) / top_score > 0.9:
            print(f"Warning: Extreme score gap detected - top: {top_score}, second: {second_score}")
```

**Don't**: Combine search results without normalization or validation

```python
# VULNERABLE: No score normalization
def hybrid_search(vector_results, lexical_results):
    combined = {}

    # Different score scales mixed directly
    for doc_id, score in vector_results:
        combined[doc_id] = score * 0.5

    for doc_id, score in lexical_results:
        # BM25 scores (0-20+) vs cosine similarity (0-1)
        combined[doc_id] = combined.get(doc_id, 0) + score * 0.5

    return sorted(combined.items(), key=lambda x: x[1], reverse=True)

# VULNERABLE: No weight validation
class UnsafeHybridSearch:
    def __init__(self, vector_weight, lexical_weight):
        # Accepts any values, including negative or >1
        self.vector_weight = vector_weight
        self.lexical_weight = lexical_weight
```

**Why**: Without proper score normalization, attackers can exploit scale differences between vector and lexical scores. BM25 scores (unbounded) mixed with cosine similarity (0-1) allows manipulation by inflating one search type. Improper fusion enables ranking attacks across the hybrid search pipeline.

**Refs**: CWE-20 (Improper Input Validation), CWE-682 (Incorrect Calculation)

---

## Rule: Stopword and Tokenizer Security

**Level**: `warning`

**When**: Configuring tokenizers and stopword lists for lexical search

**Do**: Use validated, immutable stopword lists and secure tokenizer configurations

```python
import re
from typing import List, Set, FrozenSet
from functools import lru_cache

class SecureTokenizer:
    # Immutable default stopwords - cannot be modified at runtime
    DEFAULT_STOPWORDS: FrozenSet[str] = frozenset([
        'the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for',
        'of', 'with', 'by', 'from', 'as', 'is', 'was', 'are', 'were', 'been',
        'be', 'have', 'has', 'had', 'do', 'does', 'did', 'will', 'would',
        'could', 'should', 'may', 'might', 'must', 'shall', 'this', 'that',
        'these', 'those', 'i', 'you', 'he', 'she', 'it', 'we', 'they'
    ])

    # Maximum custom stopwords to prevent DoS
    MAX_CUSTOM_STOPWORDS = 100

    # Secure token pattern - alphanumeric only
    TOKEN_PATTERN = re.compile(r'\b[a-zA-Z0-9]+\b')

    # Disallowed patterns in stopword lists
    DANGEROUS_STOPWORD_PATTERNS = [
        r'^.{1}$',  # Single character (too aggressive)
        r'^\d+$',   # Pure numbers
        r'^.{50,}$',  # Excessively long terms
    ]

    def __init__(self, custom_stopwords: List[str] = None):
        self.stopwords = set(self.DEFAULT_STOPWORDS)

        if custom_stopwords:
            self._add_custom_stopwords(custom_stopwords)

    def _add_custom_stopwords(self, custom: List[str]):
        """Add validated custom stopwords."""
        if len(custom) > self.MAX_CUSTOM_STOPWORDS:
            raise ValueError(f"Too many custom stopwords (max {self.MAX_CUSTOM_STOPWORDS})")

        validated = []
        for word in custom:
            word = word.lower().strip()

            # Check against dangerous patterns
            is_dangerous = False
            for pattern in self.DANGEROUS_STOPWORD_PATTERNS:
                if re.match(pattern, word):
                    is_dangerous = True
                    break

            if is_dangerous:
                print(f"Warning: Rejecting dangerous stopword '{word}'")
                continue

            # Length validation
            if len(word) < 2 or len(word) > 20:
                continue

            validated.append(word)

        self.stopwords.update(validated)

    @lru_cache(maxsize=10000)
    def tokenize(self, text: str) -> tuple:
        """Secure tokenization with caching."""
        # Extract tokens using safe pattern
        tokens = self.TOKEN_PATTERN.findall(text.lower())

        # Remove stopwords
        filtered = [t for t in tokens if t not in self.stopwords]

        return tuple(filtered)  # Return tuple for hashability

    def is_safe_token(self, token: str) -> bool:
        """Validate individual token safety."""
        if not token:
            return False

        if len(token) > 100:  # Prevent memory issues
            return False

        # Only alphanumeric
        if not token.isalnum():
            return False

        return True
```

**Don't**: Allow dynamic stopword modification or use unsafe tokenizer patterns

```python
# VULNERABLE: Mutable stopword list
class UnsafeTokenizer:
    stopwords = ['the', 'a', 'an']  # Mutable class variable

    def add_stopwords(self, words):
        # Allows arbitrary stopword injection
        self.stopwords.extend(words)  # No validation

    def tokenize(self, text):
        # Unsafe regex that could cause ReDoS
        tokens = re.findall(r'\S+', text)  # No length limits
        return [t for t in tokens if t not in self.stopwords]

# VULNERABLE: User-controlled tokenizer pattern
def create_tokenizer(user_pattern: str):
    # Allows ReDoS attacks via malicious patterns
    pattern = re.compile(user_pattern)  # No validation
    return pattern
```

**Why**: Attackers can manipulate stopword lists to suppress important query terms or allow noise terms that skew results. User-controlled tokenizer patterns enable ReDoS attacks. Mutable stopword lists can be poisoned over time to gradually degrade search quality.

**Refs**: CWE-20 (Improper Input Validation), CWE-1333 (ReDoS), CWE-400 (Resource Exhaustion)

---

## Rule: Query Expansion Security

**Level**: `warning`

**When**: Implementing synonym expansion, stemming, or query reformulation

**Do**: Limit expansion scope and validate expansion sources

```python
from typing import Dict, List, Set
import hashlib

class SecureQueryExpander:
    MAX_EXPANSIONS_PER_TERM = 5
    MAX_TOTAL_EXPANSIONS = 20
    MAX_EXPANSION_DEPTH = 2  # Prevent recursive expansion loops

    def __init__(self):
        # Validated synonym dictionary with checksums
        self.synonyms: Dict[str, List[str]] = {}
        self.synonym_checksums: Dict[str, str] = {}
        self.expansion_audit: List[Dict] = []

    def load_synonyms(self, synonym_dict: Dict[str, List[str]], source: str):
        """Load validated synonym dictionary."""
        validated = {}

        for term, expansions in synonym_dict.items():
            # Validate term
            if not self._is_valid_term(term):
                continue

            # Validate and limit expansions
            valid_expansions = []
            for exp in expansions[:self.MAX_EXPANSIONS_PER_TERM]:
                if self._is_valid_term(exp) and exp != term:
                    valid_expansions.append(exp)

            if valid_expansions:
                validated[term] = valid_expansions

        # Compute checksum for integrity verification
        content = str(sorted(validated.items()))
        checksum = hashlib.sha256(content.encode()).hexdigest()

        self.synonyms = validated
        self.synonym_checksums[source] = checksum

        print(f"Loaded {len(validated)} synonym entries from {source}")

    def _is_valid_term(self, term: str) -> bool:
        """Validate expansion term."""
        if not term or not isinstance(term, str):
            return False

        term = term.strip().lower()

        if len(term) < 2 or len(term) > 50:
            return False

        if not term.replace(' ', '').isalnum():
            return False

        return True

    def expand_query(self, query_terms: List[str],
                     user_id: str = None) -> List[str]:
        """Expand query with security controls."""
        expanded = set(query_terms)
        expansion_count = 0

        for term in query_terms:
            term_lower = term.lower()

            if term_lower in self.synonyms:
                for expansion in self.synonyms[term_lower]:
                    if expansion_count >= self.MAX_TOTAL_EXPANSIONS:
                        break

                    if expansion not in expanded:
                        expanded.add(expansion)
                        expansion_count += 1

        # Audit log
        self.expansion_audit.append({
            'original_terms': query_terms,
            'expanded_terms': list(expanded),
            'expansion_count': expansion_count,
            'user_id': user_id
        })

        return list(expanded)

    def apply_stemming(self, terms: List[str],
                      stemmer) -> List[str]:
        """Apply stemming with validation."""
        stemmed = []

        for term in terms:
            try:
                stem = stemmer.stem(term)

                # Validate stem output
                if stem and len(stem) >= 2 and stem.isalnum():
                    stemmed.append(stem)
                else:
                    stemmed.append(term)  # Keep original if stem invalid

            except Exception as e:
                # Log error, keep original term
                print(f"Stemming error for '{term}': {e}")
                stemmed.append(term)

        return stemmed

    def verify_integrity(self, source: str,
                        synonym_dict: Dict[str, List[str]]) -> bool:
        """Verify synonym dictionary hasn't been tampered with."""
        content = str(sorted(synonym_dict.items()))
        current_checksum = hashlib.sha256(content.encode()).hexdigest()

        return self.synonym_checksums.get(source) == current_checksum
```

**Don't**: Allow unlimited query expansion or unvalidated synonym sources

```python
# VULNERABLE: Unlimited expansion
def expand_query(query: str, synonyms: dict):
    terms = query.split()
    expanded = []

    for term in terms:
        expanded.append(term)
        if term in synonyms:
            # No limit on expansions - can explode query size
            expanded.extend(synonyms[term])

    return expanded

# VULNERABLE: Recursive expansion without depth limit
def recursive_expand(term: str, synonyms: dict, expanded: set):
    if term in expanded:
        return
    expanded.add(term)

    if term in synonyms:
        for syn in synonyms[term]:
            # Can loop infinitely with circular synonyms
            recursive_expand(syn, synonyms, expanded)

# VULNERABLE: User-provided synonyms without validation
def add_user_synonyms(user_synonyms: dict, global_synonyms: dict):
    # Allows injection of malicious synonym mappings
    global_synonyms.update(user_synonyms)
```

**Why**: Uncontrolled query expansion creates attack vectors where adversaries inject malicious synonym mappings to redirect queries to attacker-controlled content. Unlimited expansion enables DoS through exponential term growth. Circular synonyms without depth limits cause infinite loops.

**Refs**: CWE-20 (Improper Input Validation), CWE-400 (Resource Exhaustion), CWE-835 (Infinite Loop)

---

## Rule: Result Fusion Security

**Level**: `warning`

**When**: Combining results from multiple search sources using RRF or weighted fusion

**Do**: Implement bounds checking and validate fusion parameters

```python
import numpy as np
from typing import List, Dict, Tuple
from dataclasses import dataclass

@dataclass
class FusionResult:
    doc_id: str
    final_score: float
    source_scores: Dict[str, float]
    rank_positions: Dict[str, int]

class SecureResultFusion:
    # RRF parameter bounds
    MIN_K = 1
    MAX_K = 1000
    DEFAULT_K = 60

    # Weight bounds
    MIN_WEIGHT = 0.0
    MAX_WEIGHT = 1.0
    WEIGHT_TOLERANCE = 0.01

    def __init__(self, k: int = 60):
        if not self.MIN_K <= k <= self.MAX_K:
            raise ValueError(f"RRF k must be between {self.MIN_K} and {self.MAX_K}")
        self.k = k
        self.fusion_history: List[Dict] = []

    def reciprocal_rank_fusion(self,
                               result_lists: Dict[str, List[Tuple[str, float]]],
                               weights: Dict[str, float] = None) -> List[FusionResult]:
        """Secure RRF with validation."""
        # Validate weights
        if weights:
            self._validate_weights(weights, set(result_lists.keys()))
        else:
            # Equal weights
            num_sources = len(result_lists)
            weights = {source: 1.0 / num_sources for source in result_lists}

        # Track scores and ranks per document
        doc_scores: Dict[str, float] = {}
        doc_source_scores: Dict[str, Dict[str, float]] = {}
        doc_ranks: Dict[str, Dict[str, int]] = {}

        for source, results in result_lists.items():
            weight = weights[source]

            for rank, (doc_id, score) in enumerate(results):
                # Validate score
                if not isinstance(score, (int, float)) or np.isnan(score):
                    continue

                if doc_id not in doc_scores:
                    doc_scores[doc_id] = 0
                    doc_source_scores[doc_id] = {}
                    doc_ranks[doc_id] = {}

                # RRF formula with weight
                rrf_contribution = weight / (self.k + rank + 1)
                doc_scores[doc_id] += rrf_contribution
                doc_source_scores[doc_id][source] = score
                doc_ranks[doc_id][source] = rank

        # Build and validate results
        results = []
        for doc_id, score in doc_scores.items():
            # Validate final score
            if score < 0 or np.isnan(score) or np.isinf(score):
                continue

            results.append(FusionResult(
                doc_id=doc_id,
                final_score=score,
                source_scores=doc_source_scores[doc_id],
                rank_positions=doc_ranks[doc_id]
            ))

        # Sort by score
        results.sort(key=lambda x: x.final_score, reverse=True)

        # Log fusion operation
        self._log_fusion(result_lists, weights, results)

        return results

    def linear_weighted_fusion(self,
                               result_lists: Dict[str, List[Tuple[str, float]]],
                               weights: Dict[str, float]) -> List[FusionResult]:
        """Secure linear combination fusion."""
        # Validate weights
        self._validate_weights(weights, set(result_lists.keys()))

        # Normalize scores per source to [0, 1]
        normalized_lists = {}
        for source, results in result_lists.items():
            scores = [r[1] for r in results]
            if not scores:
                normalized_lists[source] = []
                continue

            min_s, max_s = min(scores), max(scores)
            range_s = max_s - min_s if max_s > min_s else 1

            normalized = [
                (doc_id, (score - min_s) / range_s)
                for doc_id, score in results
            ]
            normalized_lists[source] = normalized

        # Combine with weights
        doc_scores: Dict[str, float] = {}
        doc_source_scores: Dict[str, Dict[str, float]] = {}

        for source, results in normalized_lists.items():
            weight = weights[source]

            for doc_id, norm_score in results:
                if doc_id not in doc_scores:
                    doc_scores[doc_id] = 0
                    doc_source_scores[doc_id] = {}

                doc_scores[doc_id] += weight * norm_score
                doc_source_scores[doc_id][source] = norm_score

        # Build results
        results = [
            FusionResult(
                doc_id=doc_id,
                final_score=score,
                source_scores=doc_source_scores[doc_id],
                rank_positions={}
            )
            for doc_id, score in doc_scores.items()
            if 0 <= score <= 1  # Validate bounds
        ]

        results.sort(key=lambda x: x.final_score, reverse=True)

        return results

    def _validate_weights(self, weights: Dict[str, float],
                         expected_sources: set):
        """Validate fusion weights."""
        if set(weights.keys()) != expected_sources:
            raise ValueError("Weights must match result sources")

        for source, weight in weights.items():
            if not self.MIN_WEIGHT <= weight <= self.MAX_WEIGHT:
                raise ValueError(f"Weight for {source} out of bounds: {weight}")

        total = sum(weights.values())
        if abs(total - 1.0) > self.WEIGHT_TOLERANCE:
            raise ValueError(f"Weights must sum to 1.0, got {total}")

    def _log_fusion(self, result_lists: Dict, weights: Dict,
                   results: List[FusionResult]):
        """Log fusion operation for audit."""
        self.fusion_history.append({
            'sources': list(result_lists.keys()),
            'weights': weights,
            'result_count': len(results),
            'top_doc': results[0].doc_id if results else None,
            'top_score': results[0].final_score if results else None
        })
```

**Don't**: Implement fusion without parameter validation or score bounds checking

```python
# VULNERABLE: No parameter validation
def rrf(result_lists: dict, k: int = 60):
    scores = {}

    for source, results in result_lists.items():
        for rank, (doc_id, score) in enumerate(results):
            # No validation of rank or score
            scores[doc_id] = scores.get(doc_id, 0) + 1 / (k + rank)

    return sorted(scores.items(), key=lambda x: x[1], reverse=True)

# VULNERABLE: No weight validation
def weighted_fusion(results_a, results_b, weight_a, weight_b):
    # Accepts any weight values including negative
    combined = {}

    for doc_id, score in results_a:
        combined[doc_id] = weight_a * score

    for doc_id, score in results_b:
        combined[doc_id] = combined.get(doc_id, 0) + weight_b * score

    return combined

# VULNERABLE: No bounds checking
def combine_scores(scores_list):
    final = {}
    for scores in scores_list:
        for doc_id, score in scores.items():
            # Can produce unbounded or negative scores
            final[doc_id] = final.get(doc_id, 0) + score
    return final
```

**Why**: Invalid fusion parameters (negative weights, unbounded k values) can produce nonsensical rankings or be exploited to bias results. Attackers who can influence weights or parameters can manipulate which documents rank highest. Lack of bounds checking allows numeric overflow/underflow attacks.

**Refs**: CWE-20 (Improper Input Validation), CWE-682 (Incorrect Calculation), CWE-190 (Integer Overflow)

---

## Rule: Resource Limits for Large Corpus Searches

**Level**: `strict`

**When**: Executing lexical searches on large document corpora

**Do**: Implement timeouts, memory limits, and pagination for search operations

```python
import time
import resource
import signal
from typing import List, Generator, Optional
from contextlib import contextmanager
from rank_bm25 import BM25Okapi

class ResourceLimitedSearch:
    # Default limits
    DEFAULT_TIMEOUT_SECONDS = 30
    DEFAULT_MAX_RESULTS = 1000
    DEFAULT_PAGE_SIZE = 100
    MAX_MEMORY_MB = 512
    MAX_CORPUS_SIZE = 1_000_000  # 1M documents

    def __init__(self, corpus: List[List[str]],
                 timeout_seconds: int = None,
                 max_memory_mb: int = None):
        # Validate corpus size
        if len(corpus) > self.MAX_CORPUS_SIZE:
            raise ValueError(f"Corpus exceeds maximum size of {self.MAX_CORPUS_SIZE}")

        self.timeout = timeout_seconds or self.DEFAULT_TIMEOUT_SECONDS
        self.max_memory = (max_memory_mb or self.MAX_MEMORY_MB) * 1024 * 1024

        # Set memory limit
        try:
            soft, hard = resource.getrlimit(resource.RLIMIT_AS)
            resource.setrlimit(resource.RLIMIT_AS, (self.max_memory, hard))
        except (ValueError, resource.error):
            pass  # May not be available on all platforms

        self.bm25 = BM25Okapi(corpus)
        self.corpus_size = len(corpus)

    @contextmanager
    def timeout_context(self):
        """Context manager for operation timeout."""
        def timeout_handler(signum, frame):
            raise TimeoutError(f"Search operation timed out after {self.timeout}s")

        # Set timeout signal
        old_handler = signal.signal(signal.SIGALRM, timeout_handler)
        signal.alarm(self.timeout)

        try:
            yield
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, old_handler)

    def search(self, query_tokens: List[str],
               top_k: int = None,
               offset: int = 0) -> List[tuple]:
        """Execute search with resource limits."""
        top_k = min(top_k or self.DEFAULT_PAGE_SIZE, self.DEFAULT_MAX_RESULTS)

        start_time = time.time()

        with self.timeout_context():
            scores = self.bm25.get_scores(query_tokens)

        # Get top results with pagination
        sorted_indices = sorted(
            range(len(scores)),
            key=lambda i: scores[i],
            reverse=True
        )

        # Apply pagination
        paginated = sorted_indices[offset:offset + top_k]

        results = [
            (idx, scores[idx])
            for idx in paginated
        ]

        elapsed = time.time() - start_time

        # Log performance metrics
        self._log_search_metrics(
            query_tokens=query_tokens,
            results_count=len(results),
            elapsed_seconds=elapsed,
            corpus_size=self.corpus_size
        )

        return results

    def search_generator(self, query_tokens: List[str],
                        page_size: int = None) -> Generator:
        """Paginated search generator for memory efficiency."""
        page_size = min(page_size or self.DEFAULT_PAGE_SIZE, self.DEFAULT_MAX_RESULTS)
        offset = 0

        while True:
            results = self.search(query_tokens, top_k=page_size, offset=offset)

            if not results:
                break

            yield results

            if len(results) < page_size:
                break

            offset += page_size

    def _log_search_metrics(self, query_tokens: List[str],
                           results_count: int,
                           elapsed_seconds: float,
                           corpus_size: int):
        """Log search performance metrics."""
        metrics = {
            'query_terms': len(query_tokens),
            'results_returned': results_count,
            'elapsed_seconds': round(elapsed_seconds, 3),
            'corpus_size': corpus_size,
            'throughput': round(corpus_size / elapsed_seconds, 0) if elapsed_seconds > 0 else 0
        }

        # Alert on slow queries
        if elapsed_seconds > self.timeout * 0.8:
            print(f"Warning: Search approaching timeout - {metrics}")


class ElasticsearchResourceLimits:
    """Resource limits for Elasticsearch BM25 queries."""

    DEFAULT_TIMEOUT = '30s'
    MAX_RESULT_WINDOW = 10000
    MAX_TERMS_COUNT = 1000

    @staticmethod
    def build_limited_query(query: str,
                           size: int = 100,
                           from_offset: int = 0,
                           timeout: str = None) -> dict:
        """Build Elasticsearch query with resource limits."""
        # Enforce limits
        size = min(size, ElasticsearchResourceLimits.MAX_RESULT_WINDOW)

        if from_offset + size > ElasticsearchResourceLimits.MAX_RESULT_WINDOW:
            raise ValueError(
                f"Result window exceeds maximum of {ElasticsearchResourceLimits.MAX_RESULT_WINDOW}"
            )

        return {
            'query': {
                'match': {
                    'content': {
                        'query': query,
                        'operator': 'or',
                        'max_expansions': 50  # Limit query expansion
                    }
                }
            },
            'size': size,
            'from': from_offset,
            'timeout': timeout or ElasticsearchResourceLimits.DEFAULT_TIMEOUT,
            'terminate_after': ElasticsearchResourceLimits.MAX_RESULT_WINDOW,
            'track_total_hits': False  # Disable expensive total count
        }
```

**Don't**: Execute searches without resource limits or pagination

```python
from rank_bm25 import BM25Okapi

# VULNERABLE: No timeout or memory limits
def search_large_corpus(query: str, corpus: list):
    bm25 = BM25Okapi(corpus)  # No size limit
    tokens = query.split()

    # Returns ALL results - memory exhaustion on large corpus
    scores = bm25.get_scores(tokens)

    # Sorts entire corpus - CPU exhaustion
    return sorted(range(len(scores)),
                 key=lambda i: scores[i],
                 reverse=True)

# VULNERABLE: No pagination in Elasticsearch
def es_search_all(query: str, es_client):
    return es_client.search(
        index="documents",
        body={
            "query": {"match": {"content": query}},
            "size": 100000  # Excessive result size
            # No timeout specified
        }
    )

# VULNERABLE: Unbounded iteration
def get_all_results(bm25, query):
    scores = bm25.get_scores(query.split())
    # Returns potentially millions of results
    return [(i, s) for i, s in enumerate(scores) if s > 0]
```

**Why**: Without resource limits, adversaries can craft queries that exhaust server memory or CPU, causing denial of service. Complex queries on large corpora can take minutes to execute, blocking other operations. Unbounded result sets can crash applications or expose excessive data.

**Refs**: CWE-400 (Uncontrolled Resource Consumption), CWE-770 (Allocation of Resources Without Limits), CWE-834 (Excessive Iteration)

---

## Additional Elasticsearch BM25 Security Considerations

```python
# Secure Elasticsearch BM25 configuration
es_settings = {
    "index": {
        "similarity": {
            "custom_bm25": {
                "type": "BM25",
                "k1": 1.2,  # Term frequency saturation
                "b": 0.75   # Document length normalization
            }
        },
        # Security settings
        "max_result_window": 10000,
        "max_terms_count": 65536,
        "max_regex_length": 1000
    },
    "analysis": {
        "analyzer": {
            "secure_analyzer": {
                "type": "custom",
                "tokenizer": "standard",
                "filter": [
                    "lowercase",
                    "stop",  # Remove stopwords
                    "snowball"  # Stemming
                ],
                "char_filter": ["html_strip"]  # Remove HTML
            }
        }
    }
}
```

---

## Whoosh Implementation Security

```python
from whoosh.index import create_in, open_dir
from whoosh.fields import Schema, TEXT, ID
from whoosh.qparser import QueryParser
from whoosh.query import And, Or, Term
import os

class SecureWhooshSearch:
    def __init__(self, index_dir: str):
        self.index_dir = index_dir
        self.schema = Schema(
            id=ID(stored=True, unique=True),
            content=TEXT(stored=True)
        )

        if not os.path.exists(index_dir):
            os.makedirs(index_dir)
            self.index = create_in(index_dir, self.schema)
        else:
            self.index = open_dir(index_dir)

    def secure_search(self, query: str, limit: int = 100) -> list:
        """Secure Whoosh search with limits."""
        # Limit result count
        limit = min(limit, 1000)

        with self.index.searcher() as searcher:
            # Use safe query parser
            parser = QueryParser("content", self.index.schema)

            # Disable wildcards and fuzzy queries for security
            parser.remove_plugin_class(
                whoosh.qparser.plugins.WildcardPlugin
            )

            try:
                parsed = parser.parse(query)
            except Exception as e:
                raise ValueError(f"Invalid query: {e}")

            results = searcher.search(parsed, limit=limit)

            return [
                {'id': r['id'], 'content': r['content'], 'score': r.score}
                for r in results
            ]
```
