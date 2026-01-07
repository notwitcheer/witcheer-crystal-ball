"""
Wallet clustering system for detecting coordinated trading activity.

Identifies groups of wallets that exhibit similar behavioral patterns,
timing correlations, and trading strategies that suggest coordination
or shared control by the same entity.
"""

import asyncio
import numpy as np
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Set, Optional, Tuple, Any
from dataclasses import dataclass, field
from collections import defaultdict
import structlog

from ..secure_logging import get_secure_logger
from ..detection.signals import WalletProfile, SignalType
from ..exceptions import InsufficientDataError, DetectionError
from ..validation import validate_wallet_address

logger = get_secure_logger(__name__)


@dataclass
class TradingBehavior:
    """Represents trading behavior patterns for a wallet."""

    wallet_address: str
    total_trades: int
    preferred_markets: List[str]  # Markets traded most frequently
    trade_sizes: List[float]     # Historical trade sizes
    trade_times: List[datetime]  # Timestamps of trades
    market_timing: Dict[str, List[datetime]]  # Market -> trade times
    success_rate: float
    avg_trade_size: float
    trade_frequency: float  # Trades per day

    # Behavioral fingerprints
    time_of_day_pattern: List[float]  # 24-hour trading pattern
    market_preference_scores: Dict[str, float]  # Market -> preference score
    size_distribution: Dict[str, float]  # Size category -> frequency

    def __post_init__(self):
        """Calculate derived metrics after initialization."""
        if self.trade_times:
            self._calculate_time_patterns()
            self._calculate_market_preferences()
            self._calculate_size_distribution()

    def _calculate_time_patterns(self):
        """Calculate trading time patterns."""
        # Initialize 24-hour pattern
        self.time_of_day_pattern = [0.0] * 24

        for trade_time in self.trade_times:
            hour = trade_time.hour
            self.time_of_day_pattern[hour] += 1

        # Normalize to percentages
        total = sum(self.time_of_day_pattern)
        if total > 0:
            self.time_of_day_pattern = [count / total for count in self.time_of_day_pattern]

    def _calculate_market_preferences(self):
        """Calculate market preference scores."""
        market_counts = defaultdict(int)
        for market in self.preferred_markets:
            market_counts[market] += 1

        total_markets = len(self.preferred_markets)
        self.market_preference_scores = {
            market: count / total_markets
            for market, count in market_counts.items()
        }

    def _calculate_size_distribution(self):
        """Calculate trade size distribution."""
        if not self.trade_sizes:
            self.size_distribution = {}
            return

        # Define size categories
        sizes = sorted(self.trade_sizes)
        q25 = np.percentile(sizes, 25)
        q75 = np.percentile(sizes, 75)

        categories = {
            'small': 0,    # Below 25th percentile
            'medium': 0,   # 25th to 75th percentile
            'large': 0     # Above 75th percentile
        }

        for size in sizes:
            if size <= q25:
                categories['small'] += 1
            elif size <= q75:
                categories['medium'] += 1
            else:
                categories['large'] += 1

        total = len(sizes)
        self.size_distribution = {
            category: count / total
            for category, count in categories.items()
        }


@dataclass
class WalletCluster:
    """Represents a cluster of potentially coordinated wallets."""

    cluster_id: str
    wallets: Set[str]
    confidence_score: float  # 0-100, how confident we are in coordination
    coordination_type: str   # 'timing', 'behavioral', 'mixed'

    # Evidence for coordination
    timing_correlation: float      # Correlation in trade timing
    behavioral_similarity: float   # Similarity in trading patterns
    market_overlap: float         # Overlap in markets traded

    # Cluster statistics
    total_volume: float
    trade_count: int
    markets_affected: Set[str]
    first_activity: datetime
    last_activity: datetime

    # Metadata for analysis
    detection_method: str
    suspicious_patterns: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def get_cluster_summary(self) -> Dict[str, Any]:
        """Get human-readable cluster summary."""
        return {
            'cluster_id': self.cluster_id,
            'wallet_count': len(self.wallets),
            'confidence_score': self.confidence_score,
            'coordination_type': self.coordination_type,
            'total_volume': self.total_volume,
            'markets_affected': len(self.markets_affected),
            'suspicious_patterns': self.suspicious_patterns,
            'activity_span_days': (self.last_activity - self.first_activity).days
        }


class BehaviorAnalyzer:
    """Analyzes individual wallet behaviors and extracts patterns."""

    def __init__(self):
        self.behavior_cache: Dict[str, TradingBehavior] = {}

    async def analyze_wallet_behavior(self,
                                    wallet_address: str,
                                    trades: List[Dict[str, Any]]) -> TradingBehavior:
        """
        Analyze trading behavior for a single wallet.

        Args:
            wallet_address: Wallet to analyze
            trades: List of trade data for the wallet

        Returns:
            TradingBehavior object with extracted patterns
        """
        if wallet_address in self.behavior_cache:
            return self.behavior_cache[wallet_address]

        if len(trades) < 3:
            raise InsufficientDataError(
                "trade_data",
                f"Need at least 3 trades for analysis, got {len(trades)}"
            )

        try:
            # Extract basic metrics
            trade_sizes = [float(trade.get('size', 0)) for trade in trades]
            trade_times = [
                datetime.fromisoformat(trade['timestamp'])
                for trade in trades
                if trade.get('timestamp')
            ]

            markets = [trade.get('market', '') for trade in trades]
            preferred_markets = [m for m in markets if m]

            # Calculate timing by market
            market_timing = defaultdict(list)
            for trade in trades:
                if trade.get('market') and trade.get('timestamp'):
                    market_timing[trade['market']].append(
                        datetime.fromisoformat(trade['timestamp'])
                    )

            # Calculate success rate (placeholder - would need market outcome data)
            success_rate = 0.65  # Default estimate

            # Calculate frequency
            if len(trade_times) >= 2:
                time_span = (max(trade_times) - min(trade_times)).days
                trade_frequency = len(trades) / max(time_span, 1)
            else:
                trade_frequency = 0.0

            behavior = TradingBehavior(
                wallet_address=wallet_address,
                total_trades=len(trades),
                preferred_markets=preferred_markets,
                trade_sizes=trade_sizes,
                trade_times=trade_times,
                market_timing=dict(market_timing),
                success_rate=success_rate,
                avg_trade_size=np.mean(trade_sizes) if trade_sizes else 0.0,
                trade_frequency=trade_frequency,
                time_of_day_pattern=[],
                market_preference_scores={},
                size_distribution={}
            )

            self.behavior_cache[wallet_address] = behavior

            logger.debug("wallet_behavior_analyzed",
                        wallet=wallet_address[:10],
                        trades=len(trades),
                        markets=len(set(preferred_markets)),
                        avg_size=behavior.avg_trade_size)

            return behavior

        except Exception as e:
            logger.error("behavior_analysis_failed",
                        wallet=wallet_address[:10],
                        error=str(e))
            raise DetectionError(
                "behavior_analysis",
                f"Failed to analyze wallet behavior: {e}",
                wallet_address=wallet_address
            )


class CoordinationDetector:
    """Detects coordination patterns between wallets."""

    def __init__(self):
        self.similarity_threshold = 0.7    # Threshold for behavioral similarity
        self.timing_threshold = 0.8        # Threshold for timing correlation
        self.market_overlap_threshold = 0.6 # Threshold for market overlap

    async def detect_timing_coordination(self,
                                       behaviors: List[TradingBehavior],
                                       time_window_minutes: int = 30) -> List[Tuple[str, str, float]]:
        """
        Detect coordination based on timing patterns.

        Args:
            behaviors: List of wallet behaviors to analyze
            time_window_minutes: Window for considering trades as coordinated

        Returns:
            List of (wallet1, wallet2, correlation_score) tuples
        """
        coordinated_pairs = []
        time_window = timedelta(minutes=time_window_minutes)

        for i, behavior1 in enumerate(behaviors):
            for j, behavior2 in enumerate(behaviors[i+1:], i+1):
                try:
                    # Find common markets
                    common_markets = set(behavior1.market_timing.keys()) & \
                                   set(behavior2.market_timing.keys())

                    if len(common_markets) < 2:
                        continue  # Need overlap in at least 2 markets

                    correlation_scores = []

                    for market in common_markets:
                        times1 = behavior1.market_timing[market]
                        times2 = behavior2.market_timing[market]

                        # Count coordinated trades (trades within time window)
                        coordinated_count = 0
                        total_comparisons = 0

                        for t1 in times1:
                            for t2 in times2:
                                total_comparisons += 1
                                if abs((t1 - t2).total_seconds()) <= time_window.total_seconds():
                                    coordinated_count += 1

                        if total_comparisons > 0:
                            market_correlation = coordinated_count / total_comparisons
                            correlation_scores.append(market_correlation)

                    if correlation_scores:
                        avg_correlation = np.mean(correlation_scores)

                        if avg_correlation >= self.timing_threshold:
                            coordinated_pairs.append((
                                behavior1.wallet_address,
                                behavior2.wallet_address,
                                avg_correlation
                            ))

                            logger.info("timing_coordination_detected",
                                       wallet1=behavior1.wallet_address[:10],
                                       wallet2=behavior2.wallet_address[:10],
                                       correlation=avg_correlation,
                                       common_markets=len(common_markets))

                except Exception as e:
                    logger.warning("timing_correlation_failed",
                                 wallet1=behavior1.wallet_address[:10],
                                 wallet2=behavior2.wallet_address[:10],
                                 error=str(e))

        return coordinated_pairs

    async def detect_behavioral_similarity(self,
                                         behaviors: List[TradingBehavior]) -> List[Tuple[str, str, float]]:
        """
        Detect coordination based on behavioral similarity.

        Args:
            behaviors: List of wallet behaviors to analyze

        Returns:
            List of (wallet1, wallet2, similarity_score) tuples
        """
        similar_pairs = []

        for i, behavior1 in enumerate(behaviors):
            for j, behavior2 in enumerate(behaviors[i+1:], i+1):
                try:
                    similarity_score = self._calculate_behavioral_similarity(behavior1, behavior2)

                    if similarity_score >= self.similarity_threshold:
                        similar_pairs.append((
                            behavior1.wallet_address,
                            behavior2.wallet_address,
                            similarity_score
                        ))

                        logger.info("behavioral_similarity_detected",
                                   wallet1=behavior1.wallet_address[:10],
                                   wallet2=behavior2.wallet_address[:10],
                                   similarity=similarity_score)

                except Exception as e:
                    logger.warning("behavioral_similarity_failed",
                                 wallet1=behavior1.wallet_address[:10],
                                 wallet2=behavior2.wallet_address[:10],
                                 error=str(e))

        return similar_pairs

    def _calculate_behavioral_similarity(self,
                                       behavior1: TradingBehavior,
                                       behavior2: TradingBehavior) -> float:
        """Calculate overall behavioral similarity between two wallets."""
        similarity_components = []

        # Time pattern similarity
        if behavior1.time_of_day_pattern and behavior2.time_of_day_pattern:
            time_similarity = self._calculate_vector_similarity(
                behavior1.time_of_day_pattern,
                behavior2.time_of_day_pattern
            )
            similarity_components.append(time_similarity * 0.3)  # 30% weight

        # Market preference similarity
        market_similarity = self._calculate_market_preference_similarity(
            behavior1.market_preference_scores,
            behavior2.market_preference_scores
        )
        similarity_components.append(market_similarity * 0.3)  # 30% weight

        # Size distribution similarity
        if behavior1.size_distribution and behavior2.size_distribution:
            size_similarity = self._calculate_distribution_similarity(
                behavior1.size_distribution,
                behavior2.size_distribution
            )
            similarity_components.append(size_similarity * 0.2)  # 20% weight

        # Trading frequency similarity
        freq_similarity = self._calculate_frequency_similarity(
            behavior1.trade_frequency,
            behavior2.trade_frequency
        )
        similarity_components.append(freq_similarity * 0.2)  # 20% weight

        return sum(similarity_components) if similarity_components else 0.0

    def _calculate_vector_similarity(self, vec1: List[float], vec2: List[float]) -> float:
        """Calculate cosine similarity between two vectors."""
        if len(vec1) != len(vec2) or not vec1 or not vec2:
            return 0.0

        try:
            # Convert to numpy arrays
            v1 = np.array(vec1)
            v2 = np.array(vec2)

            # Calculate cosine similarity
            dot_product = np.dot(v1, v2)
            norm1 = np.linalg.norm(v1)
            norm2 = np.linalg.norm(v2)

            if norm1 == 0 or norm2 == 0:
                return 0.0

            return dot_product / (norm1 * norm2)
        except Exception:
            return 0.0

    def _calculate_market_preference_similarity(self,
                                              prefs1: Dict[str, float],
                                              prefs2: Dict[str, float]) -> float:
        """Calculate similarity in market preferences."""
        if not prefs1 or not prefs2:
            return 0.0

        # Get common markets
        common_markets = set(prefs1.keys()) & set(prefs2.keys())
        if not common_markets:
            return 0.0

        # Calculate preference vector similarity for common markets
        vec1 = [prefs1[market] for market in common_markets]
        vec2 = [prefs2[market] for market in common_markets]

        return self._calculate_vector_similarity(vec1, vec2)

    def _calculate_distribution_similarity(self,
                                         dist1: Dict[str, float],
                                         dist2: Dict[str, float]) -> float:
        """Calculate similarity between two distributions."""
        if not dist1 or not dist2:
            return 0.0

        # Get all categories
        all_categories = set(dist1.keys()) | set(dist2.keys())

        # Create vectors with 0 for missing categories
        vec1 = [dist1.get(cat, 0.0) for cat in all_categories]
        vec2 = [dist2.get(cat, 0.0) for cat in all_categories]

        return self._calculate_vector_similarity(vec1, vec2)

    def _calculate_frequency_similarity(self, freq1: float, freq2: float) -> float:
        """Calculate similarity in trading frequency."""
        if freq1 == 0 and freq2 == 0:
            return 1.0

        if freq1 == 0 or freq2 == 0:
            return 0.0

        # Calculate relative similarity
        ratio = min(freq1, freq2) / max(freq1, freq2)
        return ratio


class WalletClusteringEngine:
    """
    Main wallet clustering engine that coordinates detection and analysis.
    """

    def __init__(self):
        self.behavior_analyzer = BehaviorAnalyzer()
        self.coordination_detector = CoordinationDetector()
        self.clusters: Dict[str, WalletCluster] = {}
        self.cluster_counter = 0

    async def analyze_wallet_coordination(self,
                                        wallet_trades: Dict[str, List[Dict]],
                                        min_cluster_size: int = 2) -> List[WalletCluster]:
        """
        Analyze coordination between multiple wallets.

        Args:
            wallet_trades: Dict mapping wallet addresses to their trade histories
            min_cluster_size: Minimum number of wallets to form a cluster

        Returns:
            List of detected wallet clusters
        """
        if len(wallet_trades) < min_cluster_size:
            logger.warning("insufficient_wallets_for_clustering",
                          wallet_count=len(wallet_trades),
                          min_required=min_cluster_size)
            return []

        try:
            # Step 1: Analyze individual behaviors
            logger.info("analyzing_individual_behaviors",
                       wallet_count=len(wallet_trades))

            behaviors = []
            for wallet, trades in wallet_trades.items():
                try:
                    behavior = await self.behavior_analyzer.analyze_wallet_behavior(wallet, trades)
                    behaviors.append(behavior)
                except InsufficientDataError as e:
                    logger.warning("insufficient_trade_data",
                                 wallet=wallet[:10],
                                 error=str(e))
                    continue

            if len(behaviors) < min_cluster_size:
                logger.warning("insufficient_analyzable_wallets",
                              analyzable_count=len(behaviors),
                              min_required=min_cluster_size)
                return []

            # Step 2: Detect coordination patterns
            logger.info("detecting_coordination_patterns",
                       behavior_count=len(behaviors))

            # Detect timing coordination
            timing_pairs = await self.coordination_detector.detect_timing_coordination(behaviors)

            # Detect behavioral similarity
            behavioral_pairs = await self.coordination_detector.detect_behavioral_similarity(behaviors)

            # Step 3: Form clusters
            clusters = await self._form_clusters(
                behaviors,
                timing_pairs,
                behavioral_pairs,
                min_cluster_size
            )

            logger.info("clustering_completed",
                       clusters_found=len(clusters),
                       timing_pairs=len(timing_pairs),
                       behavioral_pairs=len(behavioral_pairs))

            return clusters

        except Exception as e:
            logger.error("clustering_analysis_failed", error=str(e))
            raise DetectionError("wallet_clustering", f"Clustering analysis failed: {e}")

    async def _form_clusters(self,
                           behaviors: List[TradingBehavior],
                           timing_pairs: List[Tuple[str, str, float]],
                           behavioral_pairs: List[Tuple[str, str, float]],
                           min_cluster_size: int) -> List[WalletCluster]:
        """Form clusters from detected coordination pairs."""
        # Build adjacency graph
        graph = defaultdict(set)
        edge_scores = {}

        # Add timing coordination edges
        for wallet1, wallet2, score in timing_pairs:
            graph[wallet1].add(wallet2)
            graph[wallet2].add(wallet1)
            edge_scores[(wallet1, wallet2)] = {
                'timing': score,
                'behavioral': 0.0
            }

        # Add behavioral similarity edges
        for wallet1, wallet2, score in behavioral_pairs:
            if wallet1 not in graph[wallet2]:
                graph[wallet1].add(wallet2)
                graph[wallet2].add(wallet1)
                edge_scores[(wallet1, wallet2)] = {
                    'timing': 0.0,
                    'behavioral': score
                }
            else:
                # Both timing and behavioral similarity detected
                edge_scores[(wallet1, wallet2)]['behavioral'] = score

        # Find connected components (clusters)
        visited = set()
        clusters = []

        for wallet in graph:
            if wallet in visited:
                continue

            # BFS to find connected component
            cluster_wallets = set()
            queue = [wallet]
            visited.add(wallet)
            cluster_wallets.add(wallet)

            while queue:
                current = queue.pop(0)
                for neighbor in graph[current]:
                    if neighbor not in visited:
                        visited.add(neighbor)
                        queue.append(neighbor)
                        cluster_wallets.add(neighbor)

            # Only create cluster if it meets minimum size
            if len(cluster_wallets) >= min_cluster_size:
                cluster = await self._create_cluster(
                    cluster_wallets,
                    behaviors,
                    edge_scores
                )
                clusters.append(cluster)

        return clusters

    async def _create_cluster(self,
                            wallet_addresses: Set[str],
                            behaviors: List[TradingBehavior],
                            edge_scores: Dict[Tuple[str, str], Dict[str, float]]) -> WalletCluster:
        """Create a WalletCluster object from a set of coordinated wallets."""
        self.cluster_counter += 1
        cluster_id = f"cluster_{self.cluster_counter:04d}"

        # Get behaviors for cluster wallets
        cluster_behaviors = [
            b for b in behaviors
            if b.wallet_address in wallet_addresses
        ]

        # Calculate cluster statistics
        total_volume = sum(b.avg_trade_size * b.total_trades for b in cluster_behaviors)
        trade_count = sum(b.total_trades for b in cluster_behaviors)

        # Get all markets traded by cluster
        markets_affected = set()
        for behavior in cluster_behaviors:
            markets_affected.update(behavior.market_preference_scores.keys())

        # Calculate timing correlation and behavioral similarity
        timing_scores = []
        behavioral_scores = []

        wallet_list = list(wallet_addresses)
        for i, wallet1 in enumerate(wallet_list):
            for wallet2 in wallet_list[i+1:]:
                edge_key = (wallet1, wallet2)
                if edge_key not in edge_scores:
                    edge_key = (wallet2, wallet1)  # Try reverse order

                if edge_key in edge_scores:
                    timing_scores.append(edge_scores[edge_key]['timing'])
                    behavioral_scores.append(edge_scores[edge_key]['behavioral'])

        avg_timing_correlation = np.mean(timing_scores) if timing_scores else 0.0
        avg_behavioral_similarity = np.mean(behavioral_scores) if behavioral_scores else 0.0

        # Determine coordination type
        if avg_timing_correlation > 0.5 and avg_behavioral_similarity > 0.5:
            coordination_type = "mixed"
        elif avg_timing_correlation > avg_behavioral_similarity:
            coordination_type = "timing"
        else:
            coordination_type = "behavioral"

        # Calculate confidence score
        confidence_score = min(100, (avg_timing_correlation + avg_behavioral_similarity) * 50)

        # Get activity time range
        all_trade_times = []
        for behavior in cluster_behaviors:
            all_trade_times.extend(behavior.trade_times)

        first_activity = min(all_trade_times) if all_trade_times else datetime.now(timezone.utc)
        last_activity = max(all_trade_times) if all_trade_times else datetime.now(timezone.utc)

        # Identify suspicious patterns
        suspicious_patterns = []
        if avg_timing_correlation > 0.8:
            suspicious_patterns.append("highly_synchronized_trading")
        if len(markets_affected) < 3:
            suspicious_patterns.append("focused_market_activity")
        if confidence_score > 80:
            suspicious_patterns.append("strong_coordination_evidence")

        cluster = WalletCluster(
            cluster_id=cluster_id,
            wallets=wallet_addresses,
            confidence_score=confidence_score,
            coordination_type=coordination_type,
            timing_correlation=avg_timing_correlation,
            behavioral_similarity=avg_behavioral_similarity,
            market_overlap=len(markets_affected),
            total_volume=total_volume,
            trade_count=trade_count,
            markets_affected=markets_affected,
            first_activity=first_activity,
            last_activity=last_activity,
            detection_method="behavioral_analysis",
            suspicious_patterns=suspicious_patterns
        )

        self.clusters[cluster_id] = cluster

        logger.info("wallet_cluster_created",
                   cluster_id=cluster_id,
                   wallets=len(wallet_addresses),
                   confidence=confidence_score,
                   coordination_type=coordination_type)

        return cluster

    def get_cluster_by_wallet(self, wallet_address: str) -> Optional[WalletCluster]:
        """Get cluster containing the specified wallet."""
        for cluster in self.clusters.values():
            if wallet_address in cluster.wallets:
                return cluster
        return None

    def get_all_clusters(self) -> List[WalletCluster]:
        """Get all detected clusters."""
        return list(self.clusters.values())


# Global clustering engine instance
_clustering_engine: Optional[WalletClusteringEngine] = None


def get_clustering_engine() -> WalletClusteringEngine:
    """Get or create global clustering engine."""
    global _clustering_engine
    if _clustering_engine is None:
        _clustering_engine = WalletClusteringEngine()
    return _clustering_engine


async def test_wallet_clustering():
    """Test wallet clustering functionality."""
    print("🔗 Testing Wallet Clustering")
    print("=" * 30)

    # Create sample trade data
    sample_trades = {
        "0x1111111111111111111111111111111111111111": [
            {
                "market": "market_1",
                "size": "100.0",
                "timestamp": "2024-01-01T10:00:00Z"
            },
            {
                "market": "market_2",
                "size": "150.0",
                "timestamp": "2024-01-01T10:05:00Z"
            },
            {
                "market": "market_1",
                "size": "200.0",
                "timestamp": "2024-01-02T10:00:00Z"
            }
        ],
        "0x2222222222222222222222222222222222222222": [
            {
                "market": "market_1",
                "size": "120.0",
                "timestamp": "2024-01-01T10:02:00Z"  # Close timing to wallet 1
            },
            {
                "market": "market_2",
                "size": "180.0",
                "timestamp": "2024-01-01T10:07:00Z"  # Close timing to wallet 1
            },
            {
                "market": "market_1",
                "size": "220.0",
                "timestamp": "2024-01-02T10:03:00Z"  # Close timing to wallet 1
            }
        ]
    }

    try:
        engine = WalletClusteringEngine()
        clusters = await engine.analyze_wallet_coordination(sample_trades, min_cluster_size=2)

        print(f"✅ Clusters detected: {len(clusters)}")

        for cluster in clusters:
            summary = cluster.get_cluster_summary()
            print(f"  📊 Cluster {summary['cluster_id']}:")
            print(f"    Wallets: {summary['wallet_count']}")
            print(f"    Confidence: {summary['confidence_score']:.1f}%")
            print(f"    Type: {summary['coordination_type']}")
            print(f"    Patterns: {summary['suspicious_patterns']}")

        print("✅ Wallet clustering test completed")

    except Exception as e:
        print(f"❌ Test failed: {e}")


if __name__ == "__main__":
    asyncio.run(test_wallet_clustering())