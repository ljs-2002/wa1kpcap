"""
Export functionality for flows and features.

Provides methods to export flows to various formats including DataFrame,
CSV, JSON, and dict.

Examples:
    Export to pandas DataFrame:
        >>> from wa1kpcap import Wa1kPcap, to_dataframe
        >>> analyzer = Wa1kPcap(verbose_mode=True)
        >>> flows = analyzer.analyze_file('traffic.pcap')
        >>> df = to_dataframe(flows)
        >>> print(df[['src_ip', 'dst_ip', 'packet_count']])

    Export to CSV:
        >>> from wa1kpcap import to_csv
        >>> to_csv(flows, 'output.csv')

    Export to JSON:
        >>> from wa1kpcap import to_json
        >>> to_json(flows, 'output.json')

    Using FlowExporter class:
        >>> from wa1kpcap import FlowExporter
        >>> exporter = FlowExporter(include_features=True)
        >>> exporter.to_csv(flows, 'output.csv')
        >>> exporter.to_json(flows, 'output.json')
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any
import json

if TYPE_CHECKING:
    from wa1kpcap.core.flow import Flow


def to_dataframe(flows: list[Flow]) -> object:
    """
    Convert flows to pandas DataFrame.

    Creates a pandas DataFrame with one row per flow. Flow metadata and
    features are flattened into columns. Feature columns are prefixed
    with 'feature.' (e.g., 'feature.packet_lengths.mean').

    Args:
        flows: List of Flow objects

    Returns:
        pandas DataFrame with flow features as columns

    Raises:
        ImportError: If pandas is not installed

    Examples:
        >>> from wa1kpcap import Wa1kPcap, to_dataframe
        >>> analyzer = Wa1kPcap(verbose_mode=True)
        >>> flows = analyzer.analyze_file('traffic.pcap')
        >>> df = to_dataframe(flows)
        >>> # Filter by packet count
        >>> df_filtered = df[df['packet_count'] > 10]
        >>> # Access statistical features
        >>> print(df['feature.packet_lengths.mean'])
    """
    try:
        import pandas as pd
    except ImportError:
        raise ImportError("pandas is required for DataFrame export. Install with: pip install pandas")

    rows = []

    for flow in flows:
        row = flow.to_dict()

        # Add features if available
        if flow.features:
            features_dict = flow.features.to_dict()
            # Flatten statistics
            if 'statistics' in features_dict:
                for stat_name, stat_value in features_dict['statistics'].items():
                    if isinstance(stat_value, dict):
                        for sub_name, sub_value in stat_value.items():
                            row[f'feature.{stat_name}.{sub_name}'] = sub_value
                    else:
                        row[f'feature.{stat_name}'] = stat_value

            # Add arrays as JSON strings
            for key, value in features_dict.items():
                if key == 'statistics':
                    continue
                if hasattr(value, 'tolist'):
                    row[f'feature.{key}'] = value.tolist()
                elif isinstance(value, list):
                    row[f'feature.{key}'] = value
                else:
                    row[f'feature.{key}'] = value

        rows.append(row)

    return pd.DataFrame(rows)


def to_dict(flows: list[Flow], include_features: bool = True) -> list[dict]:
    """
    Convert flows to list of dictionaries.

    Args:
        flows: List of Flow objects
        include_features: Whether to include flow features (default: True)

    Returns:
        List of dictionaries representing flows

    Examples:
        >>> from wa1kpcap import Wa1kPcap, to_dict
        >>> analyzer = Wa1kPcap(verbose_mode=True)
        >>> flows = analyzer.analyze_file('traffic.pcap')
        >>> flow_dicts = to_dict(flows, include_features=True)
        >>> for flow_dict in flow_dicts:
        ...     print(f"{flow_dict['src_ip']} -> {flow_dict['dst_ip']}")
    """
    result = []

    for flow in flows:
        flow_dict = flow.to_dict()

        if include_features and flow.features:
            flow_dict['features'] = flow.features.to_dict()

        result.append(flow_dict)

    return result


def to_json(
    flows: list[Flow],
    path: str | Path,
    include_features: bool = True,
    indent: int = 2
) -> None:
    """
    Export flows to JSON file.

    Args:
        flows: List of Flow objects
        path: Output JSON file path
        include_features: Whether to include flow features (default: True)
        indent: JSON indentation level (default: 2)

    Examples:
        >>> from wa1kpcap import Wa1kPcap, to_json
        >>> analyzer = Wa1kPcap(verbose_mode=True)
        >>> flows = analyzer.analyze_file('traffic.pcap')
        >>> to_json(flows, 'output.json', include_features=True, indent=4)
    """
    path = Path(path)

    data = to_dict(flows, include_features=include_features)

    with open(path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=indent, default=str)


def to_csv(
    flows: list[Flow],
    path: str | Path,
    include_features: bool = True
) -> None:
    """
    Export flows to CSV file.

    Args:
        flows: List of Flow objects
        path: Output CSV file path
        include_features: Whether to include flow features (default: True)

    Raises:
        ImportError: If pandas is not installed

    Examples:
        >>> from wa1kpcap import Wa1kPcap, to_csv
        >>> analyzer = Wa1kPcap(verbose_mode=True)
        >>> flows = analyzer.analyze_file('traffic.pcap')
        >>> to_csv(flows, 'output.csv', include_features=True)
    """
    try:
        import pandas as pd
    except ImportError:
        raise ImportError("pandas is required for CSV export. Install with: pip install pandas")

    df = to_dataframe(flows)
    df.to_csv(path, index=False)


def to_list_of_dicts(
    flows: list[Flow],
    flatten_features: bool = False
) -> list[dict[str, Any]]:
    """
    Convert flows to list of dictionaries with optional feature flattening.

    Args:
        flows: List of Flow objects
        flatten_features: Whether to flatten nested feature dictionaries
            using dot notation (default: False)

    Returns:
        List of dictionaries with flow data and optionally features

    Examples:
        >>> from wa1kpcap import Wa1kPcap, to_list_of_dicts
        >>> analyzer = Wa1kPcap(verbose_mode=True)
        >>> flows = analyzer.analyze_file('traffic.pcap')
        >>> # Without flattening
        >>> flow_dicts = to_list_of_dicts(flows, flatten_features=False)
        >>> # With flattening (features become feature.packet_lengths.mean, etc)
        >>> flow_dicts = to_list_of_dicts(flows, flatten_features=True)
    """
    result = []

    for flow in flows:
        flow_dict = flow.to_dict()

        if flow.features:
            features = flow.features.to_dict()
            if flatten_features:
                # Flatten all nested dictionaries
                for key, value in features.items():
                    if isinstance(value, dict):
                        for sub_key, sub_value in value.items():
                            if isinstance(sub_value, dict):
                                for sub_sub_key, sub_sub_value in sub_value.items():
                                    flow_dict[f'feature.{key}.{sub_key}.{sub_sub_key}'] = sub_sub_value
                            else:
                                flow_dict[f'feature.{key}.{sub_key}'] = sub_value
                    else:
                        flow_dict[f'feature.{key}'] = value
            else:
                flow_dict['features'] = features

        result.append(flow_dict)

    return result


class FlowExporter:
    """
    Helper class for exporting flows in various formats.

    Provides a consistent interface for exporting flows to different formats
    with configurable feature inclusion.

    Attributes:
        include_features: Whether to include flow features in exports
        flatten_features: Whether to flatten nested feature dictionaries

    Examples:
        Basic usage:
            >>> from wa1kpcap import Wa1kPcap, FlowExporter
            >>> analyzer = Wa1kPcap(verbose_mode=True)
            >>> flows = analyzer.analyze_file('traffic.pcap')
            >>> exporter = FlowExporter(include_features=True, flatten_features=False)
            >>> exporter.to_csv(flows, 'output.csv')
            >>> exporter.to_json(flows, 'output.json')

        Export to DataFrame:
            >>> df = exporter.to_dataframe(flows)
            >>> print(df[['src_ip', 'dst_ip', 'packet_count']])

        Auto-detect format by extension:
            >>> exporter.save(flows, 'output.csv')   # CSV
            >>> exporter.save(flows, 'output.json')  # JSON
            >>> exporter.save(flows, 'output.parquet')  # Parquet
    """

    def __init__(self, include_features: bool = True, flatten_features: bool = False):
        """
        Initialize the FlowExporter.

        Args:
            include_features: Whether to include flow features (default: True)
            flatten_features: Whether to flatten nested features with dot notation (default: False)
        """
        self.include_features = include_features
        self.flatten_features = flatten_features

    def to_dataframe(self, flows: list[Flow]) -> object:
        """Convert flows to pandas DataFrame."""
        try:
            import pandas as pd
        except ImportError:
            raise ImportError("pandas is required for DataFrame export. Install with: pip install pandas")

        if self.include_features:
            return to_dataframe(flows)
        return pd.DataFrame([flow.to_dict() for flow in flows])

    def to_dict(self, flows: list[Flow]) -> list[dict]:
        """Convert flows to list of dictionaries."""
        if not self.include_features:
            return [flow.to_dict() for flow in flows]
        return to_list_of_dicts(flows, flatten_features=self.flatten_features)

    def to_json(self, flows: list[Flow], path: str | Path, indent: int = 2) -> None:
        """
        Export flows to JSON file.

        Args:
            flows: List of Flow objects
            path: Output JSON file path
            indent: JSON indentation level (default: 2)
        """
        data = self.to_dict(flows)
        path = Path(path)

        with open(path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=indent, default=str)

    def to_csv(self, flows: list[Flow], path: str | Path) -> None:
        """
        Export flows to CSV file.

        Args:
            flows: List of Flow objects
            path: Output CSV file path
        """
        df = self.to_dataframe(flows)
        path = Path(path)
        df.to_csv(path, index=False)

    def save(self, flows: list[Flow], path: str | Path) -> None:
        """
        Save flows to file based on extension.

        Automatically detects the output format from the file extension:
        - .json: JSON format
        - .csv: CSV format (requires pandas)
        - .parquet: Parquet format (requires pyarrow)

        Args:
            flows: List of Flow objects
            path: Output file path

        Raises:
            ValueError: If file extension is not supported

        Examples:
            >>> exporter.save(flows, 'output.csv')
            >>> exporter.save(flows, 'output.json')
            >>> exporter.save(flows, 'output.parquet')
        """
        path = Path(path)
        suffix = path.suffix.lower()

        if suffix == '.json':
            self.to_json(flows, path)
        elif suffix == '.csv':
            self.to_csv(flows, path)
        elif suffix == '.parquet':
            df = self.to_dataframe(flows)
            df.to_parquet(path, index=False)
        else:
            raise ValueError(f"Unsupported file extension: {suffix}")
