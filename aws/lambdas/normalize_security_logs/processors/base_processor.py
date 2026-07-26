"""
Base processor for all security log processors.

Every security log processor must inherit from this class.
"""

from abc import ABC, abstractmethod
import pandas as pd


class BaseProcessor(ABC):
    """
    Abstract base class for all security log processors.
    """

    @abstractmethod
    def validate(self, dataframe: pd.DataFrame) -> bool:
        """
        Validate whether the input dataset can be processed.

        Args:
            dataframe: Input DataFrame.

        Returns:
            True if valid, otherwise False.
        """
        pass

    @abstractmethod
    def normalize(self, dataframe: pd.DataFrame) -> pd.DataFrame:
        """
        Convert raw logs into the common schema.

        Args:
            dataframe: Raw input DataFrame.

        Returns:
            Normalized DataFrame.
        """
        pass