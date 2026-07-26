from processors.base_processor import BaseProcessor
import pandas as pd


class LinuxProcessor(BaseProcessor):
    """
    Processor for Linux system/auth logs.
    NOT YET IMPLEMENTED - no sample data available to build real normalization logic against.
    Raises explicitly rather than silently passing data through unnormalized.
    """

    def validate(self, dataframe: pd.DataFrame) -> bool:
        raise NotImplementedError(
            "LinuxProcessor is not yet implemented - no sample Linux log data available."
        )

    def normalize(self, dataframe: pd.DataFrame) -> pd.DataFrame:
        self.validate(dataframe)
        return dataframe