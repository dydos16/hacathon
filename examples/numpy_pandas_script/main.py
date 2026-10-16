"""Линейная аппроксимация растворимости от температуры (учебные данные)."""

import numpy as np
import pandas as pd

if __name__ == "__main__":
    table = pd.read_csv("data/measurements.csv")
    slope, intercept = np.polyfit(table["temperature_c"], table["solubility_g_per_100ml"], deg=1)
    print(table.describe().round(2))
    print(f"solubility = {slope:.3f} * T + {intercept:.2f}")
