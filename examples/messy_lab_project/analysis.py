"""«Сырой» проект лаборатории: так выглядит код, который не запускается у коллеги."""

import importlib
import os
import sys
from distutils.version import LooseVersion

import cv2
import jwt
import numpy as np
import pandas as pd
import yaml
from sklearn.linear_model import LinearRegression

from lab.filters import smooth
import labtools_internal

try:
    import ujson as json
except ImportError:
    import json

API_KEY = "sk-DEMO0000000000000000000000000000fake"
RAW_DATA = "/Users/ivan/lab/raw_2024.csv"


def load_plugin(name):
    return importlib.import_module(f"plugins.{name}")


def main():
    config = yaml.safe_load(open("config.yaml"))
    table = pd.read_excel("results/spectra.xlsx")
    noise = np.random.normal(0, 0.1, size=len(table))
    model = LinearRegression().fit(table[["x"]], smooth(table["y"]) + noise)
    print(json.dumps({"coef": float(model.coef_[0]), "threshold": config["threshold"]}))
    print(LooseVersion(np.__version__), cv2.__version__, jwt.__name__, os.getcwd())
    load_plugin(sys.argv[1] if len(sys.argv) > 1 else "baseline")


if __name__ == "__main__":
    main()
