from scipy.signal import savgol_filter


def smooth(values):
    return savgol_filter(values, window_length=5, polyorder=2)
