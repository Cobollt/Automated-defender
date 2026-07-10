import math


def calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0

    counts = [0] * 256

    for byte in data:
        counts[byte] += 1

    entropy = 0.0
    data_length = len(data)

    for count in counts:
        if count == 0:
            continue

        probability = count / data_length
        entropy -= probability * math.log2(probability)

    return entropy
