"""Measure the selected Argon2id configuration and save honest results."""

import csv
import platform
import statistics
import time
from pathlib import Path

from src.auth import config
from src.auth.password import create_password_record, verify_password


def main() -> None:
    results = []
    password = "Benchmark-Password-2026"
    create_password_record(password)  # warm-up
    for _ in range(5):
        start = time.perf_counter()
        record = create_password_record(password)
        create_seconds = time.perf_counter() - start
        start = time.perf_counter()
        assert verify_password(password, record)
        verify_seconds = time.perf_counter() - start
        results.append((create_seconds, verify_seconds))

    output = Path("data/argon2_benchmark.csv")
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(["run", "create_seconds", "verify_seconds"])
        for number, (create_time, verify_time) in enumerate(results, 1):
            writer.writerow([number, f"{create_time:.6f}", f"{verify_time:.6f}"])

    verify_times = [item[1] for item in results]
    print("Machine:", platform.platform())
    print("Memory cost:", config.ARGON2_MEMORY_COST, "KiB")
    print("Time cost:", config.ARGON2_TIME_COST)
    print("Parallelism:", config.ARGON2_PARALLELISM)
    print("Average verification:", f"{statistics.mean(verify_times):.4f}", "seconds")
    print("Median verification:", f"{statistics.median(verify_times):.4f}", "seconds")
    print("Results saved to", output)


if __name__ == "__main__":
    main()
