
from __future__ import annotations

import argparse
import platform
import statistics
import sys
import time
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


from src.auth import config
from src.auth.password import (
    create_password_record,
    derive_password_secret,
)

DEFAULT_PASSWORD = "SecureVault-Benchmark-Password-2026!"

DEFAULT_TRIALS = 10

DEFAULT_WARMUP_RUNS = 2


def print_machine_information() -> None:

    print()
    print("=" * 64)
    print("MACHINE INFORMATION")
    print("=" * 64)

    print(f"System           : {platform.system()}")
    print(f"Release          : {platform.release()}")
    print(f"Machine          : {platform.machine()}")
    print(f"Processor        : {platform.processor() or 'Unknown'}")
    print(f"Python version   : {platform.python_version()}")


def print_argon2_configuration(record) -> None:

    print()
    print("=" * 64)
    print("ARGON2ID CONFIGURATION")
    print("=" * 64)

    print(f"Algorithm        : {record.algorithm}")

    print(
        f"Memory cost      : "
        f"{record.memory_cost} KiB "
        f"({record.memory_cost / 1024:.2f} MiB)"
    )

    print(f"Time cost        : {record.time_cost}")
    print(f"Parallelism      : {record.parallelism}")
    print(f"Output length    : {record.hash_length} bytes")
    print(f"Salt length      : {len(record.salt)} bytes")
    print(f"Argon2 version   : {record.version}")

def benchmark_argon2(
    password: str,
    trials: int,
    warmup_runs: int,
) -> list[float]:

    if trials <= 0:
        raise ValueError(
            "Number of trials must be greater than zero."
        )

    if warmup_runs < 0:
        raise ValueError(
            "Number of warm-up runs cannot be negative."
        )

    record = create_password_record(password)

    print_argon2_configuration(record)

    print()
    print("=" * 64)
    print("WARM-UP")
    print("=" * 64)

    if warmup_runs == 0:
        print("No warm-up runs requested.")

    else:

        for index in range(1, warmup_runs + 1):

            start = time.perf_counter()

            secret = derive_password_secret(
                password,
                record,
            )

            elapsed = time.perf_counter() - start

            if len(secret) != record.hash_length:
                raise RuntimeError(
                    "Argon2id returned an unexpected output length."
                )

            print(
                f"Warm-up {index:02d}: "
                f"{elapsed * 1000:.2f} ms"
            )

    print()
    print("=" * 64)
    print("MEASURED TRIALS")
    print("=" * 64)

    measurements_ms: list[float] = []

    for index in range(1, trials + 1):

        start = time.perf_counter()

        secret = derive_password_secret(
            password,
            record,
        )

        elapsed_seconds = (
            time.perf_counter() - start
        )

        elapsed_ms = (
            elapsed_seconds * 1000
        )

        if len(secret) != record.hash_length:
            raise RuntimeError(
                "Argon2id returned an unexpected output length."
            )

        measurements_ms.append(
            elapsed_ms
        )

        print(
            f"Trial {index:02d}: "
            f"{elapsed_ms:.2f} ms"
        )

    return measurements_ms


def print_results(
    measurements_ms: list[float],
) -> None:
    """
    Print summary statistics for the benchmark.
    """

    if not measurements_ms:
        raise ValueError(
            "No benchmark measurements were provided."
        )

    minimum = min(measurements_ms)

    maximum = max(measurements_ms)

    average = statistics.mean(
        measurements_ms
    )

    median = statistics.median(
        measurements_ms
    )

    if len(measurements_ms) > 1:

        standard_deviation = statistics.stdev(
            measurements_ms
        )

    else:

        standard_deviation = 0.0

    if median > 0:

        guesses_per_second = (
            1000.0 / median
        )

    else:

        guesses_per_second = float("inf")

    print()
    print("=" * 64)
    print("BENCHMARK RESULTS")
    print("=" * 64)

    print(
        f"Number of trials : "
        f"{len(measurements_ms)}"
    )

    print(
        f"Minimum time     : "
        f"{minimum:.2f} ms"
    )

    print(
        f"Maximum time     : "
        f"{maximum:.2f} ms"
    )

    print(
        f"Average time     : "
        f"{average:.2f} ms"
    )

    print(
        f"Median time      : "
        f"{median:.2f} ms"
    )

    print(
        f"Std. deviation   : "
        f"{standard_deviation:.2f} ms"
    )

    print(
        f"Approx. sequential guesses/sec on this machine: "
        f"{guesses_per_second:.2f}"
    )

    print()
    print(
        "NOTE: The guesses/second value above is only a sequential "
        "CPU estimate for this machine."
    )

    print(
        "It is NOT a GPU cracking benchmark and should not be "
        "reported as one."
    )

    print()
    print("=" * 64)
    print("INTERPRETATION")
    print("=" * 64)

    if 200 <= median <= 300:

        print(
            "The median derivation time is approximately within "
            "the 200-300 ms target range."
        )

    elif median < 200:

        print(
            "The median derivation time is below 200 ms."
        )

        print(
            "The team may consider increasing the Argon2id work "
            "factor after evaluating login usability."
        )

    else:

        print(
            "The median derivation time is above 300 ms."
        )

        print(
            "The team should evaluate whether the current cost is "
            "acceptable for interactive login."
        )


def parse_arguments() -> argparse.Namespace:
    """
    Parse command-line benchmark options.
    """

    parser = argparse.ArgumentParser(
        description=(
            "Benchmark SecureVault's Argon2id password derivation."
        )
    )

    parser.add_argument(
        "--trials",
        type=int,
        default=DEFAULT_TRIALS,
        help=(
            "Number of measured Argon2id derivations "
            f"(default: {DEFAULT_TRIALS})."
        ),
    )

    parser.add_argument(
        "--warmup",
        type=int,
        default=DEFAULT_WARMUP_RUNS,
        help=(
            "Number of warm-up derivations excluded from results "
            f"(default: {DEFAULT_WARMUP_RUNS})."
        ),
    )

    return parser.parse_args()


def main() -> None:
    """
    Run the complete Argon2id benchmark.
    """

    args = parse_arguments()

    print()
    print("=" * 64)
    print("SECUREVAULT ARGON2ID BENCHMARK")
    print("=" * 64)

    print_machine_information()

    measurements = benchmark_argon2(
        password=DEFAULT_PASSWORD,
        trials=args.trials,
        warmup_runs=args.warmup,
    )

    print_results(
        measurements
    )

    print()
    print("=" * 64)
    print("BENCHMARK COMPLETE")
    print("=" * 64)
    print()


if __name__ == "__main__":
    main()