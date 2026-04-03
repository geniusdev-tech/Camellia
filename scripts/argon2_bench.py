import time
import statistics
from argon2 import PasswordHasher

def benchmark_argon2():
    ph = PasswordHasher()
    password = "CorrectHorseBatteryStaple"

    print(f"Benchmarking Argon2 with default parameters...")
    print(f"Parameters: {ph.type.name}, time_cost={ph.time_cost}, memory_cost={ph.memory_cost}, parallelism={ph.parallelism}")

    hash_times = []
    verify_times = []

    # Warmup
    ph.hash(password)

    for i in range(5):
        start = time.perf_counter()
        hashed = ph.hash(password)
        end = time.perf_counter()
        hash_times.append(end - start)

        start = time.perf_counter()
        ph.verify(hashed, password)
        end = time.perf_counter()
        verify_times.append(end - start)

        print(f"Iteration {i+1}: Hash={hash_times[-1]:.4f}s, Verify={verify_times[-1]:.4f}s")

    print("\nResults:")
    print(f"Average Hash Time:   {statistics.mean(hash_times):.4f}s")
    print(f"Average Verify Time: {statistics.mean(verify_times):.4f}s")

    # Target is usually < 0.5s for password hashing in many security recommendations
    if statistics.mean(hash_times) > 1.0:
        print("\nWARNING: Argon2 hashing is taking more than 1 second. Consider adjusting parameters for your hardware.")

if __name__ == "__main__":
    benchmark_argon2()
