def zeroize_bytearray(buffer: bytearray) -> None:
    """
    Best-effort application-level zeroization subject to Python runtime,
    allocator, garbage collector and operating-system memory behavior.
    """
    if isinstance(buffer, bytearray):
        for i in range(len(buffer)):
            buffer[i] = 0
