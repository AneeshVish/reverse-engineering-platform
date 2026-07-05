# ExeBench-style harness subset — honest MCGD metrics (no paper claims).
# Run: pytest tests/benchmarks/test_exebench_harness.py

SAMPLE_FUNCTIONS = [
    {
        "name": "hello_main",
        "source": '#include <stdio.h>\nint main(void){printf("hi\\n");return 0;}\n',
    },
]
