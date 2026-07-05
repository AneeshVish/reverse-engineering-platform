"""R(C_d) reward scoring for MCGD iterations."""

from dataclasses import dataclass

ALPHA = 0.15
BETA = 0.25
GAMMA = 0.50
DELTA = 0.10

VERIFIED_THRESHOLD = 0.8


@dataclass
class RewardScore:
    total: float
    syntax: float
    compile: float
    exec_rate: float
    fidelity: float
    verified: bool


def compute_reward(
    syntax_ok: bool,
    compile_ok: bool,
    exec_pass_rate: float,
    fidelity: float = 0.0,
    alpha=ALPHA,
    beta=BETA,
    gamma=GAMMA,
    delta=DELTA,
) -> RewardScore:
    s = 1.0 if syntax_ok else 0.0
    c = 1.0 if compile_ok else 0.0
    e = max(0.0, min(1.0, exec_pass_rate))
    f = max(0.0, min(1.0, fidelity))
    total = alpha * s + beta * c + gamma * e + delta * f
    verified = syntax_ok and compile_ok and e >= VERIFIED_THRESHOLD
    return RewardScore(total=total, syntax=s, compile=c, exec_rate=e, fidelity=f, verified=verified)
