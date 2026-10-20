"""agentgate - layered screening and hijack-resistance for AI-agent operators."""
__version__ = "1.2.1"

from .gate import (normalize_text, verify_chain, Gate, Decision, Finding, rule_classifier, POLICY, TIER_ANON, TIER_VERIFIED, TIER_VERIFIED_SECURITY,
                   ALLOW, ALLOW_LOGGED, SUPPORT, BLOCK, ESCALATE, SUSPENDED, STEP_UP)
from .behavior import BehaviorMonitor, backtest
from .transport import TransportMonitor, DestinationMonitor
from .tripwire import HoneyTokens, ReconDetector, TypingMonitor
from .signing import DeviceRegistry, make_proof, public_hex
from .approval import ApprovalService, make_approval
from .anchor import anchor_log, verify_anchors, ots_upgrade, ots_verify
from .webauthn import verify_registration, verify_assertion, WebAuthnError, b64u, b64u_dec
from .softauth import SoftAuthenticator
from .edge import build_meta, ja3, classify_net
from .calibrate import calibrate
from .llm_classifier import LLMClassifier, LawKB, anthropic_llm, kb_status, kb_approve

__all__ = [n for n in dir() if not n.startswith("_")]
