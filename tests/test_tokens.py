"""令牌签发/校验：过期、伪造、签名无效的原因可区分。"""
import logging

import pytest

from app.errors import AuthError, FailureReason
from app.tokens import decode_token, encode_access_token

logger = logging.getLogger("auth-tests")
SECRET = "k"


def test_roundtrip():
    tok = encode_access_token(SECRET, "u", "s1", frozenset({"read"}), now=100, ttl=60, jti="j1")
    claims = decode_token(SECRET, tok, now=159)
    logger.info("用例=令牌往返 | 输入=sub=u,scopes=[read],now=159 | 判定依据=签名有效且未过期 | 结果=%s", claims)
    assert claims.sub == "u" and claims.scopes == frozenset({"read"})


@pytest.mark.parametrize("bad,reason,basis", [
    ("not-a-token", FailureReason.TOKEN_INVALID, "段数不为3 -> 格式错误"),
    (None, FailureReason.TOKEN_INVALID, "签名被篡改 -> 签名无效"),  # None 占位，运行时替换
    ("wrong-secret", FailureReason.TOKEN_INVALID, "密钥不符 -> 签名无效"),
    ("expired", FailureReason.TOKEN_EXPIRED, "now >= exp -> 过期"),
])
def test_distinguishable_failures(bad, reason, basis):
    tok = encode_access_token(SECRET, "u", "s1", frozenset(), now=100, ttl=60, jti="j")
    if bad is None:
        bad = tok[:-2] + ("aa" if not tok.endswith("aa") else "bb")
    elif bad == "wrong-secret":
        bad = encode_access_token("other", "u", "s1", frozenset(), 100, 60, "j")
    elif bad == "expired":
        bad = tok
    now = 200 if reason == FailureReason.TOKEN_EXPIRED else 150
    with pytest.raises(AuthError) as exc:
        decode_token(SECRET, bad, now=now)
    logger.info("用例=失败区分 | 输入=%s | 判定依据=%s | 结果=%s", basis, basis, exc.value.reason)
    assert exc.value.reason == reason
