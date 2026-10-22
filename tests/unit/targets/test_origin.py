"""origin 的嚴格解析（docs/DECISIONS.md §10.2、SEC-05）。

只接受各家 URL parser 解讀一致的子集：拒絕的輸入不能變成「看起來像別的 host」，接受的輸入
以 canonical 形式保存，而且標準函式庫 urlsplit 解出的 host 與 port 必須相同。
"""

import re
import socket
from urllib.parse import urlsplit

import pytest
from hypothesis import find, given
from hypothesis import strategies as st

from secscan.targets.domain import ORIGIN_MAX_LENGTH, InvalidOriginError, Origin, parse_origin

# 非 ASCII 的測試字元以程式產生，原始碼中不放容易誤認的字元。
FULLWIDTH_LAB = "".join(chr(ord(letter) + 0xFEE0) for letter in "lab")
LATIN_LAB = "l" + chr(0xE4) + "b"
KATAKANA_LAB = chr(0x30E9) + chr(0x30DC)
NO_BREAK_SPACE = chr(0xA0)
CANONICAL_SHAPE = r"http://[a-z0-9.-]+(:[1-9][0-9]{0,4})?"


@pytest.mark.parametrize(
    ("value", "canonical"),
    [
        ("http://vampi-vuln:5000", "http://vampi-vuln:5000"),
        ("http://vampi-vuln:5000/", "http://vampi-vuln:5000"),
        ("HTTP://Vampi-Vuln:5000", "http://vampi-vuln:5000"),
        ("http://juice-shop:3000", "http://juice-shop:3000"),
        ("http://lab", "http://lab"),
        ("http://lab:80", "http://lab"),
        ("http://lab:80/", "http://lab"),
        ("http://10.89.7.20:5000", "http://10.89.7.20:5000"),
        ("http://api.lab.internal:8080", "http://api.lab.internal:8080"),
        ("http://a", "http://a"),
        ("http://123.lab:1", "http://123.lab:1"),
        ("http://lab:65535", "http://lab:65535"),
    ],
)
def test_accepts_http_origins_and_canonicalizes_them(value: str, canonical: str) -> None:
    origin = parse_origin(value)

    assert str(origin) == canonical
    assert parse_origin(canonical) == origin


def test_origin_parts() -> None:
    assert parse_origin("http://Lab:5000") == Origin(host="lab", port=5000)
    assert parse_origin("http://lab").port == 80
    assert parse_origin("http://10.89.7.20:5000").ip is not None
    assert parse_origin("http://lab:5000").ip is None


@pytest.mark.parametrize(
    ("host", "port"),
    [
        ("LAB", 80),
        ("lab.", 80),
        ("0x0a.89.7.20", 80),
        ("localhost", 80),
        ("lab", 0),
        ("lab", 65536),
    ],
)
def test_origin_constructed_directly_keeps_the_canonical_rules(host: str, port: int) -> None:
    """從 DB 讀回的 origin 也經過相同的規則（例如 host 必須已是小寫）。"""
    with pytest.raises(InvalidOriginError):
        Origin(host=host, port=port)


@pytest.mark.parametrize(
    "value",
    [
        # 不是 http://host[:port] 的形式
        "",
        "lab:5000",
        "//lab:5000",
        "http:lab",
        "http:/lab",
        "http:///lab",
        "http://",
        "http://:5000",
        # 其他 scheme（P0 只支援 HTTP 靶場）
        "https://lab",
        "ftp://lab",
        "file:///etc/passwd",
        "javascript:alert(1)",
        "ws://lab",
        # userinfo
        "http://user@lab",
        "http://user:secret@lab:5000",
        "http://@lab",
        "http://lab@evil",
        # 反斜線（WHATWG 把它當成斜線，urlsplit 不會）
        "http://lab\\@evil",
        "http:\\\\lab",
        "http://lab\\",
        # percent-encoding
        "http://l%61b",
        "http://lab%2F",
        # path、query、fragment
        "http://lab/api",
        "http://lab:5000/api/",
        "http://lab//",
        "http://lab?x=1",
        "http://lab/?x",
        "http://lab#frag",
        "http://lab/#",
        # 空白、控制字元與非 ASCII
        " http://lab",
        "http://lab ",
        "http://la b",
        "http://lab\t",
        "http://lab\n",
        "http://lab\x00",
        "http://lab\x7f",
        f"http://lab{NO_BREAK_SPACE}",
        f"http://{FULLWIDTH_LAB}",
        f"http://{LATIN_LAB}",
        f"http://{KATAKANA_LAB}",
        # IPv6
        "http://[::1]",
        "http://[::ffff:10.89.7.20]:80",
        "http://::1",
        # 主機名稱的格式
        "http://lab.",
        "http://lab.:5000",
        "http://.lab",
        "http://lab..internal",
        "http://-lab",
        "http://lab-",
        "http://la_b",
        "http://lab!",
        "http://xn--lb-via",
        "http://ab--cd",
        "http://" + "a" * 64,
        # 數字形式模糊的 host：只接受四段十進位、沒有前導 0 的 IPv4
        "http://0x0a.89.7.20",
        "http://0x0a59071a",
        "http://167772160",
        "http://012.89.7.20",
        "http://10.89.07.20",
        "http://10.89.7",
        "http://10.89.7.20.1",
        "http://10.89.7.256",
        "http://lab.1",
        "http://lab.0x1",
        "http://1e5",
        "http://2fa",
        "http://0",
        # 本機
        "http://localhost",
        "http://LOCALHOST:8000",
        "http://api.localhost",
        # port
        "http://lab:",
        "http://lab:0",
        "http://lab:080",
        "http://lab:00080",
        "http://lab:65536",
        "http://lab:99999",
        "http://lab:123456",
        "http://lab:-1",
        "http://lab:+80",
        "http://lab:8o",
        "http://lab:80:80",
        # 長度
        "http://" + "a." * 130 + "lab",
    ],
    ids=repr,
)
def test_rejects_ambiguous_or_unsupported_urls(value: str) -> None:
    with pytest.raises(InvalidOriginError):
        parse_origin(value)


def _url_of_length(length: int) -> str:
    """長度剛好是 length 的合法 URL：每一段都不超過 63 個字元，只有總長度會超過上限。"""
    host_length = length - len("http://")
    labels = ["a" * 63] * (host_length // 64)
    labels.append("b" * (host_length - 64 * len(labels)))
    return "http://" + ".".join(labels)


@pytest.mark.parametrize(
    ("value", "reason"),
    [
        ("lab", "http://"),
        ("https://lab", "HTTPS"),
        ("http://user@lab", "userinfo"),
        ("http://lab\\x", "反斜線"),
        ("http://l%61b", "percent-encoding"),
        ("http://lab?x", "query"),
        ("http://lab#x", "fragment"),
        ("http://[::1]", "IPv6"),
        (f"http://{FULLWIDTH_LAB}", "ASCII"),
        ("http://la b", "空白"),
        ("http://lab/api", "path"),
        ("http://localhost", "localhost"),
        ("http://0x0a.89.7.20", "四段十進位"),
        ("http://lab:080", "port"),
        ("http://la_b", "主機名稱"),
        ("http://", "缺少主機名稱"),
        ("http://" + "a" * 300, "256"),
    ],
)
def test_errors_explain_the_reason(value: str, reason: str) -> None:
    """拒絕的規則有重疊（例如反斜線也不是合法的主機名稱字元），訊息要指出第一個原因。"""
    with pytest.raises(InvalidOriginError, match=re.escape(reason)):
        parse_origin(value)


def test_length_limit() -> None:
    longest = _url_of_length(ORIGIN_MAX_LENGTH)

    assert len(longest) == ORIGIN_MAX_LENGTH
    assert str(parse_origin(longest)) == longest
    with pytest.raises(InvalidOriginError, match=str(ORIGIN_MAX_LENGTH)):
        parse_origin(_url_of_length(ORIGIN_MAX_LENGTH + 1))


@pytest.mark.parametrize(
    "value",
    [
        "http://user:hunter2-secret@lab:5000",
        "http://lab:5000/hunter2-secret",
        "http://lab?token=hunter2-secret",
        "https://hunter2-secret.lab",
    ],
)
def test_errors_never_echo_the_input(value: str) -> None:
    """URL 可能含帳密或 Token：錯誤訊息只說明原因。"""
    with pytest.raises(InvalidOriginError) as caught:
        parse_origin(value)

    assert "hunter2-secret" not in str(caught.value)


def test_parsing_does_not_resolve_names(monkeypatch: pytest.MonkeyPatch) -> None:
    """API 不對使用者給的 URL 發出任何流量（docs/DECISIONS.md §10.2）。"""

    def no_dns(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("parse_origin 不可解析 DNS")

    monkeypatch.setattr(socket, "getaddrinfo", no_dns)
    monkeypatch.setattr(socket, "gethostbyname", no_dns)

    assert str(parse_origin("http://vampi-vuln:5000")) == "http://vampi-vuln:5000"


# --- property test --------------------------------------------------------------------------

_LABEL = st.from_regex(r"[a-z]([a-z0-9-]{0,14}[a-z0-9])?", fullmatch=True).filter(
    lambda label: label[2:4] != "--"
)
_HOSTNAME = st.lists(_LABEL, min_size=1, max_size=4).map(".".join)
_IPV4 = st.tuples(*[st.integers(0, 255)] * 4).map(lambda parts: ".".join(map(str, parts)))
_PORT = st.integers(1, 65535)


@st.composite
def _valid_origins(draw: st.DrawFn) -> tuple[str, str, int]:
    """依規則組出的合法 origin：(輸入字串, host, port)。scheme 與 host 的大小寫隨機。"""
    host = draw(st.one_of(_HOSTNAME, _IPV4))
    port = draw(st.one_of(st.none(), _PORT))
    scheme = draw(st.sampled_from(["http", "HTTP", "Http"]))
    shown_host = draw(st.sampled_from([host, host.upper()]))
    suffix = draw(st.sampled_from(["", "/"]))
    authority = shown_host if port is None else f"{shown_host}:{port}"
    return f"{scheme}://{authority}{suffix}", host, 80 if port is None else port


@given(_valid_origins())
def test_valid_origins_are_accepted_canonically_and_agree_with_urlsplit(
    case: tuple[str, str, int],
) -> None:
    value, host, port = case

    origin = parse_origin(value)

    assert (origin.host, origin.port) == (host, port)
    assert parse_origin(str(origin)) == origin
    assert urlsplit(value).hostname == origin.host
    assert (urlsplit(value).port or 80) == origin.port


# 由合法與常見的危險片段拼成的 URL：約一半會被接受，另一半帶有某種模糊之處。
_SCHEME_PIECES = st.sampled_from(["http://", "HTTP://", "https://", "http:/", "http:", "//", ""])
_HOST_PIECES = st.one_of(
    _HOSTNAME,
    _IPV4,
    st.sampled_from(
        [
            "0x0a.89.7.20",
            "010.89.7.20",
            "167772160",
            "localhost",
            "lab.",
            ".lab",
            "la_b",
            "[::1]",
            "user@lab",
            "lab\\@evil",
            "l%61b",
            FULLWIDTH_LAB,
        ]
    ),
)
_PORT_PIECES = st.sampled_from(["", ":80", ":5000", ":65535", ":080", ":0", ":65536", ":", ":1:2"])
_SUFFIX_PIECES = st.sampled_from(["", "/", "//", "/api", "?q", "#f", " ", "\t", "/%2e"])
_MIXED_URLS = st.tuples(_SCHEME_PIECES, _HOST_PIECES, _PORT_PIECES, _SUFFIX_PIECES).map("".join)


@given(_MIXED_URLS)
def test_any_url_is_rejected_or_canonical(value: str) -> None:
    """只有兩種結果：拒絕，或得到 canonical origin，而且 urlsplit 解出相同的 host 與 port。"""
    try:
        origin = parse_origin(value)
    except InvalidOriginError:
        return

    canonical = str(origin)
    assert re.fullmatch(CANONICAL_SHAPE, canonical)
    assert parse_origin(canonical) == origin
    assert urlsplit(value).hostname == origin.host
    assert (urlsplit(value).port or 80) == origin.port


def _accepted(value: str) -> bool:
    try:
        parse_origin(value)
    except InvalidOriginError:
        return False
    return True


def test_mixed_urls_exercise_both_outcomes() -> None:
    """上面的 property test 不能空轉：拼出的 URL 必須同時有被接受與被拒絕的。

    找不到符合條件的例子時，find 會失敗。
    """
    assert _accepted(find(_MIXED_URLS, _accepted))
    assert not _accepted(find(_MIXED_URLS, lambda value: not _accepted(value)))


@given(st.text(max_size=300))
def test_arbitrary_text_only_raises_invalid_origin(value: str) -> None:
    """任意文字（含 Unicode 與控制字元）都不會引發 InvalidOriginError 以外的例外。"""
    try:
        origin = parse_origin(value)
    except InvalidOriginError:
        return
    assert parse_origin(str(origin)) == origin
