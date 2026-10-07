from app.services.url_analyzer import URLAnalyzer


def test_extract_urls():
    analyzer = URLAnalyzer()

    text = (
        "Visit https://example.com and "
        "https://example.org/login for more information."
    )

    assert analyzer.extract_urls(text) == [
        "https://example.com",
        "https://example.org/login",
    ]


def test_extract_urls_removes_trailing_punctuation():
    analyzer = URLAnalyzer()

    text = "Check this link: https://example.com/refund."

    assert analyzer.extract_urls(text) == [
        "https://example.com/refund"
    ]


def test_extract_urls_removes_duplicates():
    analyzer = URLAnalyzer()

    text = (
        "https://example.com/login "
        "https://example.com/login"
    )

    assert analyzer.extract_urls(text) == [
        "https://example.com/login"
    ]


def test_http_url_is_flagged():
    analyzer = URLAnalyzer()

    signals = analyzer.analyze(
        "Visit http://example.com/login"
    )

    assert "URL uses HTTP instead of HTTPS" in signals


def test_url_shortener_is_flagged():
    analyzer = URLAnalyzer()

    signals = analyzer.analyze(
        "Click https://bit.ly/refund123"
    )

    assert "URL uses a known URL shortener" in signals


def test_ip_address_url_is_flagged():
    analyzer = URLAnalyzer()

    signals = analyzer.analyze(
        "Visit http://192.168.1.20/login"
    )

    assert "URL uses an IP address instead of a domain" in signals


def test_non_standard_port_is_flagged():
    analyzer = URLAnalyzer()

    signals = analyzer.analyze(
        "Visit https://example.com:8080/login"
    )

    assert "URL uses a non-standard port" in signals


def test_nested_subdomains_are_flagged():
    analyzer = URLAnalyzer()

    signals = analyzer.analyze(
        "Visit https://login.verify.account.example.com"
    )

    assert "URL contains multiple nested subdomains" in signals


def test_at_symbol_is_flagged():
    analyzer = URLAnalyzer()

    signals = analyzer.analyze(
        "Visit https://example.com@evil.example/login"
    )

    assert "URL contains an @ symbol" in signals


def test_encoded_url_is_flagged():
    analyzer = URLAnalyzer()

    signals = analyzer.analyze(
        "Visit https://example.com/%6cogin"
    )

    assert "URL contains percent-encoded characters" in signals


def test_payment_related_path_is_flagged():
    analyzer = URLAnalyzer()

    signals = analyzer.analyze(
        "Visit https://example.com/upi/payment/verify"
    )

    assert (
        "URL contains payment, verification, account, or "
        "credential-related terms"
    ) in signals


def test_multiple_url_signals_are_detected():
    analyzer = URLAnalyzer()

    signals = analyzer.analyze(
        "Click http://192.168.1.20:8080/upi/verify"
    )

    assert "URL uses HTTP instead of HTTPS" in signals
    assert "URL uses an IP address instead of a domain" in signals
    assert "URL uses a non-standard port" in signals
    assert (
        "URL contains payment, verification, account, or "
        "credential-related terms"
    ) in signals


def test_benign_https_url_has_no_suspicious_url_signal():
    analyzer = URLAnalyzer()

    signals = analyzer.analyze(
        "Visit https://example.com/about"
    )

    assert signals == []