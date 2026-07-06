from src.sdk.scope_importer import extract_scope_domains


def test_extract_scope_domains_filters_platform_noise_with_hint():
    page = """
    Bugcrowd engagement for Example.
    In scope targets:
      example.com
      *.example.com
      api.example.com
    Out of page chrome:
      bugcrowd.com docs.bugcrowd.com cdn.cloudflare.com schema.org
      static.example.com/app.js
      evil.net
    """

    imported, ignored = extract_scope_domains(
        page,
        root_hint="example.com",
        source_host="bugcrowd.com",
    )

    assert imported == ["*.example.com", "api.example.com", "example.com"]
    assert "bugcrowd.com" in ignored
    assert "evil.net" in ignored


def test_extract_scope_domains_without_hint_ignores_source_platform():
    page = "Targets: tripadvisor.com *.tripadvisor.com www.tripadvisor.com bugcrowd.com"

    imported, ignored = extract_scope_domains(page, source_host="bugcrowd.com")

    assert imported == ["*.tripadvisor.com", "tripadvisor.com", "www.tripadvisor.com"]
    assert "bugcrowd.com" in ignored
