### IMPORTS
### ============================================================================
# Package
from parsedmarc import utils


### TESTS
### ============================================================================
def test_base64_decoding():
    b64_str = "YW55IGNhcm5hbCBwbGVhcw"
    decoded_str = utils.decode_base64(b64_str)
    assert decoded_str == b"any carnal pleas"
    return


def test_psl_download():
    subdomain = "foo.example.com"
    result = utils.get_base_domain(subdomain)
    assert result == "example.com"

    # Test newer PSL entries
    subdomain = "e3191.c.akamaiedge.net"
    result = utils.get_base_domain(subdomain)
    assert result == "c.akamaiedge.net"
    return
