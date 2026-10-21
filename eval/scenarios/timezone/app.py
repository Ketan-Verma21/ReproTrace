"""Expects India Standard Time (UTC+05:30), e.g. for date-boundary logic."""

import time

offset = time.localtime().tm_gmtoff
if offset != 19800:
    raise SystemExit(f"expected UTC+05:30, got an offset of {offset} seconds")
print("timezone ok")
