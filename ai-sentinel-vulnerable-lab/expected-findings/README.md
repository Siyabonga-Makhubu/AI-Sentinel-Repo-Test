# Ground truth

`intended_findings` lists targets and evidence; `confirmed_findings` is reserved for results actually emitted by a scanner. The checked-in manifest intentionally does not claim a scanner run occurred. `scripts/validate-results.py` compares scanner output to the inventory and distinguishes invalid output and scanner errors from missing detections. Review advisory source severity independently of scanner severity labels.
