## Summary

<!-- What does this PR change and why? Link related issues (e.g. "Fixes #12"). -->

## Checklist

- [ ] Tests added or updated (attack fires **and** benign variant stays quiet for detections)
- [ ] `QT_QPA_PLATFORM=offscreen python -m pytest` passes
- [ ] `python -m pyflakes ot_pcap_analyzer tests` shows no errors
- [ ] No captures, reports, databases or credentials committed
- [ ] README / CHANGELOG updated if behaviour or usage changed
