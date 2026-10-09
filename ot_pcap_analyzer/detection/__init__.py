"""
Extended detection components for OT PCAP Analyzer.

``behavior``      :class:`BehaviorProfiler` - post-capture behavioural analysis
                  (new masters / devices / functions, polling deviations,
                  out-of-range written values) learnt from the start of the capture.
``rules_engine``  :class:`RuleEngine` - user-defined, Suricata-like detection rules
                  for decoded OT events, loaded from YAML or JSON files.

Both modules only depend on the standard library (PyYAML is optional, used
only to read ``*.yml`` / ``*.yaml`` rule files).
"""
