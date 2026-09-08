# Reproducibility checklist

This checklist accompanies the [worked example](README.md). It is not a certification of a biological analysis.

| Question | Evidence or current limit |
| --- | --- |
| Which data? | GEO GSE85241; exact original URL, compressed-file size, and SHA-256 are in the code, README and observed record. |
| Whose data? | Muraro and colleagues; publication DOI and GEO accession are cited. No affiliation or endorsement is implied. |
| Which representation? | Submitted processed fractional expression values; no conversion to raw integer counts. |
| What was included? | Every submitted column; no quality-control filtering, annotation or clustering. ERCC spike-in rows are counted separately. |
| Which code and choices? | Exact code references, script hash, parameters and existing verifier identity are recorded. |
| Which environment? | Observed Python and package versions are recorded; the workflow logs resolved packages. A fully hash-locked dependency/container build is not claimed. |
| What actually ran? | A full file summary, repeated twice, receipt checks and input/output file checks; no scoring-method or differential-expression run. |
| Did the result repeat? | The recorded runs produced byte-identical summary output. Fresh workflow output matched the retained summary and receipt. |
| Do changed artifacts fail? | Changed payload and changed output are rejected against the fixed reference; synthetic input-validation cases are separate tests. |
| What is the independent unit? | No hypothesis test here. Source labels preserve donor grouping, not authenticated identity or an adequate experimental design. |
| Is authorship established? | No. The record is unsigned; replacing the reference and all its hashes is outside its guarantee. |
| Is scientific validity established? | No. Biological findings, causal effects, clinical safety and scoring superiority were not tested. |
| Was there external review? | Not claimed. Ask an independent researcher to reproduce the instructions before making that claim. |
| Can every future use or redistribution proceed? | Not assumed. Review applicable data and software terms for the intended use. |

## Next-step order

Publish the narrow example with attribution and one immutable link. Invite a reproduction attempt. Then freeze a separate scoring-method protocol, dataset and environment before collecting comparative results. Add trusted signing or a new public mirror only through a separately tested release; do not retroactively describe this unsigned record as signed.
