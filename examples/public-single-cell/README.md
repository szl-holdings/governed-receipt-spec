# A reproducible single-cell data example

This example downloads a public human pancreatic single-cell expression file, computes a small descriptive summary twice, and checks that the recorded input and output files agree with an analysis receipt. It also deliberately changes the receipt payload and the output file to test rejection.

**This is a reproducibility and file-integrity demonstration, not a new gene-signature scoring method or a biological finding.** It does not run AUCell, UCell, Seurat, differential expression, cell annotation, or clinical inference.

## Public data and attribution

The data are from Muraro et al., *A Single-Cell Transcriptome Atlas of the Human Pancreas*, Cell Systems (2016), DOI [10.1016/j.cels.2016.09.002](https://doi.org/10.1016/j.cels.2016.09.002), deposited as [GEO GSE85241](https://www.ncbi.nlm.nih.gov/geo/query/acc.cgi?acc=GSE85241). The original researchers produced the data. This example is not affiliated with them or with GEO.

The exact supplementary file is:

```text
https://ftp.ncbi.nlm.nih.gov/geo/series/GSE85nnn/GSE85241/suppl/GSE85241_cellsystems_dataset_4donors_updated.csv.gz
SHA-256: 2f253ffb1f6d54f6bb259e862195f5c20ea3f13e00471b9864ff92773658f513
Bytes: 17005498
```

Despite the filename, the decompressed file is tab-delimited. It contains submitted **processed, potentially fractional expression values**, not a raw integer count matrix. No values are rounded or renormalized here. The example downloads the original file from GEO; it does not redistribute the expression matrix or claim ownership of it. Availability is not a blanket grant of rights for every future use.

## What the calculation does

The script reads every submitted cell column and feature row. It counts features whose submitted value is greater than zero, records ERCC spike-in rows separately, and reports the minimum, median, and maximum number of detected endogenous features per cell within each source donor label. All submitted columns are retained, including columns with no positive endogenous features. There is no quality-control filtering, clustering, group comparison, or hypothesis test.

The donor labels are parsed from the submitted column names. They preserve the source grouping; they do not independently authenticate a donor identity or establish independent experimental replication for another study.

## Run it

From the root of this repository, using Python 3.12 and an isolated environment:

```sh
python -m venv .venv
# Linux/macOS:
. .venv/bin/activate
# Windows PowerShell alternative: .venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m unittest discover -s tests -p test_public_single_cell.py -v
python examples/public-single-cell/run_example.py --output /tmp/public-single-cell-example
```

Choose a new output directory for each run. On Windows, use a new local directory instead of `/tmp/public-single-cell-example`. An existing downloaded copy can be supplied with `--input PATH`; the same exact byte count and SHA-256 checks still apply. The online step reads one fixed public scientific file, without credentials.

The runner requires the reviewed existing verifier blob `84cd6b67a6a9052dc6ec6a334c810b6b4752bc8f`. A verifier change requires explicit review of that pin rather than silently accepting a different implementation.

## Outputs and verification boundary

`summary.json` contains the descriptive result and exact parameters. `receipt.json` records the input identity, analysis-script identity, and output hash in an explicitly unsigned in-toto statement envelope. `verification.json` records the checks actually exercised, package versions, and the existing verifier's report. `environment.txt` records the execution environment.

The existing repository verifier checks the receipt envelope, statement structure, and recorded payload hash. The new example adapter separately checks the actual downloaded input, actual summary file, declared parameters, and source-script identity. The full summary calculation runs twice and must produce identical bytes. Deliberately changed receipt payloads and deliberately changed summary files must be rejected when the recorded reference is held fixed.

**No signature or trusted authorship is verified.** An unsigned content hash detects a mismatch against a retained reference; it cannot establish who created the reference or prevent an attacker from replacing all files and all hashes together. The record also does not establish biological correctness, appropriate statistical design, or clinical safety. Existing verifier checks that are not applicable to this non-inference example are not counted as biological or signature validation.

## Methodological context

[Methods and limitations](METHODS_NOTES.md) explains how this demonstration relates to established single-cell scoring methods and donor-aware statistical inference. Those methods are not benchmarked by this example.

## Executed evidence

The `Public single-cell example` workflow performs the real download and calculation rather than substituting unit-test fixtures for observations. It records its actual Git checkout and resolved packages, then retains the small result, receipt, and verification files as a run artifact. The large expression matrix is not uploaded. A run is successful only after the intact bundle, repeat calculation, and both negative controls pass.

A successful workflow is evidence about that run and exact source, not an endorsement by the data authors or an evaluation of a biological hypothesis.
