# A reproducible single-cell data example

Can someone else identify the exact public data file, repeat a small calculation, and detect a changed result against the retained record?

This example answers that narrow engineering question. It is **not a new gene-signature scoring method or a biological finding**. It does not run AUCell, UCell, Seurat, differential expression, cell annotation, or clinical inference.

## Executed result

The real public-data calculation completed successfully in [this CPU run](https://huggingface.co/jobs/SZLHOLDINGS/6a9f615b259f8e97255ed671), using exact GitHub source `160e39b1383a0e249399b6dfb72983b67aef7fe8`. The [retained output and receipt](observed-run.json) were copied from that run, not generated from unit-test fixtures.

| Observed file property | Result |
| --- | ---: |
| Submitted cell columns, with no filtering | 3,072 |
| Source donor labels | 4 |
| Feature rows | 19,140 |
| Endogenous feature rows | 19,059 |
| ERCC spike-in rows | 81 |
| Columns per source donor label | 768 |

The calculation ran twice and produced byte-identical summary output. The intact bundle passed. A changed receipt payload and a changed summary file were both rejected against the unchanged recorded reference. The 14 synthetic regression tests also passed; those tests are distinct from the real-data run.

Summary SHA-256: `3a5539e922ae68687c806f35df540f365b0a249e1f654b87f5309d074ea77df6`.

These numbers describe the submitted file, not a quality-controlled cell atlas or the number of independent observations for a biological hypothesis. The per-donor detection summaries are descriptive only; their differences are not interpreted as biological effects.

## Public data and attribution

The data are from Muraro et al., *A Single-Cell Transcriptome Atlas of the Human Pancreas*, Cell Systems (2016), DOI [10.1016/j.cels.2016.09.002](https://doi.org/10.1016/j.cels.2016.09.002), deposited as [GEO GSE85241](https://www.ncbi.nlm.nih.gov/geo/query/acc.cgi?acc=GSE85241). The original researchers produced the data. This example is not affiliated with them or with GEO.

```text
https://ftp.ncbi.nlm.nih.gov/geo/series/GSE85nnn/GSE85241/suppl/GSE85241_cellsystems_dataset_4donors_updated.csv.gz
SHA-256: 2f253ffb1f6d54f6bb259e862195f5c20ea3f13e00471b9864ff92773658f513
Bytes: 17005498
```

Despite its filename, the decompressed file is tab-delimited. It contains submitted processed, fractional expression values, not a raw integer count matrix. No values are rounded or renormalized. The example downloads the original from GEO; this repository does not redistribute the expression matrix or claim ownership of it. Public availability is not a blanket grant of rights for every future use.

## Calculation

The script reads every submitted cell column and feature row. It counts features whose submitted value is greater than zero, records ERCC spike-in rows separately, and reports the minimum, median, and maximum detected endogenous features per cell within each source donor label. All columns are retained. There is no quality-control filtering, clustering, group comparison, or hypothesis test.

Donor labels are parsed from the submitted column names. They preserve the source grouping; they do not independently authenticate a donor identity or establish experimental replication for another study.

## Reproduce the recorded run

Use Python 3.12 in an isolated environment. From a new checkout:

```sh
git clone https://github.com/szl-holdings/governed-receipt-spec.git
cd governed-receipt-spec
git checkout 160e39b1383a0e249399b6dfb72983b67aef7fe8
python -m venv .venv
# Linux/macOS:
. .venv/bin/activate
# Windows PowerShell alternative: .venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m unittest discover -s tests -p test_public_single_cell.py -v
python examples/public-single-cell/run_example.py --output public-example-run-1
```

Choose a new output directory each time. An existing downloaded copy can be supplied with `--input PATH`; identical input-size and SHA-256 checks apply. The online step reads one fixed public scientific file without credentials. The two direct verifier dependencies are version-pinned; the linked run records Python and package versions. This is not a claim of a fully hermetic operating-system/container build.

The runner requires existing verifier blob `84cd6b67a6a9052dc6ec6a334c810b6b4752bc8f`. A verifier change requires review of that pin, not silent acceptance.

## Outputs and verification boundary

`summary.json` contains the result and exact parameters. `receipt.json` records input identity, analysis-script identity, and output hash in an explicitly unsigned in-toto statement envelope. `verification.json` records the exercised checks, package versions, and existing verifier report. `environment.txt` records the environment.

The existing repository verifier checks the envelope, statement structure, and recorded payload hash. The example adapter separately checks the actual input, actual summary file, parameters, and source-script identity. The calculation must repeat with identical output bytes. Changed receipt payloads and changed summary files must be rejected while their recorded reference is held fixed.

**No signature or trusted authorship is verified.** An unsigned hash identifies a mismatch against a retained reference; it cannot prove who created that reference or prevent replacement of every file and hash together. The record does not establish biological correctness, appropriate statistical design, or clinical safety. Non-applicable checks in the existing verifier are not counted as biological or signature validation.

## Continuing checks

The `Public single-cell example` workflow performs the actual download and calculation. Its small JSON records, checkout identity, and resolved packages are preserved in the run log and job summary. No expression-matrix or artifact-service upload is used. The repository's existing action allowlist is unchanged.

[Methods and limitations](METHODS_NOTES.md) places this demonstration alongside established scoring and donor-aware inference. [Plain-language post](POST.md) provides a short introduction with no model-count claims.
