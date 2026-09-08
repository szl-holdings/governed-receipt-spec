# A reproducible single-cell data example

Can someone else identify the exact public data file, repeat a small calculation, and detect a changed result against the retained record?

This example answers that narrow engineering question. It is **not a new gene-signature scoring method or a biological finding**. It does not run AUCell, UCell, Seurat, differential expression, cell annotation, or clinical inference.

## Executed result

The original public-data calculation completed in [this CPU run](https://huggingface.co/jobs/SZLHOLDINGS/6a9f615b259f8e97255ed671), using pre-merge source `160e39b1383a0e249399b6dfb72983b67aef7fe8`. The [retained output and receipt](observed-run.json) remain an unchanged record of that execution. For a normal fresh clone, use the published ancestor below rather than depending on a pre-merge branch commit remaining fetchable.

| Observed file property | Result |
| --- | ---: |
| Submitted cell columns, with no filtering | 3,072 |
| Source donor labels | 4 |
| Feature rows | 19,140 |
| Endogenous feature rows | 19,059 |
| ERCC spike-in rows | 81 |
| Columns per source donor label | 768 |

The original calculation ran twice and produced byte-identical summary output. The intact bundle passed. A changed receipt payload and changed summary file were rejected against the unchanged recorded reference. The 14 synthetic tests in that original run are distinct from the real-data measurements and from additional tests added later.

Summary SHA-256: `3a5539e922ae68687c806f35df540f365b0a249e1f654b87f5309d074ea77df6`.

These numbers describe the submitted file, not a quality-controlled cell atlas or independent observations for a biological hypothesis. The per-donor detection summaries are descriptive only; their differences are not interpreted as biological effects.

## Public data and attribution

Data: Muraro et al., *A Single-Cell Transcriptome Atlas of the Human Pancreas*, Cell Systems (2016), [10.1016/j.cels.2016.09.002](https://doi.org/10.1016/j.cels.2016.09.002), deposited as [GEO GSE85241](https://www.ncbi.nlm.nih.gov/geo/query/acc.cgi?acc=GSE85241). The original researchers produced the data. This example is not affiliated with them or with GEO.

```text
https://ftp.ncbi.nlm.nih.gov/geo/series/GSE85nnn/GSE85241/suppl/GSE85241_cellsystems_dataset_4donors_updated.csv.gz
SHA-256: 2f253ffb1f6d54f6bb259e862195f5c20ea3f13e00471b9864ff92773658f513
Bytes: 17005498
```

Despite its filename, the file is tab-delimited. It contains submitted processed fractional expression values, not a raw integer count matrix. No values are rounded or renormalized. The example downloads the original file from GEO and does not redistribute the expression matrix or claim ownership of it. Public availability is not a blanket grant of rights for future uses.

## Calculation

Every submitted cell column and feature row is read. Features whose submitted value is greater than zero are counted, ERCC rows are recorded separately, and minimum, median and maximum detected endogenous features per cell are reported within each source donor label. All columns are retained. No quality-control filtering, clustering, group comparison or hypothesis test is performed. Labels parsed from the column names preserve source grouping; they do not authenticate donor identity or establish experimental replication.

## Reproduce the historical calculation

The published commit below is part of the default-branch history. The current workflow checks that its analysis file has exactly the same Git blob as the unchanged current analysis. It does not relabel that published commit as the original CPU run's source.

```sh
git clone https://github.com/szl-holdings/governed-receipt-spec.git
cd governed-receipt-spec
git checkout 66700778fd995051f01c9ed7fe42226b464a31a4
python -m venv .venv
# Linux/macOS:
. .venv/bin/activate
# Windows PowerShell alternative: .venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m unittest discover -s tests -p 'test_public_single_cell*.py' -v
python examples/public-single-cell/run_example.py --output public-example-run-1
```

That historical recipe pins two direct dependencies, not the complete environment. Choose a new output directory each time. `--input PATH` accepts an existing exact downloaded gzip after the same byte-count and SHA-256 checks.

## New locked reproduction path

For the reviewed CPython 3.12.14 / Linux x86_64 environment, [LOCKED_REPRODUCTION.md](LOCKED_REPRODUCTION.md) provides the complete five-package binary hash lock and a container pinned to an official platform-specific image digest. This path requires a checkout containing those new files; they are not backported into the historical commit above.

The existing workflow now verifies wheel files, installs with pip's hash enforcement, tests rejection of a deliberately changed wheel, builds the example container, and runs the unchanged calculation with container networking disabled against a read-only input mount. It then compares host, container and retained summary/receipt output. Consult the exact commit's completed workflow before claiming that any particular revision passed. Docker and package consistency do not constitute scientific or supply-chain security certification.

## Outputs and verification boundary

`summary.json` contains the result and parameters. `receipt.json` links input identity, analysis-script identity and output hash in an explicitly unsigned statement. `verification.json` records the exercised checks, package versions and existing verifier report. `environment.txt` records the runtime environment.

The existing verifier checks the envelope, statement structure and recorded payload hash. The example adapter separately checks actual input/output files, parameters and source-script identity. The verifier's reviewed Git blob is `84cd6b67a6a9052dc6ec6a334c810b6b4752bc8f`; changing it requires explicit review.

**No signature or trusted authorship is verified.** Hashes detect differences against a retained reference, not replacement of all references and hashes together. The example does not establish biological correctness, statistical validity or clinical safety. Non-applicable signature and chain checks are not counted as validation. Project-run repetitions are not independent external replication.

## Continuing checks and discussion

The `Public single-cell example` workflow records small public results, actual checkout, resolved packages and built-image identity in logs and the job summary. It does not upload the expression matrix or change the action allowlist. No image or model is published by this example.

[Methods and limitations](METHODS_NOTES.md) · [Scientist's guide](SCIENTIST_GUIDE.md) · [Reproducibility checklist](REPRODUCIBILITY_CHECKLIST.md) · [Post draft](POST.md)
