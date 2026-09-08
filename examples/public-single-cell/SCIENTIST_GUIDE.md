# Scientist's guide to this example

## What was demonstrated

This is a small, inspectable software example: a specified public expression file is summarized, the exact choices and output are recorded, and a repeat run and deliberate modifications test the resulting record. The existing calculation and verifier have not been changed by this communications update.

The [observed record](observed-run.json) contains 3,072 submitted cell columns, four source donor labels, 19,059 endogenous feature rows, and 81 ERCC spike-in rows. All submitted columns are retained. A source donor label is not an independently authenticated donor identity. The file is processed and fractional; it is not relabeled as raw integer counts.

The same calculation generated identical summary bytes on repeat execution. Changing the recorded payload or result file was rejected while the reference was held fixed. The intact case and both negative controls are recorded separately. Fourteen synthetic input and file-binding tests and four recorded-output consistency tests are not additional biological observations.

The merged original example also passed its [post-merge public-data workflow](https://github.com/szl-holdings/governed-receipt-spec/actions/runs/34176439398), which downloaded the source again and compared its fresh summary and receipt with the retained run. This is repeated execution by the project, **not an independent external replication**.

## What a receipt means here

A receipt is a small machine-readable analysis record linking a source file, the code, parameters, and output through content hashes. A hash is a compact identifier of file bytes. It is useful for detecting changes relative to a retained reference.

There is no digital signature in this example. Replacing every file and every hash together could produce a different internally consistent record. No trusted author identity, trustworthy timestamp, biological correctness, or clinical validity follows from a checksum. The original verifier's non-applicable signature or chain checks do not establish those properties.

The [checklist](REPRODUCIBILITY_CHECKLIST.md) separates the checks performed from additional requirements for broader claims. The [README](README.md) is the reproduction guide; use a new checkout and output directory rather than silently replacing prior evidence.

## Answers to likely questions

**What is new?** This demonstrates integration of existing data and verification tools around one explicit computation. It makes no priority claim for provenance, signatures, workflow tracking, or gene-set scoring.

**Is this more than a hash?** It records parameters and source-code identity, checks the actual input and output, repeats the computation, and tests deliberately changed artifacts. It does not create a new cryptographic primitive. Scientific usefulness beyond this small example needs user testing and comparisons with existing workflow tools.

**Did it reproduce the original paper's biological results?** No. It summarized one supplementary file. It did not repeat the paper's cell filtering, annotation, clustering, or biological conclusions.

**Why this dataset?** Its public supplementary file is small enough for a bounded CPU example, has source donor grouping labels, and is attributed to an identifiable original publication. It was not selected after screening methods for a favorable score.

**Why not claim 3,072 independent samples?** Those are submitted cell columns, not independent donors. This example has no hypothesis test. Future inference must justify its experimental unit and account for nested sampling and confounding.

**Does it outperform AUCell, UCell, or AddModuleScore?** Not tested. Those methods compute gene-signature scores; this example computes a descriptive file summary. Comparing their score values directly to this output would compare different tasks.

**Was it externally validated or peer-reviewed?** No such review is claimed. Completed project-run checks and public code enable scrutiny but do not substitute for it.

**May the data be reused freely for every purpose?** Not established. The example fetches the original public file for this demonstration and does not redistribute the expression matrix. Future uses require review of applicable data and software terms.

## Before a scoring-method comparison

The following is a **proposed study design, not an executed benchmark**. Keep it separate from this worked example and do not add its planned results to the post.

First define the scientific task, intended comparison, independent sampling unit, and criteria before seeing scores. Choose a dataset whose specimen metadata and input representation support that task. Record eligibility, preprocessing, exclusions and every excluded sample. Preserve donor grouping; do not randomly split cells from one donor across training and test sets while claiming donor-level generalization.

Use the published implementations, not ad hoc imitations. Freeze exact versions, input-file digests, gene identifiers and mapping rules, gene universe, signature membership and direction, normalization, control settings, and random-number settings. For Seurat's expression-matched controls, retain the actual selected controls as well as bin count, pool and seed. For ranking-based methods, retain ranking cutoffs, missing-gene handling and tie settings. Keep optional neighbor smoothing separately identified. [1–3]

For sensitivity checks, vary one factor at a time: population composition for the same retained cells, seed, detection depth, feature availability, or signature size. Report agreement and rank stability with their limits; a high correlation between methods does not by itself establish accuracy. Count-thinning experiments require a justified count representation, not the fractional processed file relabeled as raw counts.

For biological claims, prespecify the design and independent validation. Appropriate donor/sample-level summaries or mixed models depend on the question and data; neither is a universal fix for inadequate replication. Permutations and resampling must preserve relevant donor and study structure. Report effect sizes, uncertainty, multiplicity handling, failures and excluded runs—not only p-values or a winning example. A small number of donors limits inference even when there are many cells. [4]

## Posting and release recommendations

Use one immutable example link, keep author attribution prominent, and avoid model counts, promises of improved biology, or claims of external endorsement. Put detailed citations in the first comment and keep the public post short. Ask for a reproducibility review, not validation of an untested scientific claim.

An independent computational biologist reproducing the instructions in a fresh environment is the next useful external check. Record any discrepancy rather than changing the reference silently. A later version can add dependency hashes, a resolved container-image digest, and trusted release signing; each should be reported only after it is actually implemented and exercised.

## Primary sources

1. Satija Lab, [AddModuleScore reference](https://satijalab.org/seurat/reference/addmodulescore): expression-binned sampled controls and documented parameters.
2. Aibar et al., [AUCell author vignette](https://bioconductor.org/packages/release/bioc/vignettes/AUCell/inst/doc/AUCell.html): within-cell recovery rankings, cutoff, ties and sensitivity considerations.
3. Andreatta and Carmona, [UCell implementation](https://github.com/carmonalab/UCell) and [2026 UCell/pyUCell paper](https://doi.org/10.1093/bioinformatics/btag055): per-cell rank scoring, version-specific normalization and optional smoothing.
4. Squair et al. (2021), [Confronting false discoveries in single-cell differential expression](https://doi.org/10.1038/s41467-021-25960-2): accounting for biological-replicate variation.

See [METHODS_NOTES.md](METHODS_NOTES.md) for the existing methodological briefing. The recommendations above are analysis design advice, not results of this file-integrity example.
