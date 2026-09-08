# Methods and limitations: briefing for scientific discussion

## What this example contributes

This is an engineering example around an existing public expression file: explicit source identification, recorded analysis choices, repeat execution, and checks of actual output files. It is not a new scoring algorithm. A repeatable computation can still use an unsuitable statistical method or an unrepresentative dataset. The worked example makes no biological hypothesis test and no comparison between scoring methods.

## Seurat AddModuleScore

AddModuleScore averages expression of a signature and subtracts an expression-matched control score. The implementation bins genes by aggregate expression and samples controls from the relevant bins. Its documented defaults include 24 bins, 100 control features per analyzed feature, seed 1, and the data slot. These choices are established methodology, not inventions of this project. [1]

Because binning depends on the data being analyzed, rescoring the same cells within a different cell population can change the controls and scores. A fixed seed does not fix a changed gene pool or bin assignment. The authors of UCell provide a worked comparison illustrating this distinction. [2]

For a future reproducible comparison, record the software version, normalization, assay and layer/slot, feature identifiers, available gene universe, control pool, binning settings, seed, and actual sampled controls. Check whether each bin can support the requested sampling. Do not interpret a negative background-adjusted score as negative expression or a score threshold as a calibrated p-value.

## AUCell

AUCell ranks genes within each cell and summarizes signature recovery near the top of that ranking. The documented default examines the top 5% of genes; ties, including zero-expression genes, are shuffled. Record the ranking cutoff and random-number settings. The authors explicitly discuss comparable detection sensitivity and gene identifiers when combining rankings. A rank-based score is not immune to missing genes, shallow measurement, or a changed feature universe. [3]

AUCell's activity thresholds require context; an AUC cutoff is not a universal significance threshold. The accompanying example does not run or benchmark AUCell.

## UCell and pyUCell

UCell uses per-cell ranks and the Mann-Whitney U statistic. With the same cell values, feature universe, and parameters, raw per-cell scoring avoids recomputing a population-derived expression-control baseline. This is a narrower statement than immunity to every preprocessing or sampling change. [2,4]

Pin the implementation version: the authors document a normalization change beginning with UCell 2.7.6. Record maxRank and signature handling. Distinguish raw scores from optional neighbor-smoothed scores, which depend on the neighborhood representation. The 2026 UCell/pyUCell paper documents current R and Python implementations; citing only the 2021 paper is insufficient to specify a present-day implementation. [4,5]

## Biological replication and pseudoreplication

Squair et al. show that differential-expression methods that ignore variation between biological replicates can produce false discoveries. Thousands of cells from a few donors do not become thousands of independent biological replicates. [6]

A future condition comparison needs a justified sample/donor-level design, appropriate replication, and a method that accounts for the nesting, such as suitably designed pseudobulk or mixed-model analysis. Resampling must respect the inferential unit. Neither a file hash nor a donor-label column fixes confounding. This warning concerns statistical inference; it does not make every per-cell descriptive score invalid.

The GEO file used here contains processed fractional values. It must not simply be relabeled as raw integer counts for a count-based pseudobulk workflow. This example preserves its original values and makes no condition comparison.

## A defensible answer to “What is new?”

“The scoring methods are established. This example is about making a small computation inspectable: which public file was used, what was calculated, whether the output can be regenerated, and whether changes are detected against the retained record. It does not establish biological validity or replace experimental design.”

## Primary sources

1. Satija Lab. [AddModuleScore reference](https://satijalab.org/seurat/reference/addmodulescore).
2. Carmona Lab. [UCell versus AddModuleScore worked comparison](https://carmonalab.github.io/UCell_demo/UCell_Seurat.html). See also Andreatta and Carmona (2021), [10.1016/j.csbj.2021.06.043](https://doi.org/10.1016/j.csbj.2021.06.043).
3. Aibar et al. [AUCell author vignette](https://bioconductor.org/packages/release/bioc/vignettes/AUCell/inst/doc/AUCell.html); SCENIC (2017), [10.1038/nmeth.4463](https://doi.org/10.1038/nmeth.4463).
4. Carmona Lab. [UCell implementation and version-specific changes](https://github.com/carmonalab/UCell).
5. Andreatta and Carmona (2026). *UCell and pyUCell: single-cell gene signature scoring for R and Python*. [10.1093/bioinformatics/btag055](https://doi.org/10.1093/bioinformatics/btag055).
6. Squair et al. (2021). *Confronting false discoveries in single-cell differential expression*. [10.1038/s41467-021-25960-2](https://doi.org/10.1038/s41467-021-25960-2).
