# Methods and limitations: briefing for scientific discussion

## Contribution and boundary

This is an engineering example around a public expression file: explicit source identification, recorded calculation choices, repeat execution, and checks of actual output files. It is not a new scoring algorithm. A repeatable computation can still use an unsuitable statistical method or unrepresentative data. This example makes no biological hypothesis test or comparison between scoring methods.

## Seurat AddModuleScore

AddModuleScore averages signature expression and subtracts an expression-matched control score. It bins genes by aggregate expression and samples controls from those bins. Documented defaults include 24 bins, 100 control features per analyzed feature, seed 1, and the data slot. This is established methodology, not an invention of this project. [1]

Rescoring cells within a different population can change their expression-control baseline. A fixed seed does not fix changed gene pools or bin assignments. The UCell authors provide a worked comparison. [2]

For a future comparison, record software version, normalization, assay and layer/slot, feature identifiers, gene universe, control pool, bin settings, seed, and actual sampled controls. Check that bins support the requested sampling. A negative background-adjusted score is not negative expression, and the score is not a calibrated p-value.

## AUCell

AUCell ranks genes within each cell and summarizes signature recovery near the top. Its documented default examines the top 5% of genes. Ties, including zero-expression genes, are shuffled, so record ranking cutoffs and random-number settings. Its authors explicitly discuss comparable detection sensitivity and gene identifiers when combining rankings. [3]

Rank-based scoring is not immunity to missing genes, shallow measurement, or a changed feature universe. Activity thresholds require context; an AUC cutoff is not a universal significance threshold. This example does not run or benchmark AUCell.

## UCell and pyUCell

UCell uses per-cell ranks and the Mann-Whitney U statistic. Keeping the cell's input values, gene universe, and parameters fixed avoids recomputing a population-derived expression-control baseline. This is narrower than immunity to every preprocessing or sampling change. [2,4]

Pin the implementation version: UCell documents a normalization change beginning with version 2.7.6. Record maxRank and signature handling. Distinguish raw from optional neighbor-smoothed scores, which depend on the neighborhood representation. The 2026 UCell/pyUCell paper describes current R and Python implementations. [4,5]

## Biological replication

Squair et al. show that differential-expression methods ignoring variation between biological replicates can produce false discoveries. Thousands of cells from a few donors do not become thousands of independent biological replicates. [6]

A future condition comparison needs justified sample/donor-level design, appropriate replication, and an analysis accounting for nesting, such as suitably designed pseudobulk or mixed models. Resampling must respect the inferential unit. Neither a file hash nor a donor-label column fixes confounding. This warning concerns inference; it does not make every per-cell descriptive score invalid.

The GEO file here contains processed fractional values. It must not simply be relabeled as raw counts for a count-based pseudobulk workflow. Its original values are preserved and no condition comparison is performed.

## Answer to “What is new?”

“The scoring methods are established. This example makes a small computation inspectable: which public file was used, what was calculated, whether the output can be regenerated, and whether changes are detected against the retained record. It does not establish biological validity or replace experimental design.”

## Primary sources

1. Satija Lab. [AddModuleScore reference](https://satijalab.org/seurat/reference/addmodulescore).
2. Carmona Lab. [UCell versus AddModuleScore worked comparison](https://carmonalab.github.io/UCell_demo/UCell_Seurat_vignette.html). Andreatta and Carmona (2021), [10.1016/j.csbj.2021.06.043](https://doi.org/10.1016/j.csbj.2021.06.043).
3. Aibar et al. [AUCell author vignette](https://bioconductor.org/packages/release/bioc/vignettes/AUCell/inst/doc/AUCell.html); SCENIC (2017), [10.1038/nmeth.4463](https://doi.org/10.1038/nmeth.4463).
4. Carmona Lab. [UCell implementation and version-specific changes](https://github.com/carmonalab/UCell).
5. Andreatta and Carmona (2026). *UCell and pyUCell: single-cell gene signature scoring for R and Python*. [10.1093/bioinformatics/btag055](https://doi.org/10.1093/bioinformatics/btag055).
6. Squair et al. (2021). *Confronting false discoveries in single-cell differential expression*. [10.1038/s41467-021-25960-2](https://doi.org/10.1038/s41467-021-25960-2).
