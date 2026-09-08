# Post draft

A result is easier to examine when the path from data to output is visible.

I built a small reproducibility example using the public human pancreatic single-cell dataset GSE85241, published by Muraro and colleagues.

It reads the submitted expression file, calculates a descriptive summary, and records the exact input file, code, parameters, and output. The example retains all 3,072 submitted cell columns across four source donor labels; it is not a quality-filtered analysis.

The calculation produced identical output bytes on repeat execution. Deliberately changing the recorded payload or result file caused verification to fail against the retained reference.

This is not a new gene-scoring method, a biological discovery, or a replacement for donor-aware statistical analysis. The record is unsigned: it checks file consistency and repeatability, not trusted authorship or biological validity.

The code, observed output, verification record, and limitations are available in one worked example below. Credit for the underlying data belongs to the original researchers.

For researchers reviewing computational results: what information is most often missing when you try to reproduce someone else's analysis?

Worked example: ./README.md

Data publication: https://doi.org/10.1016/j.cels.2016.09.002

---

Before posting, replace the relative worked-example link with the exact public directory URL for the reviewed source. Do not replace it with an organization homepage or an internal model inventory. This file is a draft; no social post was sent by the workflow.
