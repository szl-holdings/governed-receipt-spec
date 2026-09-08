# Post draft

Can someone else retrace a computational result—not just read its conclusion?

I built a small reproducibility example using the public human pancreatic single-cell dataset GSE85241 from Muraro and colleagues.

It keeps all 3,072 submitted cell columns across four source donor labels, uses the processed expression values without rounding, and calculates a descriptive file summary. This is an unfiltered example, not a biological comparison.

A machine-readable analysis record links the exact input file, code, parameters, and output. Repeating the calculation produced identical output bytes. Deliberately changing the recorded payload or result file was rejected against the retained reference.

The record is unsigned: it checks file consistency and repeatability, not trusted authorship or biological validity. It is not a new gene-scoring method and does not replace donor-aware statistical analysis.

Code, observed results, and limitations:
https://github.com/szl-holdings/governed-receipt-spec/tree/320983d22e76fc9b26af0b2cd20799c5000543fc/examples/public-single-cell

Credit for the underlying data belongs to the original researchers.

What information is most often missing when you try to reproduce someone else's analysis?
