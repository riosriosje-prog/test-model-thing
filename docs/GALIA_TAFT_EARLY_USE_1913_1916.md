# GALIA 2.0 — Early Taft street-use chronology, 1913–1916

Status: **RESEARCH CANDIDATE ONLY — NO CANONICAL PROMOTION**

This dossier separates the earliest recovered public use of the Taft street
name from the still-unresolved questions of physical origin, municipal naming
act, acceptance/dedication, and eponym identity.

## 1. Primary anchor — 11 February 1913

Publication: *The Times*, San Juan, Puerto Rico  
Document date: **1913-02-11**  
UFDC object: `AA/00/09/69/97/00644/1913021101.pdf`

Raw PDF:
- bytes: **47,305,570**
- SHA-256:
  `e3452119441cbf750e748ecd69ae74e4cdb98aa565c8b1b5a075fc5abd1fc7f1`

Visual anchor:
- PDF page: **9**
- rendered-page SHA-256:
  `68f05e1a4271a03b943d71cf4ef11dd90cf22b5aa4d00652962ca044979795b0`

The classified advertisement is visually readable as:

> House for Sale; Eight apartments, Nº 22 Taft Street, near Seashore.
> Apply G. T. Parker, Box 667, San Juan, P.R.

The material tokens are visually legible on the rendered primary-source page:
**Taft Street**, **No. 22**, **near Seashore**, **G. T. Parker**, and
**San Juan, P.R.**

GitHub Actions:
- run: `36143268220`
- artifact: `GALIA_TAFT_1913_02_11_PRIMARY`
- artifact digest:
  `sha256:1257c4f088b2321e9922137e0a8e9c11b07fb8f4378d5eb44eb977740cb46ce5`

A repeated version of the same classified address appears again on
**12 February 1913**; that later repetition is not the earliest anchor in the
resolved corpus.

### Backward corpus immediately preceding the anchor

GALIA resolved and scanned **36/36 publication issues from 1 January through
11 February 1913**. Only the **11 February** issue contains a qualified Taft
street-form hit. The resolved issues from **1 January through 10 February**
contain **zero qualified Taft street-form hits**.

December 1912 was separately scanned:
- 24 resolved issues;
- 0 qualified Taft street-form hits;
- 25 December and 31 December were not resolved in the tested UFDC mapping and
  are excluded from the negative count rather than treated as negative issues.

Accordingly:

```text
TAFT_PUBLIC_NAME_USE_BY_1913_02_11 = DOCUMENTED
TAFT_FIRST_IN_RESOLVED_1913_CORPUS = 1913-02-11
TAFT_FIRST_ABSOLUTE_USE            = OPEN
TAFT_NAMING_ACT                    = UNRESOLVED
TAFT_EPONYM_IDENTITY               = UNRESOLVED
```

A November 1912 backward scan is a separate gate and may move the
earliest-known-use date earlier.



### Extended backward corpus — October 1912 through 10 February 1913

After hardening the street detector against political-news false positives
(for example, OCR sequences such as **“gave Taft”** from election reporting),
GALIA re-ran the pre-anchor corpus using whole-token street designators.

Qualified results:

- **October 1912:** 27 resolved issues, **0** Taft street-form hits.
- **November 1912:** 24 resolved issues, **0** Taft street-form hits.
  - unresolved/non-counted dates: **1912-11-05**, **1912-11-28**.
- **December 1912:** 24 resolved issues, **0** Taft street-form hits.
  - unresolved/non-counted dates: **1912-12-25**, **1912-12-31**.
- **1 January–10 February 1913:** 35 resolved issues, **0** Taft
  street-form hits.
- **11 February 1913:** first qualified hit in this resolved corpus.

Total resolved negative issues before the 11 February anchor:
**110**.

Therefore the supported bounded statement is:

> **11 February 1913 is the earliest verified Taft street designation in the
> resolved 1 October 1912–11 February 1913 *Times* corpus examined by GALIA.**

This is not an absolute first-use claim because unresolved publication dates,
other newspapers, directories, deeds, maps, municipal records and private
plans remain outside this bounded corpus.

The false-positive audit is itself part of the evidentiary record:
political references to President Taft are retained as generic-Ta​​ft
diagnostics but are not promoted as street-name evidence.




### September 1912 extension

A corrected UFDC date-to-folder scan resolved **24 September 1912 issues**
with the hardened whole-token street detector.

Result:
- qualified Taft street-form hits: **0**;
- unresolved/non-counted date: **1912-09-02**;
- exact 30 September anchor folder: `00533`;
- artifact digest:
  `sha256:0e17c796e93ddb6d21f158393d7042513465b34e45dbefdf1aecf04eae709df7`.

This raises the resolved negative pre-anchor corpus from **110** to **134**
issues. The supported statement remains bounded to the resolved corpus; the
2 September gap and earlier months remain open.




### August 1912 extension

The hardened resolver/scanner closed **27/27 August 1912 publication issues**
with **zero qualified Taft street-form hits** and no unresolved dates.

- 31 August anchor folder: `00509`;
- artifact digest:
  `sha256:3e1ec9d329199934ad5ece7f8afc90d8a71076699c60dc48ca89081d38a79bff`.

This raises the resolved negative pre-anchor corpus to **161 issues** before
the first qualified Taft street designation on 11 February 1913.

The supported statement remains bounded to the resolved corpus and does not
establish a legal naming date or physical opening date.




### July 1912 extension

GALIA resolved **26 July 1912 publication issues** and found **zero
qualified Taft street-form hits**.

- 31 July anchor folder: `00482`;
- unresolved/non-counted date: **1912-07-04**;
- artifact digest:
  `sha256:a6a65fffc23aefbeac235345018a8dcf82b43004d176f57c71f54cd5a03b7221`.

This raises the resolved negative pre-anchor corpus to **187 issues** before
the first qualified Taft street designation on 11 February 1913.


## 2. Independent later anchor — 18 June 1914

Publication: *El Tiempo / The Times*  
Document date: **1914-06-18**  
UFDC object: `AA/00/09/69/97/01060/1914061801.pdf`

Raw PDF:
- bytes: **46,023,243**
- SHA-256:
  `cbc7ea21047d8f7125edae773d3521e4825e7589a1dd6c872b705d654c87497b`

Page 9 contains a classified advertisement whose extracted and rendered
content identifies:

> 6 Taft Avenue, Near Stop 44

Rendered-page SHA-256:
`533ef662cde1d474f280e424b599ad5e9dfddfdb9b9f8e76cc5e356f5a09ff1f`

GitHub Actions:
- run: `36142359534`
- artifact: `GALIA_TAFT_1914_06_18_PRIMARY`
- artifact digest:
  `sha256:0ea597e55992577180870ca72f37afd21b6e2b3dbf70426d3fa4d710d833676a`

This supplies an independent temporal and locational anchor:
**Taft Avenue ↔ near Stop/Parada 44** by June 1914.

## 3. Relation to the McLeary evidence

Current verified anchors are:

```text
11-Feb-1913
  “No. 22 Taft Street, near Seashore”
              │
              ▼
18-Jun-1914
  “6 Taft Avenue, Near Stop 44”
              │
              ▼
22-Nov-1915
  “Avenida MacLeary — Parada 44”
  “Mac Leary Ave. — Stop 44”
              │
              ▼
08-Mar-1916
  “Calle Mc Leary (sale de Taft)”
```

The sequence establishes that the **Taft name is documented earlier than the
current earliest verified MacLeary/McLeary name anchor**.

It also establishes that Taft was being used as a locational axis both
near the seashore (1913) and near Stop 44 (1914) before the recovered McLeary
advertisements.

Accordingly:

```text
TAFT_NAME_PRECEDES_CURRENT_MCLEARY_ANCHOR = DOCUMENTED
TAFT_USED_AS_PREEXISTING_REFERENCE_AXIS   = STRONGLY_SUPPORTED
```

The second statement describes the documentary sequence; it does not determine
the legal origin of either road.

## 4. What this does not prove

The following remain separate gates:

- the date Taft was physically opened;
- whether Taft began as the western/transverse street opened in the
  Margarida finca 2109 parcelization;
- whether the 1913 and 1914 address usages followed an earlier municipal
  naming act;
- dedication or municipal acceptance;
- whether the street was named for William Howard Taft;
- the authority/person who selected the name;
- whether the word “Street” vs “Avenue” reflects a legal classification or
  merely newspaper/address usage.

No eponym inference is promoted from the surname alone.

## 5. Geometric implication for the private-network hypothesis

The title evidence in *King v. Fernández* documents a western/transverse
opened-street edge in the Margarida/Catlin parcel network before 1914.

The Taft newspaper evidence now demonstrates a named street that:
- reaches the seashore vicinity by February 1913; and
- is near Stop 44 by June 1914.

That correspondence makes the proposed identity

```text
MARGARIDA_WEST_TRANSVERSE_AXIS == LATER_TAFT
```

more testable, but **not yet established**.

Required closure remains:
- cadastral/subdivision plan;
- metes-and-bounds continuity;
- 1914–1917 named plan;
- or later authoritative plan tied back to predecessor finca numbers.

## 6. Eponym gate

William Howard Taft is a plausible eponym candidate because he had direct
institutional and personal involvement with Puerto Rico before the recovered
street-name use, including a 1907 visit as U.S. Secretary of War and direct
presidential action concerning Puerto Rican government during his 1909–1913
presidency.

This context establishes plausibility only:

```text
EPONYM_CANDIDATE_WILLIAM_H_TAFT = PLAUSIBLE
EPONYM_WILLIAM_H_TAFT           = UNRESOLVED
TAFT_NAMING_ACT                 = UNRESOLVED
```

Promotion requires a municipal resolution/ordinance/minute, approved plan,
contemporaneous explanatory notice, or equivalent authoritative naming record.


## 7. Scanner false-positive control

An earlier scanner version used the pattern `ave.? + Taft` without a leading
word boundary. In the 6 November 1912 election coverage, this incorrectly
matched the substring **"gave Taft"** and produced four apparent street hits.

The scanner was hardened to require whole-token street designators, including:

- `\bave\.?\s+taft\b`;
- `\bavenida\s+taft\b`;
- `\btaft\s+street\b`;
- equivalent qualified forms.

After the fix:

- **November 1912:** 24 resolved issues, **0 qualified Taft street hits**;
  unresolved dates: 5 and 28 November.
- **December 1912:** 24 resolved issues, **0 qualified Taft street hits**;
  unresolved dates: 25 and 31 December.
- The 6 November 1912 election-news matches disappear completely.

Therefore:

```text
1912_11_06_TAFT_STREET_HIT = FALSE_POSITIVE_REJECTED
NOV_1912_RESOLVED_CORPUS   = NEGATIVE_FOR_QUALIFIED_STREET_USE
DEC_1912_RESOLVED_CORPUS   = NEGATIVE_FOR_QUALIFIED_STREET_USE
```

The positive 11 February 1913 anchor is independent of this regex issue:
its exact PDF and rendered page were captured separately and visually verified.

## 8. Aggregate backward-search bound

With the hardened street-form detector, the resolved pre-anchor corpus now is:

- **October 1912:** 27 resolved issues, 0 qualified Taft street hits, 0 unresolved publication dates in the tested sequence;
- **November 1912:** 24 resolved issues, 0 qualified hits; 5 and 28 November unresolved and excluded;
- **December 1912:** 24 resolved issues, 0 qualified hits; 25 and 31 December unresolved and excluded;
- **1 January–10 February 1913:** 35 resolved publication issues, 0 qualified hits;
- **11 February 1913:** positive primary-source anchor, visually verified and byte-bound.

Thus **110 resolved pre-anchor issues** from 1 October 1912 through 10 February 1913 contain zero qualified Taft street-designation hits, followed by the verified 11 February 1913 address.

The supported bounded statement is:

> **Earliest verified Taft street designation in the resolved October 1912–February 1913 *Times* corpus examined by GALIA: 11 February 1913.**

This is not an absolute first-use claim. Earlier newspapers, maps, deeds, directories, municipal minutes, private subdivision papers, or unresolved issue dates may move the terminus earlier.

```text
TAFT_EARLIEST_VERIFIED_IN_RESOLVED_CORPUS = 1913-02-11
PRE_ANCHOR_RESOLVED_ISSUES_NEGATIVE        = 110
TAFT_ABSOLUTE_FIRST_USE                    = OPEN
TAFT_NAMING_ACT                            = UNRESOLVED
```
