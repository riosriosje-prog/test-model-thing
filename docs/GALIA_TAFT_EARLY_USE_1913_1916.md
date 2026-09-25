# GALIA 2.0 — Early Taft street-use chronology, 1913–1916

Status: **RESEARCH CANDIDATE ONLY — NO CANONICAL PROMOTION**

This dossier separates the earliest recovered public use of the Taft street
name from the still-unresolved questions of physical origin, municipal naming
act, acceptance/dedication, and eponym identity.

## 1. Primary anchor — 12 February 1913

Publication: *The Times*, San Juan, Puerto Rico  
Document date: **1913-02-12**  
UFDC object: `AA/00/09/69/97/00645/1913021201.pdf`

Raw PDF:
- bytes: **47,014,513**
- SHA-256:
  `3732d38ddf2d867caa5761b74e4b54ce51953f633e09205a0afbc87f4b789834`

Visual anchor:
- PDF page: **9**
- rendered-page SHA-256:
  `6ce40c7dbb0ef10c55b36ebd0e50bebc438ac6f42d3c663a7499b4cb3b292530`

The classified advertisement is visually readable as:

> House for Sale; Eight apartments, Nº 22 Taft Street, near Seashore.
> Apply G. T. Parker, Box 667, San Juan, P.R.

The exact punctuation is subject to diplomatic transcription review, but
**Taft Street**, **No. 22**, **near Seashore**, **G. T. Parker**, and
**San Juan** are visually legible.

GitHub Actions:
- run: `36142519484`
- artifact: `GALIA_TAFT_1913_02_12_PRIMARY`
- artifact digest:
  `sha256:8dc84a663e25e9d0ed14b8213c65ace93b5a59836b7a579c4deeca4a79deef47`

Bounded state:

```text
TAFT_PUBLIC_NAME_USE_BY_1913_02_12 = DOCUMENTED
TAFT_FIRST_ABSOLUTE_USE            = OPEN
TAFT_NAMING_ACT                    = UNRESOLVED
TAFT_EPONYM_IDENTITY               = UNRESOLVED
```

A backward scan of resolved *Times* issues before this date is a separate gate
and may move the earliest-known-use date earlier.

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
12-Feb-1913
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
