# GALIA McLeary source discovery — 22 November 1915

Status: **DISCOVERY RECORD ONLY — NOT CANONICAL HISTORICAL PROMOTION**

This record preserves a reproducible source-discovery result for the earliest
McLeary/MacLeary street designation recovered in the September–November 1915
*El Tiempo / The Times* corpus examined by GALIA, subject to the explicit
coverage limits stated below.

## Positive source anchor

- Publication: *El Tiempo / The Times*
- Document date: 1915-11-22
- UFDC folder: `01444`
- Source object: `1915112201.pdf`
- Source URL:
  `https://ufdcimages.uflib.ufl.edu/AA/00/09/69/97/01444/1915112201.pdf`
- Raw PDF SHA-256:
  `95b39283b2f073dfb5a2d3f2ba65f0eff65f2511f721a30951cf2a921bb70c4d`
- Raw PDF size: 43,845,960 bytes
- Extracted pages: 12

### Spanish anchor — PDF page 4

Rendered-page reading:

> SE ALQUILA una casa de concreto, reciente construcción, cinco dormitorios,
> 2 inodoros, baño, etc., frente al mar. Avenida MacLeary. Parada 44,
> Solar de 1104 m² ... Llame al teléfono No. 117, San Juan.

The exact punctuation and damaged characters around non-material portions of
the advertisement remain subject to diplomatic transcription review. The
material street/location tokens are visually legible: **Avenida MacLeary**,
**Parada 44**, **1104 m²**, and telephone **117**.

### English anchor — PDF page 9

Rendered-page reading:

> FOR RENT. A cool and comfortable house, recently built of concrete.
> Five sleeping rooms, two toilets, bath, etc. fronting the sea.
> Mac Leary Ave., Stop 44. Site 1104 sq. Meters.
> For further information telephone No. 117, San Juan.

The bilingual advertisements describe the same property by matching location,
lot area, phone number and sea-front description. This is strong internal
corroboration for the street designation, but it is still one newspaper issue
rather than an independent custodial source.

## Backward search coverage

GALIA searched the text layers for street-form variants including
`McLeary`, `MacLeary`, `Mac Leary`, and `Mc Leary`. Generic
`Leary` occurrences are retained separately as diagnostics and do not count
as street hits.

### November 1915

All eighteen mapped publication days from **1915-11-01 through 1915-11-20**
(excluding Sundays) were examined. Street-form hits: **0**.

### October 1915

All twenty-six mapped publication days from **1915-10-01 through 1915-10-30**
(excluding Sundays) were examined. Street-form hits: **0**.

The initial October pass produced generic `O'Leary` diagnostics on
1915-10-02; the scanner was then hardened to keep those person-name diagnostics
separate from McLeary/MacLeary street forms. A dedicated retry independently
resolved 1915-10-30 and returned zero McLeary/MacLeary street hits.

### September 1915

Twenty-five issues from **1915-09-01 through 1915-09-30** were resolved and
examined. Street-form hits: **0**.

One candidate publication date remains unresolved in the UFDC mapping:
**1915-09-06**. Accordingly, GALIA does not characterize September 1915 as a
complete negative month.

## Bounded historical result

The evidence currently supports this statement:

> **Earliest verified McLeary/MacLeary street designation in the
> September–November 1915 El Tiempo corpus recovered and examined by GALIA:
> 22 November 1915.**

Coverage before that positive anchor consists of **69 resolved earlier issues**
(25 September + 26 October + 18 November), all with zero McLeary/MacLeary
street-form hits. The unresolved 1915-09-06 date remains an explicit coverage
gap.

This result does **not** establish that 22 November 1915 was:
- the legal naming date;
- the physical opening date;
- the dedication or municipal-acceptance date;
- the first use in every surviving newspaper or archival source; or
- proof of the identity of the avenue's eponym.

## Workflow evidence

Positive discovery:
- GitHub Actions run: `36137670701`
- Artifact: `GALIA_MCLEARY_1915_11_22_DISCOVERY`
- Artifact digest:
  `sha256:bc1b6722d8af8f1fdbcb220cbac96c3d15da5d4ea2dc77fc8051f6aac0cce3e4`

Pre-22 November scan, 15–20 November:
- GitHub Actions run: `36138088482`
- Artifact digest:
  `sha256:5f402c23bb667747abe58cdd4f4c6e646c76d197860b633a8e232ab90cf6587e`

Early November scan, 1–13 November:
- GitHub Actions run: `36138256436`
- Artifact digest:
  `sha256:2b21cec4168039969754d2ab24f00b4441694c1cfac3691840868d0f9ed06597`

October hardened street-form scan:
- GitHub Actions run: `36139111929`
- Artifact: `GALIA_MCLEARY_OCTOBER_1915_SCAN`
- Artifact digest:
  `sha256:eda52020ca38bfa3254f57e4544108fdc244e6210613f41f9fe27ec94a28997c`

Independent 30 October retry:
- GitHub Actions run: `36139174577`
- Artifact: `GALIA_MCLEARY_1915_10_30_RETRY`
- Artifact digest:
  `sha256:66f6885eb99a016c580c1847da893ac8f5376e812febc5351ad2692768515876`

September date-resolved scan:
- GitHub Actions run: `36139358167`
- Artifact: `GALIA_MCLEARY_SEPTEMBER_1915_SCAN`
- Artifact digest:
  `sha256:9f2da69c7a52a53731dde134397cd49f3118750ffab750ff5d694624fae013c7`

## Authority boundary

This discovery does not establish:
- a municipal nominative ordinance or resolution;
- dedication or municipal acceptance of the roadway;
- the identity of the eponym;
- that the avenue was named for James Harvey McLeary;
- the date the physical road was opened.

Those propositions remain separate claims and require their own evidence.

For the legal-nominative question, the municipal web library presently exposes
ordinance series beginning in 1931. The relevant pre-1931 archival route is
therefore the Archivo General de Puerto Rico's **Fondo Municipio de San Juan**,
especially **Serie Libros de Actas y otros (PR-SJ-AGPR-00335), 1722–1955**,
rather than an inference from the newspaper designation.


## Nominative-act search gate

The 1915 legal/archival search must not be limited to a document titled
"ordinance."

### Governing municipal body in 1915

The Archivo General de Puerto Rico's institutional history records that the
1906 municipal law further separated the mayor's executive powers from the
legislative powers of the **Concejo Municipal**. The later Junta de
Comisionados belongs to a different governmental period and is not the correct
1915 decision-making body.

Contemporaneous legislative material for the 1906 Municipal Law states that
the municipal council could vote an **ordinance or resolution** within its
statutory powers, including matters involving the demarcation and opening of
municipal streets and roads. Therefore the nominative search is fail-closed
against all of the following record forms:

1. ordenanza;
2. resolución;
3. acuerdo entered in council minutes;
4. certified extract/certificación of a council action;
5. correspondence implementing or transmitting such an action;
6. street/road project records that quote or attach the governing action.

Absence from an ordinance index alone is not evidence that no nominative act
existed.

### AGPR search order

Primary repository:
**Archivo General de Puerto Rico, Fondo Municipio de San Juan
(PR-SJ-AGPR-00338).**

Priority A — governing-action records:
- **Serie Libros de Actas y otros (PR-SJ-AGPR-00335)**, especially post-1900
  council-act/minute material, certifications, correspondence and asuntos
  varios.
- **Serie Expedientes Administrativos — Subserie Ordenanzas**, because a
  formal street designation may have been filed as a standalone municipal
  ordinance rather than only in a bound minute book.

Priority B — subject-matter records:
- **Serie Expedientes de Servicios — Subserie Calles y caminos**, because the
  AGPR finding aid expressly classifies municipal street and road records
  there.
- Related **Obras Municipales**, **Obras Particulares**, **Proyectos**,
  **Plazas y Paseos**, and municipal correspondence if they contain plans,
  alignments, dedications or implementation instructions.

Priority C — external corroboration:
- Fondo Obras Públicas for plans, road/transport files or correspondence that
  may reproduce the municipal designation.
- Contemporary newspapers for publication, notice or reporting of the
  council action.

### Date window

The first-pass nominative window is:

**1914-01-01 through 1915-11-21**

with an initial high-priority slice of:

**1915-09-01 through 1915-11-21**

because the 22 November 1915 newspaper issue is the present documentary
terminus ante quem for public use of the MacLeary street designation.

The search must also include spelling variants:
`McLeary`, `MacLeary`, `Mac Leary`, `Mc Leary`, `Macleary`, and
OCR-confusable forms.

### Promotion rule

A newspaper designation can establish public use of the name. It cannot, by
itself, satisfy `MCLEARY_NAMING_ACT`.

That gate may be satisfied only by a municipal record or a sufficiently
authoritative contemporaneous record that identifies the governmental action,
its date and the body/official responsible. If a source merely calls the road
MacLeary, the naming-act claim remains **UNRESOLVED**.
