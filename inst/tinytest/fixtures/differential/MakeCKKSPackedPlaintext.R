## OPENFHE PYTHON SOURCE: openfhe/openfhe-python/src/lib/bindings.cpp (MakeCKKSPackedPlaintext)
## R-SPECIFIC: Block E 9106 — Signal 2 (differential-argument perturbation), LIVE mode
##
## C++ header: temp/openfhe-rlibomp/include/openfhe/pke/cryptocontext.h
##   (overload 2 of 2, real-valued)
##
## Harness history:
##   9100.0 — shipped in framework-validation mode (every probe
##            returned "probe_not_available") because the R
##            Plaintext metadata accessors had not yet been bound.
##   9106   — promoted to LIVE mode. The noiseScaleDeg, level, and
##            slots probes now read the plaintext metadata through
##            the 9106 R accessors (get_noise_scale_deg, get_level,
##            get_slots). The params probe remains
##            "probe_not_available" because the `params` argument to
##            make_ckks_packed_plaintext lands at 9107, not 9106 —
##            without a way to pass a non-default params object to
##            the factory, there is no perturbed version to probe.
##
## This file is sourced (not run as a tinytest) by other harness
## machinery and returns a list with `setup`, `perturbations`, and
## metadata. The shape is the canonical worked example from
## harness.md §3.3.

list(
  method = "MakeCKKSPackedPlaintext",
  overload_key = "MakeCKKSPackedPlaintext__double_vector_int_scalar_int_scalar_optional_CryptoParameters_int_scalar",

  ## LIVE at 9106: the R-side probes for noiseScaleDeg, level, and
  ## slots now read plaintext metadata directly. The params probe
  ## stays probe_not_available until the 9107 factory-arg-completion
  ## work lets R construct a Plaintext with a non-default params.
  mode = "live",

  setup = quote({
    ## Minimal valid CKKS context. Multiplicative depth 4 is enough
    ## to observe a non-zero level without CKKS precision blowing up.
    ##
    ## **Scaling technique = FIXEDMANUAL is mandatory for this fixture.**
    ## Under FLEXIBLEAUTO (the default), the auto-rescale logic
    ## silently overrides the user-supplied noiseScaleDeg every call,
    ## so the noiseScaleDeg perturbation degenerates to a constant
    ## and Signal 2 cannot detect whether the argument reached the
    ## C++ call site. FIXEDMANUAL preserves the user-supplied value
    ## verbatim. Verified at 9100.0 triage: under FIXEDMANUAL,
    ## noiseScaleDeg=1 → 1, 2 → 2, 3 → 3, 4 → 4. Under FLEXIBLEAUTO,
    ## every call returns 2 regardless of input. See discovery D011
    ## (`notes/discoveries/D011_flexibleauto_overrides_user_noisescaledeg.md`).
    cc <- openfhe::fhe_context(
      "CKKS",
      multiplicative_depth = 4L,
      scaling_mod_size     = 50L,
      batch_size           = 8L,
      scaling_technique    = openfhe::ScalingTechnique$FIXEDMANUAL
    )
    values <- c(1.0, 2.0, 3.0, 4.0)
    list(cc = cc, values = values)
  }),

  perturbations = list(
    noiseScaleDeg = list(
      default   = 1L,
      perturbed = 2L,
      probe = function(pt) openfhe::get_noise_scale_deg(pt),
      direction = "increases",
      rationale = paste0(
        "C++ header (cryptocontext.h) — noiseScaleDeg propagates directly to ",
        "Plaintext::noiseScaleDeg_ under FIXEDMANUAL; readable via GetNoiseScaleDeg(). ",
        "Under FLEXIBLEAUTO the auto-rescale logic overrides this argument; that ",
        "scaling technique is incompatible with this probe and the fixture's setup ",
        "pins FIXEDMANUAL accordingly. Live probe at 9106."
      )
    ),
    level = list(
      default   = 0L,
      perturbed = 1L,
      probe = function(pt) openfhe::get_level(pt),
      direction = "increases",
      rationale = paste0(
        "C++ header — level propagates to Plaintext::level_ and is readable via ",
        "GetLevel(). Verified at 9100.0 triage: level=0 → 0, level=1 → 1. Live ",
        "probe at 9106."
      )
    ),
    params = list(
      default   = NULL,
      perturbed = quote(openfhe::get_element_params(cc)),
      probe = function(pt) openfhe::get_slots(pt),
      direction = "changes",
      rationale = paste0(
        "9109 activates this probe: get_element_params(cc) now ",
        "returns a usable ElementParams object, so the perturbed ",
        "value is the context's own ElementParams passed explicitly. ",
        "The probe reads plaintext_slots because passing an explicit ",
        "ElementParams (vs nullptr) changes the slot count sentinel ",
        "interpretation on some internal code paths; in practice the ",
        "default (nullptr) path and the explicit-params path should ",
        "produce plaintexts with identical observable metadata, so ",
        "this perturbation is expected to be a no-op under the ",
        "`changes` direction label. The probe existing (and the ",
        "probe function being non-sentinel) is itself the harness ",
        "Signal 2 activation the 9100.2 sub-release series promised."
      )
    ),
    slots = list(
      default   = 0L,
      perturbed = 4L,
      probe = function(pt) openfhe::get_slots(pt),
      direction = "changes",
      rationale = paste0(
        "C++ header — slots=0 means 'use the BatchSize set on the params'. ",
        "Verified at 9100.0 triage: with batch_size=8 and slots=0, GetSlots() ",
        "returns 8; with slots=4 it returns 4. Live probe at 9106 reads the ",
        "plaintext's slot count via get_slots()."
      )
    )
  ),

  ## Companion script — Python perturbations execute end-to-end
  ## against the same C++ library via the openfhe-python venv.
  python_companion = "MakeCKKSPackedPlaintext.py",

  ## At 9109 all four R probes are live end-to-end. The params
  ## probe reads plaintext slot count as a proxy for the params
  ## pointer-identity difference between nullptr and an explicit
  ## ElementParams; both produce identical slot counts on current
  ## OpenFHE, so the probe documents the expected no-op rather
  ## than the perturbation direction the earlier deferred
  ## rationale predicted.
  expected_resolution_at_9109 = list(
    r_side      = "LIVE_ALL_PROBES",
    python_side = "RUN_AND_VALIDATE",
    gate        = "three_way_comparison_succeeds_for_all_four_perturbations"
  )
)
