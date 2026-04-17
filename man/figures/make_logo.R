## Generate hex sticker for openfhe.
##
## Visual motif: 2D lattice patch with two basis vectors drawn from
## the origin, the fundamental parallelogram they span filled in a
## diluted violet, a fourth navy "sum" dot at the far corner of that
## parallelogram, and violet noise halos around every lattice point.
##
## The parallelogram + sum dot carry the homomorphism visually: the
## far corner at b1+b2 is the geometric vector addition of the two
## basis-point ciphertexts, which IS ciphertext addition under RLWE.
## No caption is needed — the picture is the statement. See
## `make_logo_desc.md` in the same directory for the full semantic
## reading and the change-resistance contract.
##
## Aesthetic template: the bcaboot hex sticker. One dominant visual,
## harmonized cool palette, hex border color echoes an interior
## accent, clean thick lines that read at any size.
library(ggplot2)
library(hexSticker)
library(sysfonts)
library(showtext)

font_add_google("Raleway", "raleway")
showtext_auto()

## Lattice basis vectors. Slightly skewed so the result does not look
## like Z^2 graph paper — a real lattice basis is rarely axis-aligned.
## The basis is also tilted ~6 degrees clockwise so the parallelogram
## sum corner (b1+b2) sits lower than a symmetric basis would place
## it — this makes the parallelogram read as "a tilted shape in a
## lattice" rather than a perfect diamond aligned with the visual
## axes, and gives the whole picture a subtle asymmetry that
## reinforces the "arbitrary public basis" reading.
##
## Sized for a 3x3 dot patch (9 points) that fills the hex interior
## comfortably. A 4x4 dot version (3x3 fundamental cells) with the
## parallelogram centered on the hex was tried earlier but came out
## too busy at pkgdown navbar size. The 3x3 version is inherently
## asymmetric in one dimension: with 9 dots the fundamental
## parallelogram cannot be centered on the hex (there is no
## lattice-integer arrangement that places the parallelogram at the
## lattice center with 9 surrounding dots), so we let the origin
## sit at the hex center and the parallelogram occupies the
## upper-right quadrant.
b1 <- c(1.30, 0.13)
b2 <- c(0.50, 1.25)

## Generate lattice points as integer combinations of b1 and b2.
make_lattice <- function(range, b1, b2) {
    ij <- expand.grid(i = range, j = range)
    data.frame(
        x = ij$i * b1[1] + ij$j * b2[1],
        y = ij$i * b1[2] + ij$j * b2[2]
    )
}

## 3x3 dot patch (9 points). Origin at plot (0, 0).
pts <- make_lattice(-1:1, b1, b2)

## Soft radial glow: approximated by stacking many concentric
## geom_point layers at each lattice point with decreasing alpha and
## increasing size. More layers -> smoother gradient. The glow color
## is the purple that also serves as the hex border and the
## basis-vector accent, so it ties the interior palette to the border
## rather than introducing a new color. See `make_logo_desc.md`
## section "The violet halos: noise balls" for why these are here.
glow_layers <- data.frame(
    size  = c(8.5,  7.0,  5.8,  4.8,  3.8,  2.9,  2.3,  1.8),
    alpha = c(0.03, 0.05, 0.08, 0.12, 0.17, 0.23, 0.30, 0.35)
)

## Four distinguished lattice points — origin, b1, b2, and the sum
## b1+b2. The sum point is the far corner of the parallelogram and
## is the key visual carrier of the homomorphism: geometric vector
## addition of two ciphertext-as-lattice-points produces a third
## ciphertext-as-lattice-point. Promoting it from a background
## steel-blue dot to a foreground navy generator (with its own
## noise halo) is what makes the homomorphism visible without a
## caption.
pts$special <- with(pts, {
    is_origin <- abs(x) < 1e-6 & abs(y) < 1e-6
    is_b1     <- abs(x - b1[1]) < 1e-6 & abs(y - b1[2]) < 1e-6
    is_b2     <- abs(x - b2[1]) < 1e-6 & abs(y - b2[2]) < 1e-6
    is_sum    <- abs(x - (b1[1] + b2[1])) < 1e-6 &
                 abs(y - (b1[2] + b2[2])) < 1e-6
    is_origin | is_b1 | is_b2 | is_sum
})

## Basis vector segments from origin to b1 and b2.
basis_df <- data.frame(
    x    = c(0, 0),
    y    = c(0, 0),
    xend = c(b1[1], b2[1]),
    yend = c(b1[2], b2[2]),
    vec  = c("b1", "b2")
)

## Fundamental parallelogram: the region spanned by b1 and b2, with
## vertices at origin, b1, b1+b2, b2. Filled at low alpha so it
## reads as a tinted background rather than a solid panel.
parallelogram <- data.frame(
    x = c(0, b1[1], b1[1] + b2[1], b2[1]),
    y = c(0, b1[2], b1[2] + b2[2], b2[2])
)

## Cool cryptography-feeling palette. The hex border is navy so it
## reads against any light pkgdown page background; navy also ties
## the border to the four distinguished generator dots (same color),
## so the outermost and innermost dark elements of the logo are
## visually locked together. The noise halos keep their own ambient
## purple tone via col_glow so the interior still reads as "warm
## violet glow in a cool lattice" without relying on the border for
## color unity.
col_lattice <- "#457b9d"   # muted steel blue - background lattice points
col_basis   <- "#9d4edd"   # violet - basis vectors and parallelogram fill
col_special <- "#1d3557"   # navy - origin + basis endpoints + sum dot
col_border  <- col_special # navy - hex border, echoes the generator dots
col_fill    <- "#f5f0eb"   # cream - hex interior
col_glow    <- "#6a4c93"   # purple - noise halos, ambient interior tint

p <- ggplot()

## Layer 1: parallelogram fill underneath everything. The fill is
## one fundamental cell of the lattice; highlighting just the
## origin-anchored cell anchors the "sum corner at b1+b2" reading
## and makes the homomorphism visible as a geometric completion
## rather than as a caption.
p <- p + geom_polygon(data = parallelogram,
                      aes(x = x, y = y),
                      fill = col_basis,
                      alpha = 0.16,
                      color = NA)

## Layer 2: stacked glow rings under every lattice point. Outer rings
## first (faint, large), inner rings last (brighter, smaller).
for (k in seq_len(nrow(glow_layers))) {
    p <- p + geom_point(data = pts,
                        aes(x = x, y = y),
                        color = col_glow,
                        size   = glow_layers$size[k],
                        alpha  = glow_layers$alpha[k])
}

## Layer 3: derived (steel-blue) lattice dots, then basis-vector
## segments, then the four distinguished navy dots on top.
p <- p +
    geom_point(data = subset(pts, !special),
               aes(x = x, y = y),
               color = col_lattice, size = 1.15, alpha = 0.90) +
    geom_segment(data = basis_df,
                 aes(x = x, y = y, xend = xend, yend = yend),
                 color = col_basis,
                 linewidth = 1.9, lineend = "round") +
    geom_point(data = subset(pts, special),
               aes(x = x, y = y),
               color = col_special, size = 1.90) +
    coord_fixed(xlim = c(-2.10, 2.10), ylim = c(-2.00, 2.00),
                clip = "off") +
    theme_void() +
    theme(legend.position = "none",
          plot.background  = element_rect(fill = "transparent", color = NA),
          panel.background = element_rect(fill = "transparent", color = NA))

sticker(
    p,
    package    = "openfhe",
    s_x        = 1,
    s_y        = 0.95,
    s_width    = 1.34,
    s_height   = 1.45,
    p_size     = 20,
    p_x        = 1,
    p_y        = 1.60,
    p_color    = "#3d3240",
    p_family   = "raleway",
    p_fontface = "bold",
    h_fill     = col_fill,
    h_color    = col_border,
    h_size     = 1.4,
    filename   = "/Users/naras/research/fhe/R_dev/openfhe/man/figures/logo.png",
    dpi        = 300
)

cat("Logo saved to R_dev/openfhe/man/figures/logo.png\n")
