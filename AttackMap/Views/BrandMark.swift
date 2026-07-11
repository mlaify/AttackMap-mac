import SwiftUI

/// The AttackMap icon (Concept A) drawn as vectors so it stays crisp at any
/// size without depending on the rasterized app-icon PNGs. Coordinates mirror
/// branding/AppIcon-master.svg (a 1024×1024 space, scaled to `size`).
struct BrandMark: View {
    var size: CGFloat = 96

    var body: some View {
        Canvas { ctx, canvas in
            let s = canvas.width / 1024
            func p(_ x: CGFloat, _ y: CGFloat) -> CGPoint { CGPoint(x: x * s, y: y * s) }
            func dot(_ c: CGPoint, _ r: CGFloat, _ color: Color) {
                ctx.fill(Path(ellipseIn: CGRect(x: c.x - r * s, y: c.y - r * s,
                                                width: 2 * r * s, height: 2 * r * s)),
                         with: .color(color))
            }

            let bg = CGRect(x: 112 * s, y: 104 * s, width: 800 * s, height: 800 * s)
            ctx.fill(Path(roundedRect: bg, cornerRadius: 180 * s),
                     with: .linearGradient(
                        Gradient(colors: [brand(0x1b2a4a), brand(0x0b1120)]),
                        startPoint: CGPoint(x: bg.midX, y: bg.minY),
                        endPoint: CGPoint(x: bg.midX, y: bg.maxY)))

            var gray = Path()
            gray.move(to: p(330, 390)); gray.addLine(to: p(540, 320))
            gray.move(to: p(540, 320)); gray.addLine(to: p(610, 520))
            ctx.stroke(gray, with: .color(brand(0x38486a)),
                       style: StrokeStyle(lineWidth: 10 * s, lineCap: .round))

            var path = Path()
            path.move(to: p(330, 390)); path.addLine(to: p(400, 600))
            path.addLine(to: p(610, 520)); path.addLine(to: p(680, 690))
            ctx.stroke(path, with: .color(brand(0xff7d3d)),
                       style: StrokeStyle(lineWidth: 18 * s, lineCap: .round, lineJoin: .round))

            dot(p(540, 320), 24, brand(0x5b6f96))
            dot(p(400, 600), 24, brand(0x9db4d6))
            dot(p(610, 520), 24, brand(0x9db4d6))
            dot(p(330, 390), 30, brand(0x2fd3c3))

            let t = p(680, 690)
            ctx.stroke(Path(ellipseIn: CGRect(x: t.x - 58 * s, y: t.y - 58 * s,
                                              width: 116 * s, height: 116 * s)),
                       with: .color(brand(0xff4d4d)), lineWidth: 8 * s)
            var ticks = Path()
            ticks.move(to: p(680, 614)); ticks.addLine(to: p(680, 636))
            ticks.move(to: p(680, 744)); ticks.addLine(to: p(680, 766))
            ticks.move(to: p(604, 690)); ticks.addLine(to: p(626, 690))
            ticks.move(to: p(734, 690)); ticks.addLine(to: p(756, 690))
            ctx.stroke(ticks, with: .color(brand(0xff4d4d)),
                       style: StrokeStyle(lineWidth: 8 * s, lineCap: .round))
            dot(t, 38, brand(0xff4d4d))
            dot(t, 13, .white)
        }
        .frame(width: size, height: size)
        .accessibilityLabel("AttackMap")
    }
}

private func brand(_ hex: UInt) -> Color {
    Color(.sRGB,
          red: Double((hex >> 16) & 0xff) / 255,
          green: Double((hex >> 8) & 0xff) / 255,
          blue: Double(hex & 0xff) / 255)
}
