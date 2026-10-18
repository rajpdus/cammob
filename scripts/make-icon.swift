// Draws the CamMob icon: macOS squircle with a deep blue gradient and a white
// CCTV dome/bullet camera with a red recording dot. Usage: swift make-icon.swift out.png
import AppKit

let size: CGFloat = 1024
let out = CommandLine.arguments[1]
let image = NSImage(size: NSSize(width: size, height: size))
image.lockFocus()
let ctx = NSGraphicsContext.current!.cgContext

let inset: CGFloat = size * 0.095
let rect = CGRect(x: inset, y: inset, width: size - 2 * inset, height: size - 2 * inset)
let bg = NSBezierPath(roundedRect: rect, xRadius: rect.width * 0.225, yRadius: rect.width * 0.225)
ctx.saveGState()
ctx.setShadow(offset: CGSize(width: 0, height: -size * 0.012), blur: size * 0.03, color: NSColor.black.withAlphaComponent(0.35).cgColor)
NSColor(red: 0.08, green: 0.22, blue: 0.45, alpha: 1).setFill()
bg.fill()
ctx.restoreGState()
bg.addClip()
NSGradient(colors: [NSColor(red: 0.20, green: 0.52, blue: 0.95, alpha: 1), NSColor(red: 0.05, green: 0.16, blue: 0.38, alpha: 1)])!
    .draw(in: rect, angle: -90)
NSGradient(colors: [NSColor.white.withAlphaComponent(0.20), NSColor.white.withAlphaComponent(0)])!
    .draw(in: CGRect(x: rect.minX, y: rect.midY, width: rect.width, height: rect.height / 2), angle: 90)

// Faint "live view" grid behind the camera.
NSColor.white.withAlphaComponent(0.08).setStroke()
let grid = NSBezierPath(); grid.lineWidth = size * 0.006
for i in 1..<3 {
    let x = rect.minX + rect.width * CGFloat(i) / 3, y = rect.minY + rect.height * CGFloat(i) / 3
    grid.move(to: CGPoint(x: x, y: rect.minY)); grid.line(to: CGPoint(x: x, y: rect.maxY))
    grid.move(to: CGPoint(x: rect.minX, y: y)); grid.line(to: CGPoint(x: rect.maxX, y: y))
}
grid.stroke()

// Bullet CCTV camera, drawn tilted down-right, in white with a soft shadow.
ctx.saveGState()
ctx.setShadow(offset: CGSize(width: 0, height: -size * 0.012), blur: size * 0.03, color: NSColor.black.withAlphaComponent(0.35).cgColor)
ctx.translateBy(x: rect.midX, y: rect.midY)
ctx.rotate(by: -0.28)
let bodyW = rect.width * 0.56, bodyH = rect.height * 0.26
let body = CGRect(x: -bodyW * 0.55, y: -bodyH / 2, width: bodyW, height: bodyH)
NSColor.white.setFill()
NSBezierPath(roundedRect: body, xRadius: bodyH * 0.22, yRadius: bodyH * 0.22).fill()
// Lens hood: wider ring at the front (right end).
let hoodW = bodyH * 0.36
let hood = CGRect(x: body.maxX - hoodW * 0.6, y: body.minY - bodyH * 0.10, width: hoodW, height: bodyH * 1.2)
NSBezierPath(roundedRect: hood, xRadius: hoodW * 0.25, yRadius: hoodW * 0.25).fill()
// Lens.
NSColor(red: 0.07, green: 0.14, blue: 0.30, alpha: 1).setFill()
let lensR = bodyH * 0.34
NSBezierPath(ovalIn: CGRect(x: hood.midX - lensR * 0.55, y: hood.midY - lensR, width: lensR * 2 * 0.55, height: lensR * 2)).fill()
NSColor(red: 0.35, green: 0.70, blue: 1.0, alpha: 1).setFill()
NSBezierPath(ovalIn: CGRect(x: hood.midX - lensR * 0.28, y: hood.midY - lensR * 0.5, width: lensR * 0.56 * 0.55, height: lensR)).fill()
// Mount arm + base (on the back-top of the body).
NSColor.white.setFill()
let armW = bodyH * 0.16
NSBezierPath(roundedRect: CGRect(x: body.minX + bodyW * 0.28, y: body.maxY - armW * 0.3, width: armW, height: bodyH * 0.55), xRadius: armW * 0.3, yRadius: armW * 0.3).fill()
ctx.restoreGState()
// Base plate (unrotated, top of the icon).
ctx.saveGState()
ctx.setShadow(offset: CGSize(width: 0, height: -size * 0.008), blur: size * 0.02, color: NSColor.black.withAlphaComponent(0.3).cgColor)
NSColor.white.setFill()
let plateW = rect.width * 0.22, plateH = rect.height * 0.045
NSBezierPath(roundedRect: CGRect(x: rect.midX - plateW * 0.68, y: rect.maxY - rect.height * 0.14, width: plateW, height: plateH), xRadius: plateH / 2, yRadius: plateH / 2).fill()
ctx.restoreGState()
// Recording dot.
NSColor(red: 0.95, green: 0.23, blue: 0.21, alpha: 1).setFill()
let dotR = rect.width * 0.045
NSBezierPath(ovalIn: CGRect(x: rect.maxX - rect.width * 0.20 - dotR, y: rect.minY + rect.height * 0.17 - dotR, width: dotR * 2, height: dotR * 2)).fill()
NSColor.white.withAlphaComponent(0.9).setStroke()
let ring = NSBezierPath(ovalIn: CGRect(x: rect.maxX - rect.width * 0.20 - dotR * 1.6, y: rect.minY + rect.height * 0.17 - dotR * 1.6, width: dotR * 3.2, height: dotR * 3.2))
ring.lineWidth = size * 0.008; ring.stroke()

image.unlockFocus()
let png = NSBitmapImageRep(data: image.tiffRepresentation!)!.representation(using: .png, properties: [:])!
try! png.write(to: URL(fileURLWithPath: out))
print("wrote \(out)")
