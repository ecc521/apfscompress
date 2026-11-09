//! Integration tests for `apfscompress dmg`: build real images with hdiutil
//! and read them back.

use std::fs;
use std::os::macos::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_apfscompress")).args(args).output().expect("failed to spawn apfscompress")
}

fn text(out: &Output) -> String {
    format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr))
}

/// `UF_COMPRESSED`.
fn is_compressed(p: &Path) -> bool {
    fs::symlink_metadata(p).unwrap().st_flags() & 0x20 != 0
}

/// A minimal app bundle: compressible code and text, plus one incompressible file.
fn fake_app(dir: &Path, name: &str, min_macos: Option<&str>) -> PathBuf {
    let app = dir.join(format!("{name}.app"));
    fs::create_dir_all(app.join("Contents/MacOS")).unwrap();
    fs::create_dir_all(app.join("Contents/Resources/en.lproj")).unwrap();
    let min = min_macos.map_or(String::new(), |v| format!("<key>LSMinimumSystemVersion</key><string>{v}</string>"));
    fs::write(
        app.join("Contents/Info.plist"),
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \
             \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict>\
             <key>CFBundleName</key><string>{name}</string>{min}</dict></plist>\n"
        ),
    )
    .unwrap();
    fs::write(app.join("Contents/MacOS").join(name), b"\x00\x01mov x0, x1; bl _objc_msgSend\n".repeat(20_000)).unwrap();
    fs::write(app.join("Contents/Resources/en.lproj/Localizable.strings"), b"\"Open\" = \"Open\";\n".repeat(5_000)).unwrap();
    let mut x: u32 = 0x9E37_79B9;
    let noise: Vec<u8> = (0..200_000)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x as u8
        })
        .collect();
    fs::write(app.join("Contents/Resources/noise.bin"), noise).unwrap();
    app
}

/// Enough of a Finder `.DS_Store` (its "Bud1" header) that macOS keeps it on
/// a volume; one that isn't is deleted when the volume is unmounted.
fn ds_store() -> Vec<u8> {
    let mut b = b"\x00\x00\x00\x01Bud1".to_vec();
    b.resize(4096, 0);
    b
}

/// An image mounted read-only for the length of a test.
struct Mount(PathBuf);

impl Mount {
    fn new(image: &Path, point: PathBuf) -> Mount {
        fs::create_dir_all(&point).unwrap();
        let out = Command::new("hdiutil")
            .args(["attach", "-nobrowse", "-readonly", "-noverify", "-noautoopen", "-mountpoint"])
            .arg(&point)
            .arg(image)
            .output()
            .unwrap();
        assert!(out.status.success(), "attach failed: {}", text(&out));
        Mount(point)
    }
}

impl Drop for Mount {
    fn drop(&mut self) {
        let _ = Command::new("hdiutil").args(["detach", "-force", "-quiet"]).arg(&self.0).status();
    }
}

fn hdiutil(args: &[&str]) {
    let out = Command::new("hdiutil").args(args).output().unwrap();
    assert!(out.status.success(), "hdiutil {args:?} failed: {}", text(&out));
}

#[test]
fn an_app_installs_compressed_in_formats_its_oldest_macos_can_read() {
    let dir = tempfile::tempdir().unwrap();
    let app = fake_app(dir.path(), "Fake", Some("11.0"));
    let image = dir.path().join("Fake.dmg");

    let out = run(&["dmg", app.to_str().unwrap(), "-o", image.to_str().unwrap()]);
    let log = text(&out);
    assert!(out.status.success(), "dmg failed: {log}");
    // LZBITMAP needs macOS 12, so it must not be raced for an 11.0 app.
    assert!(log.contains("macOS 11.0 and later: racing crushlzfse:10\n"), "{log}");
    assert!(log.contains("verified"), "{log}");

    let m = Mount::new(&image, dir.path().join("mnt"));
    let mounted = m.0.join("Fake.app");
    assert_eq!(fs::read_link(m.0.join("Applications")).unwrap(), Path::new("/Applications"));
    for rel in ["Contents/MacOS/Fake", "Contents/Resources/en.lproj/Localizable.strings"] {
        assert!(is_compressed(&mounted.join(rel)), "{rel} is not compressed in the image");
        assert_eq!(fs::read(mounted.join(rel)).unwrap(), fs::read(app.join(rel)).unwrap());
        let info = text(&run(&["info", mounted.join(rel).to_str().unwrap()]));
        assert!(info.contains("type 11") || info.contains("type 12"), "expected LZFSE, got: {info}");
    }
    assert!(!is_compressed(&mounted.join("Contents/Resources/noise.bin")));

    // What Finder does when the app is dragged out: copyfile keeps it compressed.
    let installed = dir.path().join("Installed.app");
    let out = Command::new("ditto").arg(&mounted).arg(&installed).output().unwrap();
    assert!(out.status.success());
    assert!(is_compressed(&installed.join("Contents/MacOS/Fake")));
}

#[test]
fn an_image_keeps_its_layout_format_and_volume_name() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("src");
    fs::create_dir(&src).unwrap();
    fake_app(&src, "Layout", Some("13.0"));
    fs::create_dir(src.join(".background")).unwrap();
    fs::write(src.join(".background/bg.tiff"), b"background").unwrap();
    std::os::unix::fs::symlink("/Applications", src.join("Applications")).unwrap();
    let input = dir.path().join("in.dmg");
    // Built the way DMG layout tools do: writable, layout written, converted.
    let rw = dir.path().join("rw.dmg");
    hdiutil(&["create", "-quiet", "-srcfolder", src.to_str().unwrap(), "-volname", "Layout Test", "-fs", "APFS",
        "-format", "UDRW", rw.to_str().unwrap()]);
    {
        let point = dir.path().join("rw");
        fs::create_dir_all(&point).unwrap();
        hdiutil(&["attach", "-quiet", "-nobrowse", "-mountpoint", point.to_str().unwrap(), rw.to_str().unwrap()]);
        fs::write(point.join(".DS_Store"), ds_store()).unwrap();
        hdiutil(&["detach", "-quiet", point.to_str().unwrap()]);
    }
    hdiutil(&["convert", "-quiet", rw.to_str().unwrap(), "-format", "ULFO", "-o", input.to_str().unwrap()]);
    let output = dir.path().join("out.dmg");

    let out = run(&["dmg", input.to_str().unwrap(), "-o", output.to_str().unwrap()]);
    let log = text(&out);
    assert!(out.status.success(), "dmg failed: {log}");
    assert!(log.contains("macOS 13.0 and later: racing crushlzbitmap:9, crushlzfse:10"), "{log}");
    assert!(log.contains("(ULFO, APFS,"), "{log}");

    let m = Mount::new(&output, dir.path().join("mnt"));
    assert_eq!(fs::read(m.0.join(".background/bg.tiff")).unwrap(), b"background");
    assert_eq!(fs::read(m.0.join(".DS_Store")).unwrap(), ds_store());
    assert_eq!(fs::read_link(m.0.join("Applications")).unwrap(), Path::new("/Applications"));
    assert!(is_compressed(&m.0.join("Layout.app/Contents/MacOS/Layout")));
    let info = Command::new("diskutil").arg("info").arg(&m.0).output().unwrap();
    assert!(text(&info).contains("Layout Test"), "volume name not kept: {}", text(&info));
}

#[test]
fn an_app_without_a_minimum_macos_needs_one_given() {
    let dir = tempfile::tempdir().unwrap();
    let app = fake_app(dir.path(), "NoMin", None);
    let image = dir.path().join("NoMin.dmg");

    let out = run(&["dmg", app.to_str().unwrap(), "-o", image.to_str().unwrap()]);
    assert!(!out.status.success());
    assert!(text(&out).contains("--min-macos"), "{}", text(&out));
    assert!(!image.exists());

    let out = run(&["dmg", app.to_str().unwrap(), "-o", image.to_str().unwrap(), "--min-macos", "12.0"]);
    assert!(out.status.success(), "{}", text(&out));
}

#[test]
fn an_apfs_image_is_refused_below_high_sierra() {
    let dir = tempfile::tempdir().unwrap();
    let app = fake_app(dir.path(), "Old", Some("10.12"));
    let image = dir.path().join("Old.dmg");
    let out = run(&["dmg", app.to_str().unwrap(), "-o", image.to_str().unwrap(), "--filesystem", "APFS"]);
    assert!(!out.status.success());
    assert!(text(&out).contains("needs macOS 10.13"), "{}", text(&out));
}
