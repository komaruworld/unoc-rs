use std::fs::File;
use std::io::Write;
use std::path::Path;

use zip::write::SimpleFileOptions;

pub fn write_zip_apk(path: &Path, entries: &[(&str, &[u8])]) {
    let file = File::create(path).expect("create fixture apk");
    let mut zip = zip::ZipWriter::new(file);
    let options = SimpleFileOptions::default();

    for (name, bytes) in entries {
        zip.start_file(*name, options).expect("start zip entry");
        zip.write_all(bytes).expect("write zip entry");
    }

    zip.finish().expect("finish zip");
}
