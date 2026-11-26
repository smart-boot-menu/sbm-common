#![forbid(unsafe_code)]

use std::fs;
use std::path::PathBuf;

fn main() {
    let out_dir = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("schemas"));
    fs::create_dir_all(&out_dir).expect("create schemas directory");
    let schemas = sbm_schema::all_schemas();
    for s in &schemas {
        let path = out_dir.join(s.filename);
        let mut content = serde_json::to_string_pretty(&s.schema).expect("serialize schema");
        content.push('\n');
        fs::write(&path, content).expect("write schema file");
    }
    println!(
        "Exported {} schemas into {}",
        schemas.len(),
        out_dir.display()
    );
}
