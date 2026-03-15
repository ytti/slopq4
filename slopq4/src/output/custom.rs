use std::collections::HashMap;
use std::path::PathBuf;

/// Resolves file name templates containing `%KEY%` placeholders.
///
/// Supported variables: `%AS-SET%`, `%AFI%`, `%FORMAT%`, `%CLASS%`.
pub struct TemplateNamer {
    pattern: String,
}

impl TemplateNamer {
    pub fn new(pattern: impl Into<String>) -> Self {
        Self { pattern: pattern.into() }
    }

    /// Replace all `%KEY%` tokens in the pattern with values from `vars`.
    pub fn resolve(&self, vars: &HashMap<&str, &str>) -> PathBuf {
        let mut result = self.pattern.clone();
        for (key, value) in vars {
            result = result.replace(&format!("%{}%", key), value);
        }
        PathBuf::from(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replaces_all_vars() {
        let namer = TemplateNamer::new("output/%AS-SET%_%AFI%_%CLASS%.%FORMAT%");
        let vars: HashMap<&str, &str> = [
            ("AS-SET", "AS-EXAMPLE"),
            ("AFI", "v4"),
            ("CLASS", "valid"),
            ("FORMAT", "json"),
        ]
        .into_iter()
        .collect();
        assert_eq!(namer.resolve(&vars), PathBuf::from("output/AS-EXAMPLE_v4_valid.json"));
    }

    #[test]
    fn leaves_unknown_placeholders_as_is() {
        let namer = TemplateNamer::new("%UNKNOWN%");
        let vars = HashMap::new();
        assert_eq!(namer.resolve(&vars), PathBuf::from("%UNKNOWN%"));
    }
}
