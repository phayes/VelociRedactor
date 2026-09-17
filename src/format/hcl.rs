use hcl_edit::expr::{Array, Object as HclObject, ObjectKey};
use hcl_edit::repr::{Decorated, Span, Spanned};
use hcl_edit::structure::{Block, BlockLabel, Body, Structure};
use hcl_edit::template::HeredocTemplate;
use hcl_edit::visit::{self, Visit};

use super::{Container, Format, FormatError, Leaf, LeafVisitor, Object, Splicer};

/// HCL, including Terraform and Nomad files.
///
/// String literals, the literal parts of string templates, and heredocs are
/// scanned. Blocks are objects keyed by their type; values are keyed by
/// their attribute or object key. Block labels, keys, and interpolated
/// expressions are left alone.
#[derive(Debug, Clone, Copy, Default)]
pub struct Hcl;

impl Format for Hcl {
    fn name(&self) -> &str {
        "hcl"
    }

    fn extensions(&self) -> &[&str] {
        &["hcl", "tf", "tfvars", "nomad", "pkr.hcl"]
    }

    fn file_names(&self) -> &[&str] {
        &[".terraform.lock.hcl", ".terraformrc", "terraform.rc"]
    }

    fn rewrite(&self, input: &[u8], visitor: &mut dyn LeafVisitor) -> Result<Vec<u8>, FormatError> {
        let text = std::str::from_utf8(input).map_err(|e| FormatError::new("hcl", e))?;
        let body = hcl_edit::parser::parse_body(text).map_err(|e| FormatError::new("hcl", e))?;
        let mut walker = Walker {
            visitor,
            splicer: Splicer::new(input),
            key: None,
            in_heredoc: false,
        };
        walker.body(&body, None);
        Ok(walker.splicer.finish())
    }
}

struct Walker<'a, 'v> {
    visitor: &'v mut dyn LeafVisitor,
    splicer: Splicer<'a>,
    /// Key of the value being visited.
    key: Option<String>,
    in_heredoc: bool,
}

impl Walker<'_, '_> {
    fn body(&mut self, body: &Body, key: Option<&str>) {
        let summary: Object<'_> = body
            .attributes()
            .map(|attr| (attr.key.as_str(), attr.value.as_str()))
            .collect();
        self.visitor.enter(key, Container::Object(&summary));
        for structure in body.iter() {
            self.visit_structure(structure);
        }
        self.visitor.exit();
    }

    fn with_key(&mut self, key: Option<String>, f: impl FnOnce(&mut Self)) {
        let previous = std::mem::replace(&mut self.key, key);
        f(self);
        self.key = previous;
    }

    fn scalar(
        &mut self,
        value: &str,
        raw: std::ops::Range<usize>,
        content: std::ops::Range<usize>,
        encode: impl FnOnce(&str) -> String,
    ) {
        let leaf = Leaf::new(value)
            .with_key(self.key.as_deref())
            .with_offset(content.start);
        if let Some(replacement) = self.visitor.leaf(&leaf) {
            self.splicer
                .apply(raw, content, value, &replacement, encode);
        }
    }
}

impl Visit for Walker<'_, '_> {
    fn visit_structure(&mut self, node: &Structure) {
        match node {
            Structure::Attribute(attr) => {
                let key = Some(attr.key.to_string());
                self.with_key(key, |w| w.visit_expr(&attr.value));
            }
            Structure::Block(block) => self.visit_block(block),
        }
    }

    fn visit_block(&mut self, node: &Block) {
        self.with_key(None, |w| w.body(&node.body, Some(node.ident.as_str())));
    }

    fn visit_block_label(&mut self, _node: &BlockLabel) {}

    fn visit_object_key(&mut self, _node: &ObjectKey) {}

    fn visit_array(&mut self, node: &Array) {
        self.visitor.enter(self.key.as_deref(), Container::Array);
        self.with_key(None, |w| visit::visit_array(w, node));
        self.visitor.exit();
    }

    fn visit_object(&mut self, node: &HclObject) {
        let items: Vec<(String, Option<&str>)> = node
            .iter()
            .filter_map(|(k, v)| Some((object_key(k)?, v.expr().as_str())))
            .collect();
        let summary: Object<'_> = items.iter().map(|(k, v)| (k.as_str(), *v)).collect();
        self.visitor
            .enter(self.key.as_deref(), Container::Object(&summary));
        for (k, v) in node.iter() {
            self.with_key(object_key(k), |w| w.visit_expr(v.expr()));
        }
        self.visitor.exit();
    }

    fn visit_string(&mut self, node: &Decorated<String>) {
        let Some(raw) = node.span() else { return };
        let content = raw.start + 1..raw.end.saturating_sub(1).max(raw.start + 1);
        self.scalar(node, raw, content, |v| format!("\"{}\"", escape_quoted(v)));
    }

    fn visit_heredoc_template(&mut self, node: &HeredocTemplate) {
        let previous = std::mem::replace(&mut self.in_heredoc, true);
        visit::visit_heredoc_template(self, node);
        self.in_heredoc = previous;
    }

    fn visit_literal(&mut self, node: &Spanned<String>) {
        let Some(span) = node.span() else { return };
        let heredoc = self.in_heredoc;
        self.scalar(node.value(), span.clone(), span, |v| {
            if heredoc {
                escape_template(v)
            } else {
                escape_quoted(v)
            }
        });
    }
}

fn object_key(key: &ObjectKey) -> Option<String> {
    match key {
        ObjectKey::Ident(ident) => Some(ident.to_string()),
        ObjectKey::Expression(expr) => expr.as_str().map(str::to_owned),
    }
}

/// Escape a value for use inside a quoted HCL string.
fn escape_quoted(value: &str) -> String {
    let json = serde_json::to_string(value).expect("strings always serialize");
    escape_template(&json[1..json.len() - 1])
}

/// Escape template sequences so they are read literally.
fn escape_template(value: &str) -> String {
    value.replace("${", "$${").replace("%{", "%%{")
}
