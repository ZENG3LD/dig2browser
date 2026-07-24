//! Coercion of a raw [`crate::extract::Extracted`] result to the column's
//! declared [`ColumnType`], producing a typed protocol [`Value`].
//!
//! Returns `Err(())` on any coercion failure (non-numeric text under
//! `Integer`/`Real`, unparseable `Boolean`/`Timestamp`, a type/pick
//! combination that has no sensible mapping). The caller treats `Err(())`
//! exactly like an extraction miss — both are folded into the column's
//! `OnError` policy by `crate::build_row`.

use dig2browser_protocol::shape::{ColumnType, Value};

use crate::extract::Extracted;

pub(crate) fn coerce(extracted: Extracted, ty: ColumnType) -> Result<Value, ()> {
    match extracted {
        Extracted::Missing => Err(()),
        // Const is a literal passthrough: emitted as-is regardless of
        // whether its runtime Value variant matches the column's declared
        // ColumnType. Rationale: `Extractor::Const` "never misses" (task
        // rule 5), so it must never be routed through the miss/OnError path;
        // re-coercing an already-typed literal against a possibly-mismatched
        // declared type would need its own ambiguous cross-type coercion
        // matrix (e.g. Const(Integer) into a Text column) for no real
        // benefit — a schema author who declares a mismatched Const/type
        // pair gets exactly the value they wrote, not a silently-invented
        // conversion. Value::validate() bounds (text/blob length, finite
        // Real) are still enforced downstream by `Row::new`.
        Extracted::Value(value) => Ok(value),
        Extracted::Bool(flag) => coerce_bool(flag, ty),
        Extracted::Text(text) => coerce_text(&text, ty),
    }
}

/// `Css::Exists` yields a boolean directly for a `Boolean` column, and a
/// `"true"`/`"false"` text cell for a `Text` column (the only two mappings
/// with an unambiguous meaning). Any other declared type has no sensible
/// interpretation of "did a selector match" and is a coercion failure.
fn coerce_bool(flag: bool, ty: ColumnType) -> Result<Value, ()> {
    match ty {
        ColumnType::Boolean => Ok(Value::Boolean(flag)),
        ColumnType::Text => Ok(Value::Text(if flag { "true" } else { "false" }.to_owned())),
        _ => Err(()),
    }
}

fn coerce_text(text: &str, ty: ColumnType) -> Result<Value, ()> {
    let trimmed = text.trim();
    match ty {
        ColumnType::Text => Ok(Value::Text(text.to_owned())),
        ColumnType::Integer => trimmed.parse::<i64>().map(Value::Integer).map_err(|_| ()),
        ColumnType::Real => {
            let parsed: f64 = trimmed.parse().map_err(|_| ())?;
            if parsed.is_finite() {
                Ok(Value::Real(parsed))
            } else {
                Err(())
            }
        }
        // Case-insensitive "true"/"false", plus "1"/"0" as a common
        // scraped-attribute shorthand (e.g. `data-active="1"`).
        ColumnType::Boolean => match trimmed.to_ascii_lowercase().as_str() {
            "true" | "1" => Ok(Value::Boolean(true)),
            "false" | "0" => Ok(Value::Boolean(false)),
            _ => Err(()),
        },
        ColumnType::Timestamp => trimmed.parse::<i64>().map(Value::Timestamp).map_err(|_| ()),
        ColumnType::Blob => Ok(Value::Blob(text.as_bytes().to_vec())),
    }
}

#[cfg(test)]
mod tests {
    use super::coerce;
    use crate::extract::Extracted;
    use dig2browser_protocol::shape::{ColumnType, Value};

    #[test]
    fn missing_always_fails() {
        assert!(coerce(Extracted::Missing, ColumnType::Text).is_err());
        assert!(coerce(Extracted::Missing, ColumnType::Boolean).is_err());
    }

    #[test]
    fn integer_and_real_parse_and_trim() {
        assert_eq!(
            coerce(Extracted::Text("  42 ".to_owned()), ColumnType::Integer),
            Ok(Value::Integer(42))
        );
        assert_eq!(
            coerce(Extracted::Text(" 3.5 ".to_owned()), ColumnType::Real),
            Ok(Value::Real(3.5))
        );
        assert!(coerce(Extracted::Text("not-a-number".to_owned()), ColumnType::Real).is_err());
        assert!(coerce(Extracted::Text("NaN".to_owned()), ColumnType::Real).is_err());
    }

    #[test]
    fn boolean_accepts_true_false_and_1_0_case_insensitive() {
        for (input, expected) in [
            ("true", true),
            ("TRUE", true),
            ("1", true),
            ("false", false),
            ("FALSE", false),
            ("0", false),
        ] {
            assert_eq!(
                coerce(Extracted::Text(input.to_owned()), ColumnType::Boolean),
                Ok(Value::Boolean(expected))
            );
        }
        assert!(coerce(Extracted::Text("yes".to_owned()), ColumnType::Boolean).is_err());
    }

    #[test]
    fn exists_bool_maps_to_boolean_and_text_only() {
        assert_eq!(
            coerce(Extracted::Bool(true), ColumnType::Boolean),
            Ok(Value::Boolean(true))
        );
        assert_eq!(
            coerce(Extracted::Bool(false), ColumnType::Text),
            Ok(Value::Text("false".to_owned()))
        );
        assert!(coerce(Extracted::Bool(true), ColumnType::Integer).is_err());
    }

    #[test]
    fn const_value_passes_through_regardless_of_declared_type() {
        assert_eq!(
            coerce(Extracted::Value(Value::Integer(7)), ColumnType::Text),
            Ok(Value::Integer(7))
        );
    }

    #[test]
    fn blob_uses_raw_text_bytes() {
        assert_eq!(
            coerce(Extracted::Text("abc".to_owned()), ColumnType::Blob),
            Ok(Value::Blob(vec![97, 98, 99]))
        );
    }
}
