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
        Extracted::Json(value) => coerce_json(&value, ty),
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

/// Coerce a `shape_json` [`Extracted::Json`] scalar/composite to the
/// column's declared type.
///
/// | JSON value | `Text` | `Integer` | `Real` | `Boolean` | `Timestamp` | `Blob` |
/// |---|---|---|---|---|---|---|
/// | `null` | miss | miss | miss | miss | miss | miss |
/// | `string` | the string | via [`coerce_text`] | via `coerce_text` | via `coerce_text` | via `coerce_text` | via `coerce_text` |
/// | `number` | canonical string | `i64` if integral, else miss | `f64` if finite, else miss | miss | miss | miss |
/// | `bool` | `"true"`/`"false"` | miss | miss | the bool | miss | miss |
/// | `array`/`object` | compact JSON text | miss | miss | miss | miss | compact JSON bytes |
///
/// `null` is folded to a miss (not `Value::Null`) so it flows through the
/// owning column's `OnError` policy exactly like any other extraction miss
/// — a schema author never sees a distinction between "pointer didn't
/// resolve" and "pointer resolved to `null`".
fn coerce_json(value: &serde_json::Value, ty: ColumnType) -> Result<Value, ()> {
    match value {
        serde_json::Value::Null => Err(()),
        serde_json::Value::String(text) => coerce_text(text, ty),
        serde_json::Value::Number(number) => coerce_json_number(number, ty),
        serde_json::Value::Bool(flag) => coerce_bool(*flag, ty),
        serde_json::Value::Array(_) | serde_json::Value::Object(_) => match ty {
            ColumnType::Text => serde_json::to_string(value).map(Value::Text).map_err(|_| ()),
            ColumnType::Blob => serde_json::to_string(value)
                .map(|text| Value::Blob(text.into_bytes()))
                .map_err(|_| ()),
            _ => Err(()),
        },
    }
}

/// `Integer` accepts the number only if it is exactly representable as
/// `i64` (no fractional part); `Real` accepts any finite `f64`; `Text` gets
/// the number's canonical string form (`serde_json::Number::to_string`, the
/// same text the wire payload carried); every other declared type has no
/// sensible interpretation of a bare JSON number.
fn coerce_json_number(number: &serde_json::Number, ty: ColumnType) -> Result<Value, ()> {
    match ty {
        ColumnType::Integer => number.as_i64().map(Value::Integer).ok_or(()),
        ColumnType::Real => number
            .as_f64()
            .filter(|parsed| parsed.is_finite())
            .map(Value::Real)
            .ok_or(()),
        ColumnType::Text => Ok(Value::Text(number.to_string())),
        _ => Err(()),
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

    #[test]
    fn json_null_is_always_a_miss() {
        assert!(coerce(Extracted::Json(serde_json::Value::Null), ColumnType::Text).is_err());
        assert!(coerce(Extracted::Json(serde_json::Value::Null), ColumnType::Integer).is_err());
    }

    #[test]
    fn json_string_reuses_text_coercion_rules() {
        assert_eq!(
            coerce(
                Extracted::Json(serde_json::Value::String("42".to_owned())),
                ColumnType::Integer
            ),
            Ok(Value::Integer(42))
        );
        assert_eq!(
            coerce(
                Extracted::Json(serde_json::Value::String("hi".to_owned())),
                ColumnType::Text
            ),
            Ok(Value::Text("hi".to_owned()))
        );
    }

    #[test]
    fn json_number_coerces_by_declared_type_without_stringify_round_trip() {
        let integral = serde_json::json!(42);
        assert_eq!(
            coerce(Extracted::Json(integral.clone()), ColumnType::Integer),
            Ok(Value::Integer(42))
        );
        assert_eq!(
            coerce(Extracted::Json(integral.clone()), ColumnType::Text),
            Ok(Value::Text("42".to_owned()))
        );
        assert!(coerce(Extracted::Json(integral), ColumnType::Boolean).is_err());

        let fractional = serde_json::json!(9.5);
        assert_eq!(
            coerce(Extracted::Json(fractional.clone()), ColumnType::Real),
            Ok(Value::Real(9.5))
        );
        // Not exactly representable as an integer -> miss.
        assert!(coerce(Extracted::Json(fractional), ColumnType::Integer).is_err());
    }

    #[test]
    fn json_bool_maps_to_boolean_and_text_only() {
        assert_eq!(
            coerce(Extracted::Json(serde_json::Value::Bool(true)), ColumnType::Boolean),
            Ok(Value::Boolean(true))
        );
        assert_eq!(
            coerce(Extracted::Json(serde_json::Value::Bool(false)), ColumnType::Text),
            Ok(Value::Text("false".to_owned()))
        );
        assert!(coerce(Extracted::Json(serde_json::Value::Bool(true)), ColumnType::Integer).is_err());
    }

    #[test]
    fn json_array_and_object_serialize_compactly_for_text_and_blob_only() {
        let array = serde_json::json!([1, 2, 3]);
        assert_eq!(
            coerce(Extracted::Json(array.clone()), ColumnType::Text),
            Ok(Value::Text("[1,2,3]".to_owned()))
        );
        assert_eq!(
            coerce(Extracted::Json(array.clone()), ColumnType::Blob),
            Ok(Value::Blob(b"[1,2,3]".to_vec()))
        );
        assert!(coerce(Extracted::Json(array), ColumnType::Integer).is_err());

        let object = serde_json::json!({"a": 1});
        assert_eq!(
            coerce(Extracted::Json(object), ColumnType::Text),
            Ok(Value::Text("{\"a\":1}".to_owned()))
        );
    }
}
