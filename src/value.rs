// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

use serde_json::{Map, Number, Value};

pub type JsonMap = Map<String, Value>;

pub fn as_map(value: &Value) -> Option<&JsonMap> {
    value.as_object()
}

pub fn as_map_owned(value: Value) -> Option<JsonMap> {
    match value {
        Value::Object(map) => Some(map),
        _ => None,
    }
}

pub fn as_str<'a>(value: &'a Value) -> Option<&'a str> {
    value.as_str()
}

pub fn sprint(value: &Value) -> String {
    match value {
        Value::Null => String::new(),
        Value::String(text) => text.clone(),
        Value::Bool(flag) => flag.to_string(),
        Value::Number(n) => n.to_string(),
        other => other.to_string(),
    }
}

pub fn map_str(map: &JsonMap, key: &str) -> String {
    map.get(key).map(sprint).unwrap_or_default()
}

pub fn is_exact_true(value: &Value) -> bool {
    matches!(value, Value::Bool(true))
}

pub fn as_f64(value: &Value) -> Option<f64> {
    match value {
        Value::Number(n) => n.as_f64().or_else(|| n.as_i64().map(|i| i as f64)).or_else(|| n.as_u64().map(|i| i as f64)),
        Value::Bool(_) => None,
        _ => None,
    }
}

pub fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(flag) => *flag,
        Value::String(text) => !text.is_empty(),
        Value::Number(n) => as_f64(&Value::Number(n.clone())).unwrap_or(0.0) != 0.0,
        Value::Array(_) | Value::Object(_) => true,
    }
}

pub fn as_string_list(value: &Value) -> Option<Vec<String>> {
    let list = value.as_array()?;
    let mut out = Vec::with_capacity(list.len());
    for item in list {
        out.push(item.as_str()?.to_string());
    }
    Some(out)
}

pub fn string_list(value: &Value) -> Vec<String> {
    as_string_list(value).unwrap_or_default()
}

pub fn contains_str(list: &[String], want: &str) -> bool {
    list.iter().any(|item| item == want)
}

pub fn clip(text: &str, n: usize) -> String {
    if text.len() <= n {
        text.to_string()
    } else {
        text[..n].to_string()
    }
}

pub fn json_compact(value: &Value) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "null".to_string())
}

pub fn number_i64(n: i64) -> Number {
    Number::from(n)
}

pub fn parse_json(text: &str) -> Result<Value, serde_json::Error> {
    serde_json::from_str(text)
}

pub fn obj() -> JsonMap {
    JsonMap::new()
}
