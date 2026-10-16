use serde_json::Value;

/// Event/System/Provider 的 Name 属性（通道来源，用于按提供者分派）
pub fn provider_name(record: &Value) -> Option<&str> {
    record
        .get("Event")?
        .get("System")?
        .get("Provider")?
        .get("#attributes")?
        .get("Name")?
        .as_str()
}

/// Event/System/EventID：兼容纯数字与 {"#text": N} 两种形态
pub fn event_id(record: &Value) -> Option<i64> {
    let eid = record.get("Event")?.get("System")?.get("EventID")?;
    match eid {
        Value::Number(n) => n.as_i64(),
        Value::Object(o) => o.get("#text").and_then(|t| t.as_i64()),
        _ => None,
    }
}

/// Event/System/TimeCreated 的原始 SystemTime 字符串
pub fn event_time_raw(record: &Value) -> Option<&str> {
    record
        .get("Event")?
        .get("System")?
        .get("TimeCreated")?
        .get("#attributes")?
        .get("SystemTime")?
        .as_str()
}

/// EventData（其次 UserData）归一化为键值对，兼容三种形态：
/// 1) 命名字段平铺对象 {"ServiceName":"x"}
/// 2) 数组 [{"#attributes":{"Name":"param1"},"#text":"v"}]
/// 3) 单一 Binary 字段（经典事件）
/// 位置兼容真实记录（Event 内嵌）与顶层（测试便利）
pub fn event_data(record: &Value) -> Vec<(String, String)> {
    let ev_node = record.get("Event").unwrap_or(record);
    let ed = match ev_node
        .get("EventData")
        .or_else(|| ev_node.get("UserData"))
        .or_else(|| record.get("EventData"))
        .or_else(|| record.get("UserData"))
    {
        Some(v) => v.clone(),
        None => return vec![],
    };
    let mut out: Vec<(String, String)> = Vec::new();
    match ed {
        Value::Object(m) => push_named_map(&m, &mut out),
        Value::Array(arr) => {
            for item in arr {
                if let Value::Object(o) = item {
                    let name = o
                        .get("#attributes")
                        .and_then(|a| a.get("Name"))
                        .and_then(|n| n.as_str());
                    let text = o.get("#text").and_then(|t| t.as_str());
                    if let (Some(n), Some(t)) = (name, text) {
                        out.push((n.to_string(), t.to_string()));
                    } else {
                        push_named_map(&o, &mut out);
                    }
                }
            }
        }
        _ => {}
    }
    out
}

fn push_named_map(m: &serde_json::Map<String, Value>, out: &mut Vec<(String, String)>) {
    for (k, v) in m {
        match v {
            Value::String(s) => out.push((k.clone(), s.clone())),
            Value::Number(n) => out.push((k.clone(), n.to_string())),
            Value::Object(o) => {
                let name = o
                    .get("#attributes")
                    .and_then(|a| a.get("Name"))
                    .and_then(|n| n.as_str());
                let text = o.get("#text").and_then(|t| t.as_str());
                if let (Some(n), Some(t)) = (name, text) {
                    out.push((n.to_string(), t.to_string()));
                }
            }
            _ => {}
        }
    }
}

pub fn data_get<'a>(pairs: &'a [(String, String)], key: &str) -> Option<&'a str> {
    pairs
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn event_id_plain_number() {
        let v = json!({"Event":{"System":{"EventID":6005}}});
        assert_eq!(event_id(&v), Some(6005));
    }

    #[test]
    fn event_id_qualified_object() {
        let v = json!({"Event":{"System":{"EventID":{"#attributes":{"Qualifiers":16384},"#text":6005}}}});
        assert_eq!(event_id(&v), Some(6005));
    }

    #[test]
    fn event_data_named_flat_map() {
        let v = json!({"EventData":{"ServiceName":"SysUpdate","ImagePath":"C:\\x\\s.exe"}});
        let d = event_data(&v);
        assert_eq!(data_get(&d, "ServiceName"), Some("SysUpdate"));
        assert_eq!(data_get(&d, "ImagePath"), Some("C:\\x\\s.exe"));
    }

    #[test]
    fn event_data_array_of_name_text() {
        let v = json!({"EventData":[
            {"#attributes":{"Name":"param1"},"#text":"SvcName"},
            {"#attributes":{"Name":"param2"},"#text":"C:\\x\\s.exe"}
        ]});
        let d = event_data(&v);
        assert_eq!(data_get(&d, "param1"), Some("SvcName"));
        assert_eq!(data_get(&d, "param2"), Some("C:\\x\\s.exe"));
    }

    #[test]
    fn event_data_binary_only() {
        let v = json!({"EventData":{"Binary":"DC0709000000"}});
        let d = event_data(&v);
        assert_eq!(data_get(&d, "Binary"), Some("DC0709000000"));
    }

    #[test]
    fn event_data_missing_is_empty() {
        let v = json!({"Event":{"System":{"EventID":1}}});
        assert!(event_data(&v).is_empty());
    }

    #[test]
    fn event_time_extraction() {
        let v = json!({"Event":{"System":{"TimeCreated":{"#attributes":{"SystemTime":"2026-09-22T10:42:13.245Z"}}}}});
        assert_eq!(event_time_raw(&v).unwrap(), "2026-09-22T10:42:13.245Z");
    }
}
