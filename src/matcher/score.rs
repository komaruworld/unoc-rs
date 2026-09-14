use std::collections::BTreeMap;
use std::collections::BTreeSet;

pub fn jaccard(left: &BTreeSet<String>, right: &BTreeSet<String>) -> f32 {
    if left.is_empty() && right.is_empty() {
        return 1.0;
    }
    let intersection = left.intersection(right).count() as f32;
    let union = left.union(right).count() as f32;
    if union == 0.0 {
        0.0
    } else {
        intersection / union
    }
}

pub fn exact_option(left: &Option<String>, right: &Option<String>) -> f32 {
    match (left, right) {
        (Some(a), Some(b)) if a == b => 1.0,
        (None, None) => 1.0,
        _ => 0.0,
    }
}

pub fn equal_score<T: PartialEq>(left: &T, right: &T) -> f32 {
    if left == right {
        1.0
    } else {
        0.0
    }
}

pub fn bounded_ratio(left: u32, right: u32) -> f32 {
    if left == 0 && right == 0 {
        return 1.0;
    }
    let min = left.min(right) as f32;
    let max = left.max(right) as f32;
    if max == 0.0 {
        0.0
    } else {
        min / max
    }
}

pub fn signal_jaccard(left: &BTreeSet<String>, right: &BTreeSet<String>) -> f32 {
    if left.is_empty() && right.is_empty() {
        0.0
    } else {
        jaccard(left, right)
    }
}

pub fn histogram_cosine_u8(left: &BTreeMap<u8, u32>, right: &BTreeMap<u8, u32>) -> f32 {
    if left.is_empty() && right.is_empty() {
        return 0.0;
    }

    let dot: f32 = left
        .iter()
        .filter_map(|(key, left_count)| {
            right
                .get(key)
                .map(|right_count| (*left_count, *right_count))
        })
        .map(|(left_count, right_count)| left_count as f32 * right_count as f32)
        .sum();
    let left_norm = left
        .values()
        .map(|count| (*count as f32).powi(2))
        .sum::<f32>()
        .sqrt();
    let right_norm = right
        .values()
        .map(|count| (*count as f32).powi(2))
        .sum::<f32>()
        .sqrt();
    if left_norm == 0.0 || right_norm == 0.0 {
        0.0
    } else {
        dot / (left_norm * right_norm)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::jaccard;

    #[test]
    fn computes_jaccard_score() {
        let left = BTreeSet::from(["a".to_string(), "b".to_string()]);
        let right = BTreeSet::from(["b".to_string(), "c".to_string()]);
        assert!((jaccard(&left, &right) - 0.33333334).abs() < 0.0001);
    }
}
