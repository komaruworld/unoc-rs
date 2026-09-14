pub fn descriptor_to_java_name(descriptor: &str) -> String {
    if descriptor.starts_with('L') && descriptor.ends_with(';') {
        descriptor[1..descriptor.len() - 1].replace('/', ".")
    } else {
        descriptor.to_string()
    }
}

pub fn package_shape(descriptor: &str) -> String {
    let java = descriptor_to_java_name(descriptor);
    match java.rsplit_once('.') {
        Some((package, _class)) => package
            .split('.')
            .map(|part| {
                if part.len() <= 2 && part.chars().all(|ch| ch.is_ascii_lowercase()) {
                    "*"
                } else {
                    part
                }
            })
            .collect::<Vec<_>>()
            .join("."),
        None => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::{descriptor_to_java_name, package_shape};

    #[test]
    fn converts_class_descriptor_to_java_name() {
        assert_eq!(descriptor_to_java_name("La/b/C;"), "a.b.C");
        assert_eq!(
            descriptor_to_java_name("Ljava/lang/String;"),
            "java.lang.String"
        );
    }

    #[test]
    fn builds_package_shape_for_obfuscated_packages() {
        assert_eq!(package_shape("La/b/C;"), "*.*");
        assert_eq!(package_shape("Lcom/example/Foo;"), "com.example");
    }
}
