pub fn debug_lengths() {
    let signature = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
    let public_key = "021234567890abcdef1234567890abcdef1234567890abcdef1234567890abcd";

    println!("Signature length: {}", signature.len());
    println!("Public key length: {}", public_key.len());

    // Test validation
    if signature.len() != 128 {
        println!(
            "Signature length error: expected 128, got {}",
            signature.len()
        );
    }
    if public_key.len() != 66 {
        println!(
            "Public key length error: expected 66, got {}",
            public_key.len()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_debug_lengths() {
        debug_lengths();
    }
}
