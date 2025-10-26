#[derive(serde::Serialize)]
pub struct EntryFunctionPayload {
    pub module_address: Vec<u8>,
    pub module_name: Vec<u8>,
    pub function_name: Vec<u8>,
    pub type_arguments: Vec<Vec<u8>>,
    pub arguments: Vec<Vec<u8>>,
}

#[derive(serde::Serialize)]
pub struct RawTransactionForSigning {
    pub sender: Vec<u8>,
    pub sequence_number: u64,
    pub payload: Vec<u8>,
    pub max_gas_amount: u64,
    pub gas_unit_price: u64,
    pub expiration_timestamp_secs: u64,
    pub chain_id: u8,
}

pub mod signature {
    use serde_json::Value;

    use crate::{EntryFunctionPayload, RawTransactionForSigning, move_type::parse_standard_type};

    /// serialize payload bcs model
    fn serialize_payload_bcs(payload: &Value) -> Result<Vec<u8>, String> {
        let payload_type = payload["type"]
            .as_str()
            .ok_or("Missing payload_type field")?;
        match payload_type {
            "entry_function_payload" => impl_serialize_payload_bcs(payload),
            _ => Err(format!("Not a payload type {:?}", payload_type)),
        }
    }

    /// serialize payload implement bcs model
    fn impl_serialize_payload_bcs(payload: &Value) -> Result<Vec<u8>, String> {
        let function = payload["function"]
            .as_str()
            .ok_or("Missing function field")?;
        let type_arguments = payload["type_arguments"]
            .as_array()
            .ok_or("Missing type_arguments field")?;
        let arguments = payload["arguments"]
            .as_array()
            .ok_or("Missing arguments field")?;
        // handle function address、module、function name
        let parts: Vec<&str> = function.split("::").collect();
        if parts.len() != 3 {
            return Err("Function format is incorrect, address::module::function".to_string());
        }
        let module_address = hex::decode(parts[0].trim_start_matches("0x"))
            .map_err(|e| format!("module address decode error: {:?}", e))?;
        let module_name = parts[1].as_bytes().to_vec();
        let function_name = parts[2].as_bytes().to_vec();
        // serialized type args
        let mut serialized_type_args = Vec::new();
        for type_arg in type_arguments {
            let type_str = type_arg.as_str().ok_or("type args is not string")?;
            // parse move type
            let move_type = parse_standard_type(type_str)
                .map_err(|e| format!("parse move type error: {:?}", e))
                .unwrap();
            serialized_type_args.push(move_type);
        }
        // serialized args
        let mut serialized_args = Vec::new();
        for arg in arguments {
            let arg_bytes = serialize_arg_bcs(arg)?;
            serialized_args.push(arg_bytes);
        }
        // create EntryFunctionPayload
        let entry_function = EntryFunctionPayload {
            module_address,
            module_name,
            function_name,
            type_arguments: serialized_type_args,
            arguments: serialized_args,
        };
        bcs::to_bytes(&entry_function).map_err(|e| format!("EntryFunction BCS 序列化失败: {}", e))
    }

    /// serialize argument bcs
    fn serialize_arg_bcs(arg: &Value) -> Result<Vec<u8>, String> {
        match arg {
            Value::String(s) => {
                if s.starts_with("0x") {
                    hex::decode(s.trim_start_matches("0x"))
                        .map_err(|e| format!("Address parameter decoding failed: {:?}", e))
                } else {
                    Ok(s.as_bytes().to_vec())
                }
            }
            Value::Number(n) => {
                if let Some(i) = n.as_u64() {
                    bcs::to_bytes(&i)
                        .map_err(|e| format!("Serialization of numeric parameters failed: {}", e))
                } else {
                    Err("Unsupported value type".to_string())
                }
            }
            _ => Err(format!("Unsupported parameter type: {:?}", arg)),
        }
    }

    /// serialize transaction and sign
    pub fn serialize_transaction_and_sign(raw_txn: &Value) -> Result<Vec<u8>, String> {
        let sender = raw_txn["sender"].as_str().ok_or("Missing sender field")?;
        let sequence_number = raw_txn["sequence_number"]
            .as_str()
            .ok_or("Missing sequence_number field")?;
        let max_gas_amount = raw_txn["max_gas_amount"]
            .as_str()
            .ok_or("Missing max_gas_amount field")?;
        let gas_unit_price = raw_txn["gas_unit_price"]
            .as_str()
            .ok_or("Missing gas_unit_price field")?;
        let expiration_timestamp_secs = raw_txn["expiration_timestamp_secs"]
            .as_str()
            .ok_or("Missing expiration_timestamp_secs field")?;
        let chain_id = raw_txn["chain_id"]
            .as_u64()
            .ok_or("Missing chain_id field")? as u8;
        // parse payload
        let payload = &raw_txn["payload"];
        let payload_bytes = serialize_payload_bcs(payload)?;
        // build RawTransactionForSigning
        let raw_txn_data = RawTransactionForSigning {
            sender: hex::decode(sender.trim_start_matches("0x"))
                .map_err(|e| format!("sender decode error: {:?}", e))?,
            sequence_number: sequence_number
                .parse::<u64>()
                .map_err(|e| format!("sequence_number parse error: {:?}", e))?,
            payload: payload_bytes,
            max_gas_amount: max_gas_amount
                .parse::<u64>()
                .map_err(|e| format!("max_gas_amount parse error: {:?}", e))?,
            gas_unit_price: gas_unit_price
                .parse::<u64>()
                .map_err(|e| format!("gas_unit_price parse error: {:?}", e))?,
            expiration_timestamp_secs: expiration_timestamp_secs
                .parse::<u64>()
                .map_err(|e| format!("expiration_timestamp_secs parse error: {:?}", e))?,
            chain_id,
        };
        Ok(bcs::to_bytes(&raw_txn_data).unwrap())
    }
}

/// address related tool module
pub mod address {

    /// bytes to address (0x)
    pub fn bytes_to_address(address_bytes: &[u8]) -> Result<String, String> {
        if address_bytes.len() != 32 {
            return Err(format!("The address byte array length must be 32"));
        }
        let hex_string = hex::encode(address_bytes);
        Ok(format!("0x{}", hex_string))
    }

    /// address to bytes
    pub fn address_to_bytes(address: &str) -> Result<[u8; 32], String> {
        let address_clean = address.trim_start_matches("0x");
        if address_clean.len() != 64 {
            return Err(format!("The address string must be 64 characters long"));
        }
        let bytes =
            hex::decode(address_clean).map_err(|e| format!("Address decoding failed: {:?}", e))?;
        let mut result = [0u8; 32];
        result.copy_from_slice(&bytes);
        Ok(result)
    }

    /// address string to vec
    pub fn address_to_vec(address: &str) -> Result<Vec<u8>, String> {
        let address_clean = address.trim_start_matches("0x");
        hex::decode(address_clean).map_err(|e| format!("Address decoding failed: {:}", e))
    }

    /// verify address format
    pub fn verify_address_format(address: &str) -> bool {
        let address_clean = address.trim_start_matches("0x");
        if address_clean.len() != 64 {
            return false;
        }
        hex::decode(address_clean).is_ok()
    }

    /// public key to auth key
    pub fn public_key_to_auth_key(public_key: &[u8]) -> Result<String, String> {
        use sha3::{Digest, Sha3_256};
        if public_key.len() != 32 {
            return Err(format!("The public key must be 32 bytes long"));
        }
        let mut hasher = Sha3_256::new();
        hasher.update(public_key);
        hasher.update(&[0u8]);
        let result = hasher.finalize();
        Ok(format!("0x{}", hex::encode(result)))
    }

    /// private key to address
    pub fn private_key_to_address(private_key: &[u8]) -> Result<String, String> {
        use ring::signature::{Ed25519KeyPair, KeyPair};
        if private_key.len() != 32 {
            return Err(format!("The public key must be 32 bytes long"));
        }
        let keypair = Ed25519KeyPair::from_seed_unchecked(private_key)
            .map_err(|e| format!("Key pair generation failed: {:?}", e))?;
        let public_key = keypair.public_key().as_ref();
        public_key_to_auth_key(public_key)
    }

    /// Standardized address format
    pub fn normalize_address(address: &str) -> String {
        if address.starts_with("0x") {
            address.to_lowercase()
        } else {
            format!("0x{}", address.to_lowercase())
        }
    }

    /// Verify address validity
    pub fn is_valid_address(address: &str) -> bool {
        if !address.starts_with("0x") {
            return false;
        }
        let hex_part = &address[2..];
        hex_part.len() == 64 && hex_part.chars().all(|c| c.is_ascii_hexdigit())
    }

    /// show short address
    pub fn show_short_address(address: &str) -> String {
        if address.len() <= 10 {
            address.to_string()
        } else {
            format!("{}...{}", &address[0..6], &address[address.len() - 4..])
        }
    }
}

pub mod move_type {
    use crate::address::{address_to_bytes, verify_address_format};
    use std::collections::HashMap;

    /// Parse type string into BCS serialization format
    pub fn parse_type_string(type_str: &str) -> Result<Vec<u8>, String> {
        let trimmed = type_str.trim();
        // basic types
        if let Some(basic_type) = parse_basic_type(trimmed) {
            return Ok(basic_type);
        }
        // generic types
        if let Some(generic_type) = parse_generic_type(trimmed) {
            return Ok(generic_type);
        }
        // Structure type
        if let Some(struct_type) = parse_struct_type(trimmed) {
            return Ok(struct_type);
        }
        Err(format!("Unresolved type: {:?}", type_str))
    }

    /// parsing basic types
    fn parse_basic_type(type_str: &str) -> Option<Vec<u8>> {
        let basic_types: HashMap<&str, Vec<u8>> = [
            ("bool", vec![0x00]),    // bool
            ("u8", vec![0x01]),      // u8
            ("u64", vec![0x02]),     // u64
            ("u128", vec![0x03]),    // u128
            ("address", vec![0x04]), // address
            ("signer", vec![0x05]),  // signer
            ("vector", vec![0x06]),  // vector
        ]
        .iter()
        .cloned()
        .collect();
        basic_types.get(type_str).cloned()
    }

    /// parse generic type
    fn parse_generic_type(type_str: &str) -> Option<Vec<u8>> {
        if type_str.starts_with("vector<") && type_str.ends_with('>') {
            let inner_type = &type_str[7..type_str.len() - 1];
            if let Ok(inner_bytes) = parse_type_string(inner_type) {
                let mut result = vec![0x06]; // vector tag
                result.extend_from_slice(&inner_bytes);
                return Some(result);
            }
        }
        None
    }

    /// parse struct type
    fn parse_struct_type(type_str: &str) -> Option<Vec<u8>> {
        if let Some((address, remainder)) = split_struct_parts(type_str) {
            let mut result = vec![0x07]; // struct tag
            if let Ok(address_bytes) = address_to_bytes(address) {
                result.extend_from_slice(&address_bytes);
            } else {
                return None;
            }
            // Parsing module and structure names
            if let Some((module_name, struct_name, type_params)) =
                parse_struct_components(remainder)
            {
                // Serialization module name
                let module_bytes = module_name.as_bytes();
                result.push(module_bytes.len() as u8);
                result.extend_from_slice(module_bytes);
                // Serialized structure name
                let struct_bytes = struct_name.as_bytes();
                result.push(struct_bytes.len() as u8);
                result.extend_from_slice(struct_bytes);
                // Serialization type parameters
                result.push(type_params.len() as u8);
                for type_param in type_params {
                    if let Ok(param_bytes) = parse_type_string(&type_param) {
                        result.extend_from_slice(&param_bytes);
                    } else {
                        return None;
                    }
                }
                return Some(result);
            }
        }
        None
    }

    /// Split the address and remainder of the structure type
    fn split_struct_parts(type_str: &str) -> Option<(&str, &str)> {
        if let Some(pos) = type_str.find("::") {
            let address = &type_str[..pos];
            let remainder = &type_str[pos + 2..];

            if verify_address_format(address) {
                return Some((address, remainder));
            }
        }
        None
    }

    /// Parsing structure components: module name, structure name, type parameters
    fn parse_struct_components(remainder: &str) -> Option<(String, String, Vec<String>)> {
        // Finding the boundaries between structure names and type parameters
        let angle_bracket_pos = remainder.find('<');
        let (name_part, type_params_part) = if let Some(pos) = angle_bracket_pos {
            (&remainder[..pos], &remainder[pos..])
        } else {
            (remainder, "")
        };
        let parts: Vec<&str> = name_part.split("::").collect();
        if parts.len() != 2 {
            return None;
        }
        let module_name = parts[0].to_string();
        let struct_name = parts[1].to_string();
        let type_params = if !type_params_part.is_empty() {
            parse_type_parameters(type_params_part).unwrap_or_default()
        } else {
            Vec::new()
        };
        Some((module_name, struct_name, type_params))
    }

    /// parse type parameters
    fn parse_type_parameters(type_params_str: &str) -> Result<Vec<String>, String> {
        if !type_params_str.starts_with('<') || !type_params_str.ends_with('>') {
            return Err(format!(
                "Type parameter format error: {:?}",
                type_params_str
            ));
        }
        let inner = &type_params_str[1..type_params_str.len() - 1];
        let params: Vec<String> = inner
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        Ok(params)
    }

    /// parse standard type
    pub fn parse_standard_type(type_str: &str) -> Result<Vec<u8>, String> {
        match type_str {
            "bool" => Ok(vec![0x00]),
            "u8" => Ok(vec![0x01]),
            "u64" => Ok(vec![0x02]),
            "u128" => Ok(vec![0x03]),
            "address" => Ok(vec![0x04]),
            "signer" => Ok(vec![0x05]),
            "vector<u8>" => Ok(vec![0x06, 0x01]),
            "vector<address>" => Ok(vec![0x06, 0x04]),
            "0x1::string::String" => parse_struct_type(type_str)
                .ok_or_else(|| format!("Unable to resolve standard type: {:?}", type_str)),
            "0x1::object::Object" => parse_struct_type(type_str)
                .ok_or_else(|| format!("Unable to resolve standard type: {:?}", type_str)),
            "0x1::coin::Coin" => parse_struct_type(type_str)
                .ok_or_else(|| format!("Unable to resolve standard type: {:?}", type_str)),
            _ => parse_type_string(type_str),
        }
    }

    /// batch parse type arguments
    pub fn batch_parse_type_arguments(type_args: &[String]) -> Result<Vec<Vec<u8>>, String> {
        let mut result = Vec::new();
        for type_arg in type_args {
            let parsed = parse_standard_type(type_arg)
                .map_err(|e| format!("parse type arguments '{:?}' error: {:?}", type_arg, e))?;
            result.push(parsed);
        }
        Ok(result)
    }
}

pub mod codec {
    use serde_json::Value;

    /// bcs encode
    pub fn bcs_encode<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, String> {
        bcs::to_bytes(value).map_err(|e| format!("BCS encoding failed: {}", e))
    }

    /// bcs decode
    pub fn bcs_decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, String> {
        bcs::from_bytes(bytes).map_err(|e| format!("BCS decoding failed: {}", e))
    }

    /// encode move arguments
    pub fn encode_move_arguments(args: &[Value]) -> Result<Vec<Vec<u8>>, String> {
        let mut encoded = Vec::new();
        for arg in args {
            if let Some(str_val) = arg.as_str() {
                encoded.push(str_val.as_bytes().to_vec());
            } else {
                return Err("Only string arguments are supported".to_string());
            }
        }
        Ok(encoded)
    }
}
