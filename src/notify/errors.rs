use cokret::blind_payload_sanitizer::{BlindPayloadError, BlindPayloadReasonCode};
use thiserror::Error;

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum PushNotifyPrivacyError {
    #[error("push notify payload is missing required field `{field}`")]
    MissingField { field: String },
    #[error("push notify payload field `{field}` has an invalid value")]
    InvalidFieldValue { field: String },
    #[error("push notify payload field `{field}` contains sensitive data")]
    SensitiveField { field: String },
    #[error("push notify payload field `{field}` has been removed from this contract")]
    RemovedField { field: String },
    #[error("push notify hint is sensitive")]
    SensitiveHint,
}

impl From<BlindPayloadError> for PushNotifyPrivacyError {
    fn from(err: BlindPayloadError) -> Self {
        match err.reason_code {
            BlindPayloadReasonCode::MissingRequiredField => Self::MissingField {
                field: err.field_path,
            },
            BlindPayloadReasonCode::InvalidFieldValue => Self::InvalidFieldValue {
                field: err.field_path,
            },
            BlindPayloadReasonCode::ForbiddenField | BlindPayloadReasonCode::SensitiveLiteral => {
                Self::SensitiveField {
                    field: err.field_path,
                }
            }
        }
    }
}
