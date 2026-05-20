use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Count {
    pub category: CountCategory,
    pub value: String,
    pub count: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CountCategory {
    Asset,
    Summary,
    CommonPort,
    AdminPort,
    Vulnerability,
}

impl std::fmt::Display for CountCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CountCategory::Asset => write!(f, "asset"),
            CountCategory::Summary => write!(f, "summary"),
            CountCategory::CommonPort => write!(f, "common_port"),
            CountCategory::AdminPort => write!(f, "admin_port"),
            CountCategory::Vulnerability => write!(f, "vulnerability"),
        }
    }
}
