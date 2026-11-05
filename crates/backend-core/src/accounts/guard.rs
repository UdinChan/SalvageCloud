use std::sync::Arc;

use crate::{Result, accounts::AccountContext};

/// Captures an account and its lifecycle generation across asynchronous work.
#[derive(Clone)]
pub struct AccountGuard {
    context: Arc<AccountContext>,
    generation: u64,
}

impl AccountGuard {
    pub fn capture(context: Arc<AccountContext>) -> Self {
        let generation = context.generation();
        Self {
            context,
            generation,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.context.generation() == self.generation {
            Ok(())
        } else {
            Err(crate::CoreError::Unauthorized)
        }
    }

    pub fn context(&self) -> &Arc<AccountContext> {
        &self.context
    }
}
