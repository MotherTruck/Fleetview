//! Mirrors server/app/manage_users.py: local console recovery for a locked-out
//! admin account. Invoked as a CLI subcommand on this same binary (the Rust
//! runtime image has no Python and no `python -m app.manage_users`):
//!
//!   docker compose exec server ./fleetview-server manage-users USERNAME
use sqlx::{PgPool, Row};
use std::io::Write;

pub async fn run(pool: &PgPool, username: &str) -> anyhow::Result<()> {
    let username = username.to_lowercase();
    let mut tx = pool.begin().await?;

    // Lock against concurrent admin edits the same way the rest of this
    // server does (SELECT ... FOR UPDATE on the auth_control singleton row).
    sqlx::query("SELECT id FROM auth_control WHERE id = 1 FOR UPDATE").fetch_optional(&mut *tx).await?;

    let user = sqlx::query("SELECT id, role FROM users WHERE username = $1 FOR UPDATE")
        .bind(&username)
        .fetch_optional(&mut *tx)
        .await?;
    let Some(user) = user else {
        anyhow::bail!("An existing administrator username is required.");
    };
    let role: String = user.get("role");
    if role != "admin" {
        anyhow::bail!("An existing administrator username is required.");
    }
    let user_id: String = user.get("id");

    print!("New password (12-128 characters): ");
    std::io::stdout().flush()?;
    let password = rpassword::read_password()?;
    if !(12..=128).contains(&password.chars().count()) {
        anyhow::bail!("Password must contain 12-128 characters.");
    }
    print!("Confirm new password: ");
    std::io::stdout().flush()?;
    let confirm = rpassword::read_password()?;
    if password != confirm {
        anyhow::bail!("Passwords do not match.");
    }

    let hash = crate::security::password_hash(&password);
    sqlx::query("UPDATE users SET password_hash = $1, active = true, must_change_password = false WHERE id = $2")
        .bind(&hash)
        .bind(&user_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM user_sessions WHERE user_id = $1").bind(&user_id).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO account_audit (actor, action, target, details, created_at) VALUES ('local-console', 'admin_recovered', $1, '', now())")
        .bind(&username)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;

    println!("Administrator password reset; existing sessions revoked.");
    Ok(())
}
