package db

import (
	"database/sql"
	"fmt"
	"time"
)

// CreateUser adds a new user to the database
func (d *DB) CreateUser(email, passwordHash, name, role string) (*User, error) {
	return d.CreateUserWithTenant(email, passwordHash, name, role, nil)
}

// CreateUserWithTenant adds a new user with an optional tenant association.
func (d *DB) CreateUserWithTenant(email, passwordHash, name, role string, tenantID *int64) (*User, error) {
	query := `
		INSERT INTO users (email, password, name, role, tenant_id, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`

	now := time.Now()

	result, err := d.Exec(query, email, passwordHash, name, role, tenantID, now, now)
	if err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("failed to get user ID: %w", err)
	}

	return &User{
		ID:        id,
		Email:     email,
		Password:  passwordHash,
		Name:      name,
		Role:      role,
		TenantID:  tenantID,
		CreatedAt: now,
		UpdatedAt: now,
	}, nil
}

// GetUserByEmail retrieves a user by their email address
func (d *DB) GetUserByEmail(email string) (*User, error) {
	query := `SELECT id, email, password, name, role, tenant_id, created_at, updated_at FROM users WHERE email = ?`

	var user User
	var tenantID sql.NullInt64
	err := d.QueryRow(query, email).Scan(
		&user.ID,
		&user.Email,
		&user.Password,
		&user.Name,
		&user.Role,
		&tenantID,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	if tenantID.Valid {
		user.TenantID = &tenantID.Int64
	}

	return &user, nil
}

// GetUserByID retrieves a user by their ID
func (d *DB) GetUserByID(id int64) (*User, error) {
	query := `SELECT id, email, password, name, role, tenant_id, created_at, updated_at FROM users WHERE id = ?`

	var user User
	var tenantID sql.NullInt64
	err := d.QueryRow(query, id).Scan(
		&user.ID,
		&user.Email,
		&user.Password,
		&user.Name,
		&user.Role,
		&tenantID,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	if tenantID.Valid {
		user.TenantID = &tenantID.Int64
	}

	return &user, nil
}

// UpdateUser updates an existing user's information
func (d *DB) UpdateUser(id int64, name, role string) error {
	query := `UPDATE users SET name = ?, role = ?, updated_at = ? WHERE id = ?`

	result, err := d.Exec(query, name, role, time.Now(), id)
	if err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("user with id %d not found", id)
	}

	return nil
}

// UpdateUserPassword changes a user's password hash
func (d *DB) UpdateUserPassword(id int64, newPasswordHash string) error {
	query := `UPDATE users SET password = ?, updated_at = ? WHERE id = ?`

	result, err := d.Exec(query, newPasswordHash, time.Now(), id)
	if err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("user with id %d not found", id)
	}

	return nil
}

// DeleteUser removes a user from the database
func (d *DB) DeleteUser(id int64) error {
	query := `DELETE FROM users WHERE id = ?`

	result, err := d.Exec(query, id)
	if err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("user with id %d not found", id)
	}

	return nil
}

// ListUsers returns all users (with pagination)
func (d *DB) ListUsers(limit, offset int) ([]*User, error) {
	query := `SELECT id, email, password, name, role, tenant_id, created_at, updated_at FROM users LIMIT ? OFFSET ?`

	rows, err := d.Query(query, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to list users: %w", err)
	}
	defer rows.Close()

	var users []*User
	for rows.Next() {
		var user User
		var tenantID sql.NullInt64
		err := rows.Scan(
			&user.ID,
			&user.Email,
			&user.Password,
			&user.Name,
			&user.Role,
			&tenantID,
			&user.CreatedAt,
			&user.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan user: %w", err)
		}
		if tenantID.Valid {
			user.TenantID = &tenantID.Int64
		}
		users = append(users, &user)
	}

	return users, nil
}
