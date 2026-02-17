package handlers

import (
	"fmt"
	"log"
	"net/http"
	"strconv"

	"github.com/ponder2000/guardian/internal/store"
)

// UsersData is the template data for the users list page.
type UsersData struct {
	PageData
	Users []store.User
}

// UserFormData is the template data for the user form.
type UserFormData struct {
	PageData
	EditUser *store.User
	IsEdit   bool
}

// Users handles user CRUD.
type Users struct {
	store     *store.Store
	templates TemplateRenderer
	logger    *log.Logger
}

// NewUsers creates a new Users handler.
func NewUsers(s *store.Store, t TemplateRenderer, l *log.Logger) *Users {
	return &Users{store: s, templates: t, logger: l}
}

// List renders the users table.
func (u *Users) List(w http.ResponseWriter, r *http.Request) {
	user := GetUser(r)
	users, err := u.store.ListUsers()
	if err != nil {
		u.logger.Printf("list users: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	data := UsersData{
		PageData: PageData{
			Title:     "Users",
			Active:    "users",
			User:      user,
			CSRFToken: GetCSRFToken(r),
			Flash:     r.URL.Query().Get("flash"),
		},
		Users: users,
	}
	u.templates.RenderPage(w, "users_list", "base", data)
}

// NewForm renders the create user form.
func (u *Users) NewForm(w http.ResponseWriter, r *http.Request) {
	user := GetUser(r)
	data := UserFormData{
		PageData: PageData{
			Title:     "New User",
			Active:    "users",
			User:      user,
			CSRFToken: GetCSRFToken(r),
		},
	}
	u.templates.RenderPage(w, "user_form", "base", data)
}

// Create handles user creation.
func (u *Users) Create(w http.ResponseWriter, r *http.Request) {
	user := GetUser(r)
	username := r.FormValue("username")
	email := r.FormValue("email")
	password := r.FormValue("password")
	role := r.FormValue("role")

	if username == "" || email == "" || password == "" {
		data := UserFormData{
			PageData: PageData{
				Title:     "New User",
				Active:    "users",
				User:      user,
				CSRFToken: GetCSRFToken(r),
				Error:     "All fields are required",
			},
		}
		w.WriteHeader(http.StatusBadRequest)
		u.templates.RenderPage(w, "user_form", "base", data)
		return
	}

	if role != "admin" && role != "viewer" {
		role = "viewer"
	}

	newUser, err := u.store.CreateUser(username, email, password, role)
	if err != nil {
		data := UserFormData{
			PageData: PageData{
				Title:     "New User",
				Active:    "users",
				User:      user,
				CSRFToken: GetCSRFToken(r),
				Error:     fmt.Sprintf("Failed to create user: %v", err),
			},
		}
		w.WriteHeader(http.StatusBadRequest)
		u.templates.RenderPage(w, "user_form", "base", data)
		return
	}

	u.store.LogAction(user.ID, user.Username, "user.create", "user", newUser.ID,
		fmt.Sprintf(`{"username":%q,"role":%q}`, username, role), ClientIP(r))

	http.Redirect(w, r, "/users?flash=User+created+successfully", http.StatusSeeOther)
}

// EditForm renders the edit user form.
func (u *Users) EditForm(w http.ResponseWriter, r *http.Request) {
	user := GetUser(r)
	id, _ := strconv.Atoi(r.PathValue("id"))

	editUser, err := u.store.GetUser(id)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	data := UserFormData{
		PageData: PageData{
			Title:     "Edit User",
			Active:    "users",
			User:      user,
			CSRFToken: GetCSRFToken(r),
		},
		EditUser: editUser,
		IsEdit:   true,
	}
	u.templates.RenderPage(w, "user_form", "base", data)
}

// Update handles user updates.
func (u *Users) Update(w http.ResponseWriter, r *http.Request) {
	user := GetUser(r)
	id, _ := strconv.Atoi(r.PathValue("id"))

	username := r.FormValue("username")
	email := r.FormValue("email")
	role := r.FormValue("role")
	isActive := r.FormValue("is_active") == "on"
	newPassword := r.FormValue("password")

	if role != "admin" && role != "viewer" {
		role = "viewer"
	}

	if err := u.store.UpdateUser(id, username, email, role, isActive); err != nil {
		u.logger.Printf("update user %d: %v", id, err)
		http.Error(w, "Failed to update user", http.StatusInternalServerError)
		return
	}

	if newPassword != "" {
		if err := u.store.UpdateUserPassword(id, newPassword); err != nil {
			u.logger.Printf("update password %d: %v", id, err)
		}
	}

	u.store.LogAction(user.ID, user.Username, "user.update", "user", id,
		fmt.Sprintf(`{"username":%q,"role":%q}`, username, role), ClientIP(r))

	http.Redirect(w, r, "/users?flash=User+updated+successfully", http.StatusSeeOther)
}

// Delete handles user deletion.
func (u *Users) Delete(w http.ResponseWriter, r *http.Request) {
	user := GetUser(r)
	id, _ := strconv.Atoi(r.PathValue("id"))

	// Prevent self-deletion.
	if id == user.ID {
		http.Error(w, "Cannot delete your own account", http.StatusBadRequest)
		return
	}

	if err := u.store.DeleteUser(id); err != nil {
		u.logger.Printf("delete user %d: %v", id, err)
		http.Error(w, "Failed to delete user", http.StatusInternalServerError)
		return
	}

	u.store.LogAction(user.ID, user.Username, "user.delete", "user", id, "", ClientIP(r))

	http.Redirect(w, r, "/users?flash=User+deleted", http.StatusSeeOther)
}
