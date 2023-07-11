package goxes




type Authentication interface {
	GetUser(username string) (*User, error)
	
}