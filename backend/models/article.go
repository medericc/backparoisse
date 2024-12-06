package models

// Article représente un article de blog
type Article struct {
	ID          int    `json:"id"`
	Title       string `json:"title"`
	Content     string `json:"content"`
	ImageURL    string `json:"image_url"`
	PublishedAt string `json:"published_at"`
	Username      string    `json:"username"`
	CategoryNAME  string    `json:"category_name"`
	
}
