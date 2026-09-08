package used

// Greeting is referenced from main.
func Greeting() string { return "hi" }

// Unused is exported but never referenced anywhere.
func Unused() string { return "bye" }
