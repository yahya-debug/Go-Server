package main

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Request struct {
	Method  string
	Path    string
	Prot    string
	Headers map[string]string
	body    []byte
}

// session id
var S_ID = map[string]string{}

func main() {
	listener, err := net.Listen("tcp", ":8099")
	if err != nil {
		log.Fatal("Error: ", err)
	}
	log.Println("Server is running on port: 8099")

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println("Accept error: ", err)
			continue
		}
		go handleConnection(conn)
	}
}
func handleConnection(conn net.Conn) {
	defer conn.Close()

	rdr /*Reader*/ := bufio.NewReader(conn)
	req, rreq, err := readRequest(rdr)
	if err != nil {
		log.Println("Error: ", err)
		return
	}
	addr := conn.RemoteAddr().String()
	// Client Info
	fmt.Println("Http from: " + addr)
	fmt.Println(rreq)
	writeRes(conn, req, addr)
}
func readRequest(rdr *bufio.Reader) (*Request, string, error) {
	var original_req strings.Builder
	line, err := rdr.ReadString('\n')
	if err != nil {
		return nil, "", err
	}
	original_req.WriteString(line)
	line = strings.TrimSpace(line)
	// split line to get parts of the request line
	splt := strings.Split(line, " ")
	if len(splt) < 3 {
		return nil, original_req.String(), fmt.Errorf("error occurd")
	}

	method, path, prot := splt[0], splt[1], splt[2]
	headers := make(map[string]string)

	for {
		hline, err := rdr.ReadString('\n')
		if err != nil {
			return nil, original_req.String(), err
		}
		original_req.WriteString(hline)
		hline = strings.TrimRight(hline, "\r\n")
		if hline == "" {
			break
		}
		colon := strings.Index(hline, ":")
		if colon == -1 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(hline[:colon])) // key is always before ':'
		val := strings.ToLower(strings.TrimSpace(hline[colon+1:]))
		headers[key] = val
	}
	var body []byte
	if cont_length, ok := headers["content-length"]; ok {
		var cl int
		fmt.Sscanf(cont_length, "%d", &cl)
		if cl > 0 {
			body = make([]byte, cl)
			_, err := io.ReadFull(rdr, body)
			if err != nil {
				return nil, original_req.String(), err
			}
			original_req.Write(body)
		}
	}
	req := &Request{
		Method:  method,
		Path:    path,
		Prot:    prot,
		Headers: headers,
		body:    body,
	}
	return req, original_req.String(), nil
}

func writeRes(conn net.Conn, req *Request, addr string) {
	path := req.Path
	if idx := strings.Index(path, "?"); idx != -1 {
		path = path[:idx]
	}
	if path == "" || path == "/" || path == "/index.html" || path == "/main_en.html" || path == "/en" {
		serveFile(conn, req.Prot, "public/main_en.html", "text/html", 200)
		return
	}
	if path == "/ar" {
		serveFile(conn, req.Prot, "public/main_ar.html", "text/html", 200)
		return
	}
	if path == "/chat" {
		sendRedirect(conn, req.Prot, "https://chatgpt.com/")
		return
	}
	if path == "/cf" {
		sendRedirect(conn, req.Prot, "https://www.cloudflare.com/")
		return
	}
	if path == "/rt" {
		sendRedirect(conn, req.Prot, "https://ritaj.birzeit.edu/")
		return
	}
	if path == "/register" && req.Method == "POST" {
		Register(conn, req)
		return
	}
	if path == "/login" && req.Method == "POST" {
		Login(conn, req)
		return
	}
	if path == "/logout" {
		LogOut(conn, req)
		return
	}
	if path == "/protected.html" {
		UN := getClient(req)
		if UN == "" {
			sendRedirect(conn, req.Prot, "/login.html")
			return
		}
		serveFile(conn, req.Prot, "public/protected.html", "text/html", 200)
		return
	}
	if path == "/user" {
		getUser(conn, req)
	}
	if strings.Contains(path, ".") {
		// check for extension
		ext := strings.ToLower(filepath.Ext(path))
		cont_type := ""
		switch ext {
		case ".html":
			cont_type = "text/html"
		case ".css":
			cont_type = "text/css"
		case ".png":
			cont_type = "image/png"
		case ".jpg", ".jpeg":
			cont_type = "image/jpeg"
		default:
			err_page404(conn, req.Prot, addr)
			return
		}
		filepath := filepath.Join("public", strings.TrimLeft(path, "/"))
		serveFile(conn, req.Prot, filepath, cont_type, 200)
		return
	}
	err_page404(conn, req.Prot, addr)
}
func serveFile(conn net.Conn, prot string, filepath string, cont_type string, status int) {
	data, err := os.ReadFile(filepath)
	if err != nil {
		err_page404(conn, prot, conn.RemoteAddr().String())
		return
	}
	stat := statusText(status)
	header := fmt.Sprintf("%s %d %s\r\n", prot, status, stat)
	header += fmt.Sprintf("Date: %s\r\n", time.Now().UTC().Format(time.RFC1123))
	header += "Server: YahyaGoServer/1.0\r\n"
	header += fmt.Sprintf("Content-Type: %s\r\n", cont_type)
	header += fmt.Sprintf("Content-Length: %d\r\n", len(data))
	header += "Connection: close\r\n\r\n"
	// Send the response
	conn.Write([]byte(header))
	conn.Write(data)
}
func statusText(c /*status code*/ int) string {
	switch c {
	case 200:
		return "Ok"
	case 307:
		return "Temporary Redirect"
	case 404:
		return "Not Found"
	case 401:
		return "Unauthorized"
	default:
		return "Ok"
	}
}
func sendRedirect(conn net.Conn, prot string, addr string) {
	body := "<html><body>Redirecting</body></html>"
	header := fmt.Sprintf("%s 307 Temporary Redirect\r\n", prot)
	header += fmt.Sprintf("Date: %s\r\n", time.Now().UTC().Format(time.RFC1123))
	header += "Server: YahyaGoServer/1.0\r\n"
	header += fmt.Sprintf("Location: %s\r\n", addr)
	header += "Content-Type: text/html\r\n"
	header += fmt.Sprintf("Content-Length: %d\r\n", len(body))
	header += "Connection: close\r\n\r\n"
	// Send the response
	conn.Write([]byte(header))
	conn.Write([]byte(body))
}

func err_page404(conn net.Conn, prot string, addr string) {
	team := "<b>Yahya Hasan (1242481)<br>Kinda Saadeh (1242018)<br>Maryan Aqel (1240761)</b>"
	body := fmt.Sprintf(`
	<html>
	<head>
		<title>Error 404</title>
	</head>
	<body>
		<h1 style="color: red;">The file is not found</h1>
		<p>%s</p>
		<p>IP & Port of Client: %s</p>
	</body>
	</html>`, team, addr)
	header := fmt.Sprintf("%s 404 Not Found\r\n", prot)
	header += fmt.Sprintf("Date: %s\r\n", time.Now().UTC().Format(time.RFC1123))
	header += "Server: YahyaGoServer/1.0\r\n"
	header += "Content-Type: text/html\r\n"
	header += fmt.Sprintf("Content-Length: %d\r\n", len(body))
	header += "Connection: close\r\n\r\n"
	// Send the response
	conn.Write([]byte(header))
	conn.Write([]byte(body))
}

func Register(conn net.Conn, req *Request) {
	params, err := url.ParseQuery(string(req.body))
	if err != nil {
		sendErr(conn, req.Prot, "Bad data")
		return
	}
	// user (name, password)
	un := params.Get("username")
	up := params.Get("password")
	if un == "" || up == "" {
		sendErr(conn, req.Prot, "User name and password required")
		return
	}
	// hash the password using SHA-256 Algorithm with the built-in functionallity in go
	hash := sha256.Sum256([]byte(up))
	str := hex.EncodeToString(hash[:])

	f, err := os.OpenFile("data.txt" /*Controls: */, os.O_APPEND /*append*/ |os.O_CREATE /*Create if not found*/ |os.O_WRONLY /*Write only for security*/, 0644)
	// 0644
	// unix style permission
	// 644 but in octal (so 0 is just for the base)
	// 6      		4      4
	// owner  		group  others
	// 110				100		100
	// rw-				r--		r--
	// read&write read	read
	if err != nil {
		sendErr(conn, req.Prot, "Server Error")
		return
	}
	defer f.Close()

	_, err = f.WriteString(fmt.Sprintf("%s:%s\n", un, str))
	if err != nil {
		sendErr(conn, req.Prot, "Server Error")
		return
	}

	// Successfully registered
	sendRedirect(conn, req.Prot, "/login.html")
}

func Login(conn net.Conn, req *Request) {
	params, err := url.ParseQuery(string(req.body))
	if err != nil {
		sendErr(conn, req.Prot, "Bad data")
		return
	}
	un := params.Get("username")
	up := params.Get("password")
	if un == "" || up == "" {
		sendErr(conn, req.Prot, "User name and password required")
		return
	}
	hash := sha256.Sum256([]byte(up))
	str := hex.EncodeToString(hash[:])
	DB, err := load()
	if err != nil {
		sendErr(conn, req.Prot, "Server Error")
		return
	}
	DB_hash, ok := DB[un]
	if !ok || DB_hash != str {
		body := "<html><body><h1>Invalid username or password</h1><a href=\"/login.html\"> Try Again</a></body></html>"
		header := fmt.Sprintf("%s 401 Unauthorized\r\n", req.Prot)
		header += fmt.Sprintf("Date: %s\r\n", time.Now().UTC().Format(time.RFC1123))
		header += "Server: YahyaGoServer/1.0\r\n"
		header += "Content-Type: text/html\r\n"
		header += fmt.Sprintf("Content-Length: %d\r\n", len(body))
		header += "Connection: close\r\n\r\n"
		// Send the response
		conn.Write([]byte(header))
		conn.Write([]byte(body))
		return
	}
	// generate session id
	gen := make([]byte, 16)
	rand.Read(gen)
	sessionID := hex.EncodeToString(gen)
	S_ID[sessionID] = un
	data, err := os.ReadFile("public/protected.html")
	if err != nil {
		sendErr(conn, req.Prot, "Server Error")
		return
	}

	header := fmt.Sprintf("%s 200 OK\r\n", req.Prot)
	header += fmt.Sprintf("Date: %s\r\n", time.Now().UTC().Format(time.RFC1123))
	header += "Server: YahyaGoServer/1.0\r\n"
	header += "Content-Type: text/html\r\n"
	header += fmt.Sprintf("Content-Length: %d\r\n", len(data))
	header += fmt.Sprintf("Set-Cookie: sessionid=%s; HttpOnly\r\n", sessionID)
	header += "Connection: close\r\n\r\n"
	// Send the response
	conn.Write([]byte(header))
	conn.Write(data)
}

func LogOut(conn net.Conn, req *Request) {
	sessionID := getIDCookie(req)
	if sessionID != "" {
		delete(S_ID, sessionID)
	}
	// redirect to the login page
	sendRedirect(conn, req.Prot, "/login.html")
}
func getUser(conn net.Conn, req *Request) {
	sessionID := getIDCookie(req)
	un := ""
	if sessionID != "" {
		if u, ok := S_ID[sessionID]; ok {
			un = u
		}
	}
	body := un
	header := fmt.Sprintf("%s 200 OK\r\n", req.Prot)
	header += fmt.Sprintf("Date: %s\r\n", time.Now().UTC().Format(time.RFC1123))
	header += "Server: YahyaGoServer/1.0\r\nContent-Type: text/plain\r\n"
	header += fmt.Sprintf("Content-Length: %d\r\n", len(body))
	header += "Connection: close\r\n\r\n"
	conn.Write([]byte(header))
	conn.Write([]byte(body))
}

func load() (map[string]string, error) {
	users := map[string]string{}
	f, err := os.Open("data.txt")
	if err != nil {
		if os.IsNotExist(err) {
			return users, nil
		}
		return nil, err
	}
	defer f.Close()
	// file scanner
	sc := bufio.NewScanner(f)

	for sc.Scan() {
		line := sc.Text()
		lista := strings.SplitN(line, ":", 2)
		if len(lista) != 2 {
			continue
		}
		users[lista[0]] = lista[1]
	}
	return users, sc.Err()
}

func getIDCookie(req *Request) string {
	cookieH, ok := req.Headers["cookie"]
	if !ok {
		return "" // no cookies so no session ids found, this empty string will be treated as an error as int he code above
	}
	lista := strings.Split(cookieH, ";")

	for _, i := range lista {
		i = strings.TrimSpace(i)
		if strings.HasPrefix(i, "sessionid=") {
			return strings.TrimPrefix(i, "sessionid=")
		}
	}
	return "" // this empty string will be treated as an error as int he code above
}

func getClient(req *Request) string {
	sessionID := getIDCookie(req)
	if sessionID == "" {
		return ""
	}
	return S_ID[sessionID]
}
func sendErr(conn net.Conn, prot string, msg string) {
	body := "<html><body><h1>Error</h1><p>" + msg + "</p></body></html>"
	header := fmt.Sprintf("%s %d %s\r\n", prot, 200, statusText(200))
	header += fmt.Sprintf("Date: %s\r\n", time.Now().UTC().Format(time.RFC1123))
	header += "Server: YahyaGoServer/1.0\r\n"
	header += "Content-Type: text/html\r\n"
	header += fmt.Sprintf("Content-Length: %d\r\n", len(body))
	header += "Connection: close\r\n\r\n"
	conn.Write([]byte(header))
	conn.Write([]byte(body))
}
