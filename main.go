package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"golang.org/x/term"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var (
	username    = flag.String("u", "", "set `username`")
	passwordStr = flag.String("p", "", "set `password`")
)

func getJsonp(req_url string, params url.Values) (map[string]any, error) {
	req, err := url.Parse(req_url)
	if err != nil {
		return map[string]any{}, err
	}
	t := strconv.FormatInt(time.Now().UnixMicro(), 10)
	params.Set("_", t)
	params.Set("callback", "jQuery112406951885120277062_"+t)
	req.RawQuery = params.Encode()
	resp, err := http.Get(req.String())
	if err != nil {
		return map[string]any{}, err
	}
	jsonp, err := io.ReadAll(resp.Body)
	if err != nil {
		return map[string]any{}, err
	}
	jsonString := jsonp[bytes.IndexByte(jsonp, '(')+1 : bytes.LastIndexByte(jsonp, ')')]
	var data map[string]any
	if err := json.Unmarshal(jsonString, &data); err != nil {
		return map[string]any{}, err
	}
	return data, nil
}

func ordat(msg string, idx int) int64 {
	if len(msg) > idx {
		return int64(msg[idx])
	}
	return 0
}

func senCode(msg string, key bool) []int64 {
	l := len(msg)
	pwd := make([]int64, 0)
	for i := 0; i < l; i += 4 {
		pwd = append(pwd, ordat(msg, i)|ordat(msg, i+1)<<8|ordat(msg, i+2)<<16|ordat(msg, i+3)<<24)
	}
	if key {
		pwd = append(pwd, int64(l))
	}
	return pwd
}

func lenCode(msg []int64) string {
	l := len(msg)
	res := make([]string, l)
	for i := 0; i < l; i++ {
		res[i] = string([]byte{byte(msg[i] & 0xff), byte(msg[i] >> 8 & 0xff), byte(msg[i] >> 16 & 0xff), byte(msg[i] >> 24 & 0xff)})
	}
	return strings.Join(res, "")
}

func getXencode(msg, key string) string {
	if msg == "" {
		return ""
	}
	pwd := senCode(msg, true)
	pwdk := senCode(key, false)
	if len(pwdk) < 4 {
		for i := 0; i < 4-len(pwdk); i++ {
			pwdk = append(pwdk, 0)
		}
	}
	n := int64(len(pwd) - 1)
	z := pwd[n]
	y := pwd[0]
	c := int64(0x86014019 | 0x183639A0)
	m := int64(0)
	e := int64(0)
	p := int64(0)
	q := int64(math.Floor(6 + 52/(float64(n)+1)))
	d := int64(0)
	for i := q; i > 0; i-- {
		d = (d + c) & (0x8CE0D9BF | 0x731F2640)
		e = d >> 2 & 3
		p = 0
		for p < n {
			y = pwd[p+1]
			m = z>>5 ^ y<<2
			m = m + ((y>>3 ^ z<<4) ^ (d ^ y))
			m = m + (pwdk[(p&3)^e] ^ z)
			pwd[p] = (pwd[p] + m) & (0xEFB8D130 | 0x10472ECF)
			z = pwd[p]
			p = p + 1
		}
		y = pwd[0]
		m = z>>5 ^ y<<2
		m = m + ((y>>3 ^ z<<4) ^ (d ^ y))
		m = m + (pwdk[(p&3)^e] ^ z)
		pwd[n] = (pwd[n] + m) & (0xBB390742 | 0x44C6F8BD)
		z = pwd[n]
	}
	return lenCode(pwd)
}

const padchar = '='
const alpha = "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA"

func getBase64(s string) string {
	x := make([]byte, 0)
	imax := len(s) - len(s)%3
	if len(s) == 0 {
		return s
	}

	for i := 0; i < imax; i += 3 {
		b10 := (int(s[i]) << 16) | (int(s[i+1]) << 8) | int(s[i+2])
		x = append(x, alpha[(b10>>18)], alpha[((b10>>12)&63)], alpha[((b10>>6)&63)], alpha[(b10&63)])
	}

	i := imax
	if len(s)-imax == 1 {
		b10 := int(s[i]) << 16
		x = append(x, alpha[(b10>>18)], alpha[((b10>>12)&63)], padchar, padchar)
	} else if len(s)-imax == 2 {
		b10 := (int(s[i]) << 16) | (int(s[i+1]) << 8)
		x = append(x, alpha[(b10>>18)], alpha[((b10>>12)&63)], alpha[((b10>>6)&63)], padchar)
	}
	return string(x)
}

func login() {
	fmt.Println("BUAA网关登录")
	if username == "" {
		fmt.Print("用户名：")
		fmt.Scanln(&username)
	}
	var password []byte
	if passwordStr == "" {
		fmt.Print("密码：")
		password, _ = term.ReadPassword(int(syscall.Stdin))
		fmt.Println("")
	} else {
		password = []byte(passwordStr)
	}

	params := url.Values{
		"username": {username},
		"ip":       {"0.0.0.0"},
	}
	resp, err := getJsonp("https://gw.buaa.edu.cn/cgi-bin/get_challenge", params)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	ip, token := resp["client_ip"].(string), resp["challenge"].(string)

	h := hmac.New(md5.New, []byte(token))
	h.Write(password)
	encryptedPassword := hex.EncodeToString(h.Sum(nil))

	info := map[string]string{
		"username": username,
		"password": string(password),
		"ip":       ip,
		"acid":     "1",
		"enc_ver":  "srun_bx1",
	}
	jsonInfo, _ := json.Marshal(info)
	encryptedInfo := "{SRBX1}" + getBase64(getXencode(string(jsonInfo), token))

	chksumSha1 := sha1.Sum([]byte(token + username + token + encryptedPassword + token + "1" + token + ip + token + "200" + token + "1" + token + encryptedInfo))
	chksum := hex.EncodeToString(chksumSha1[:])

	params = url.Values{
		"action":   {"login"},
		"username": {username},
		"password": {"{MD5}" + encryptedPassword},
		"ac_id":    {"1"},
		"ip":       {ip},
		"info":     {encryptedInfo},
		"n":        {"200"},
		"type":     {"1"},
		"chksum":   {chksum},
	}
	resp, err = getJsonp("https://gw.buaa.edu.cn/cgi-bin/srun_portal", params)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	ecode := resp["ecode"]
	switch ecode.(type) {
	case float64:
		fmt.Println("已登录")
		fmt.Println(resp["suc_msg"].(string))
	case string:
		fmt.Println("登录失败")
		fmt.Println(resp["error_msg"].(string))
	}
}

func main() {
	flag.Parse()
	login()
}
