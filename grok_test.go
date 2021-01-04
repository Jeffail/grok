package grok

import (
	"testing"

	"github.com/trivago/grok/patterns"
	"github.com/trivago/tgo/ttesting"
)

func TestNew(t *testing.T) {
	expect := ttesting.NewExpect(t)

	g, err := New(Config{NamedCapturesOnly: true})
	expect.NoError(err)
	expect.Greater(len(g.patterns), 0)

	g, err = New(Config{SkipDefaultPatterns: true})
	expect.NoError(err)
	expect.Equal(0, len(g.patterns))

	g, err = New(Config{Patterns: patterns.AWS})
	expect.NoError(err)

	g, err = New(Config{Patterns: patterns.Grok})
	expect.NoError(err)

	g, err = New(Config{Patterns: patterns.Firewalls})
	expect.NoError(err)
}

func TestParseWithDefaultCaptureMode(t *testing.T) {
	expect := ttesting.NewExpect(t)

	g, err := New(Config{NamedCapturesOnly: true})
	expect.NoError(err)

	captures, err := g.ParseString("%{COMMONAPACHELOG}", `127.0.0.1 - - [23/Apr/2014:22:58:32 +0200] "GET /index.php HTTP/1.1" 404 207`)
	expect.NoError(err)
	expect.MapEqual(captures, "timestamp", "23/Apr/2014:22:58:32 +0200")
	expect.MapNotSet(captures, "TIME")

	g, err = New(Config{})
	expect.NoError(err)

	captures, err = g.ParseString("%{COMMONAPACHELOG}", `127.0.0.1 - - [23/Apr/2014:22:58:32 +0200] "GET /index.php HTTP/1.1" 404 207`)
	expect.NoError(err)
	expect.MapEqual(captures, "timestamp", "23/Apr/2014:22:58:32 +0200")
	expect.MapEqual(captures, "TIME", "22:58:32")
}

func TestMultiParseWithDefaultCaptureMode(t *testing.T) {
	expect := ttesting.NewExpect(t)

	g, err := New(Config{NamedCapturesOnly: true})
	expect.NoError(err)

	captures, err := g.ParseStringToMultiMap("%{COMMONAPACHELOG} %{COMMONAPACHELOG}", `127.0.0.1 - - [23/Apr/2014:23:58:32 +0200] "GET /index.php HTTP/1.1" 404 207 127.0.0.1 - - [24/Apr/2014:22:58:32 +0200] "GET /index.php HTTP/1.1" 404 207`)
	expect.NoError(err)
	expect.MapNotSet(captures, "TIME")
	expect.Equal(2, len(captures["timestamp"]))

	g, err = New(Config{})
	expect.NoError(err)

	captures, err = g.ParseStringToMultiMap("%{COMMONAPACHELOG} %{COMMONAPACHELOG}", `127.0.0.1 - - [23/Apr/2014:23:58:32 +0200] "GET /index.php HTTP/1.1" 404 207 127.0.0.1 - - [24/Apr/2014:22:58:32 +0200] "GET /index.php HTTP/1.1" 404 207`)
	expect.NoError(err)

	expect.MapSet(captures, "TIME")
	expect.Equal(2, len(captures["TIME"]))
	expect.Equal(2, len(captures["timestamp"]))
}

func TestMatch(t *testing.T) {
	expect := ttesting.NewExpect(t)

	g, err := New(Config{})
	expect.NoError(err)

	result, err := g.MatchString("%{MONTH}", "June")
	expect.NoError(err)
	expect.True(result)

	comp, err := g.Compile("%{MONTH}")
	expect.NoError(err)
	expect.True(comp.MatchString("June"))
}

func TestDoesNotMatch(t *testing.T) {
	expect := ttesting.NewExpect(t)

	g, err := New(Config{})
	expect.NoError(err)

	result, err := g.MatchString("%{MONTH}", "13")
	expect.NoError(err)
	expect.False(result)

	comp, err := g.Compile("%{MONTH}")
	expect.NoError(err)
	expect.False(comp.MatchString("13"))
}

func TestErrorMatch(t *testing.T) {
	expect := ttesting.NewExpect(t)

	g, err := New(Config{})
	expect.NoError(err)

	_, err = g.MatchString("(", "13")
	expect.NotNil(err)
}

func TestShortName(t *testing.T) {
	expect := ttesting.NewExpect(t)

	g, err := New(Config{Patterns: map[string]string{"A": "a"}})
	expect.NoError(err)

	result, err := g.MatchString("%{A}", "a")
	expect.NoError(err)
	expect.True(result)
}

func TestDayCompile(t *testing.T) {
	expect := ttesting.NewExpect(t)

	g, err := New(Config{Patterns: map[string]string{
		"DAY": "(?:Mon(?:day)?|Tue(?:sday)?|Wed(?:nesday)?|Thu(?:rsday)?|Fri(?:day)?|Sat(?:urday)?|Sun(?:day)?)",
	}})
	expect.NoError(err)

	_, err = g.Compile("%{DAY}")
	expect.NoError(err)
}

func TestErrorCompile(t *testing.T) {
	expect := ttesting.NewExpect(t)

	g, err := New(Config{})
	expect.NoError(err)

	_, err = g.Compile("(")
	expect.NotNil(err)
}

func TestNamedCaptures(t *testing.T) {
	expect := ttesting.NewExpect(t)

	g, err := New(Config{})
	expect.NoError(err)

	captured, err := g.ParseString("%{DAY:jour}", "Tue May 15 11:21:42 [conn1047685] moveChunk deleted: 7157")
	expect.NoError(err)
	expect.MapEqual(captured, "jour", "Tue")
}

func TestNamedCapturesWithDots(t *testing.T) {
	expect := ttesting.NewExpect(t)

	g, err := New(Config{})
	expect.NoError(err)

	captured, err := g.ParseString("%{DAY:nested.foo.jour}", "Tue May 15 11:21:42 [conn1047685] moveChunk deleted: 7157")
	expect.NoError(err)
	expect.MapEqual(captured, "nested.foo.jour", "Tue")
}

func TestErrorCaptureUnknowPattern(t *testing.T) {
	expect := ttesting.NewExpect(t)

	g, err := New(Config{})
	expect.NoError(err)

	_, err = g.ParseString("%{UNKNOWPATTERN}", "")
	expect.NotNil(err)
}

func TestParse(t *testing.T) {
	expect := ttesting.NewExpect(t)

	g, err := New(Config{})
	expect.NoError(err)

	res, err := g.ParseString("%{DAY}", "Tue qds")
	expect.NoError(err)
	expect.MapEqual(res, "DAY", "Tue")
}

func TestErrorParseToMultiMap(t *testing.T) {
	expect := ttesting.NewExpect(t)

	g, err := New(Config{})
	expect.NoError(err)

	_, err = g.ParseStringToMultiMap("%{UNKNOWPATTERN}", "")
	expect.NotNil(err)
}

func TestParseToMultiMap(t *testing.T) {
	expect := ttesting.NewExpect(t)

	g, err := New(Config{})
	expect.NoError(err)

	res, err := g.ParseStringToMultiMap("%{COMMONAPACHELOG} %{COMMONAPACHELOG}", `127.0.0.1 - - [23/Apr/2014:23:58:32 +0200] "GET /index.php HTTP/1.1" 404 207 127.0.0.1 - - [24/Apr/2014:22:58:32 +0200] "GET /index.php HTTP/1.1" 404 207`)
	expect.NoError(err)
	expect.MapSet(res, "TIME")
	expect.Equal(2, len(res["TIME"]))
	expect.Equal("23:58:32", res["TIME"][0])
	expect.Equal("22:58:32", res["TIME"][1])
}

func TestParseToMultiMapOnlyNamedCaptures(t *testing.T) {
	expect := ttesting.NewExpect(t)

	g, err := New(Config{NamedCapturesOnly: true})
	expect.NoError(err)

	res, err := g.ParseStringToMultiMap("%{COMMONAPACHELOG} %{COMMONAPACHELOG}", `127.0.0.1 - - [23/Apr/2014:22:58:32 +0200] "GET /index.php HTTP/1.1" 404 207 127.0.0.1 - - [24/Apr/2014:22:58:32 +0200] "GET /index.php HTTP/1.1" 404 207`)
	expect.NoError(err)

	expect.MapSet(res, "timestamp")
	expect.Equal(2, len(res["timestamp"]))
	expect.Equal("23/Apr/2014:22:58:32 +0200", res["timestamp"][0])
	expect.Equal("24/Apr/2014:22:58:32 +0200", res["timestamp"][1])
}

func TestCaptureAll(t *testing.T) {
	expect := ttesting.NewExpect(t)

	g, err := New(Config{})
	expect.NoError(err)

	captures, err := g.ParseString("%{COMMONAPACHELOG}", `127.0.0.1 - - [23/Apr/2014:22:58:32 +0200] "GET /index.php HTTP/1.1" 404 207`)
	expect.NoError(err)
	expect.MapEqual(captures, "timestamp", "23/Apr/2014:22:58:32 +0200")
	expect.MapEqual(captures, "TIME", "22:58:32")

	captures, err = g.ParseString("%{TIMESTAMP_ISO8601}", `s d9fq4999s ../ sdf 2013-11-06 04:50:17,1599sd`)
	expect.NoError(err)
	expect.MapEqual(captures, "SECOND", "17,1599")

	captures, err = g.ParseString("%{HOSTPORT}", `google.com:8080`)
	expect.NoError(err)
	expect.MapEqual(captures, "HOSTNAME", "google.com")
	expect.MapEqual(captures, "POSINT", "8080")
}

func TestNamedCapture(t *testing.T) {
	expect := ttesting.NewExpect(t)

	g, err := New(Config{NamedCapturesOnly: true})
	expect.NoError(err)

	captures, err := g.ParseString("%{COMMONAPACHELOG}", `127.0.0.1 - - [23/Apr/2014:22:58:32 +0200] "GET /index.php HTTP/1.1" 404 207`)
	expect.NoError(err)
	expect.MapEqual(captures, "timestamp", "23/Apr/2014:22:58:32 +0200")
	expect.MapNotSet(captures, "TIME")

	captures, err = g.ParseString("%{TIMESTAMP_ISO8601}", `s d9fq4999s ../ sdf 2013-11-06 04:50:17,1599sd`)
	expect.NoError(err)
	expect.MapNotSet(captures, "SECOND")

	captures, err = g.ParseString("%{HOSTPORT}", `google.com:8080`)
	expect.NoError(err)
	expect.MapNotSet(captures, "HOSTNAME")
	expect.MapNotSet(captures, "POSINT")
}

func TestRemoveEmptyValues(t *testing.T) {
	expect := ttesting.NewExpect(t)

	g, err := New(Config{NamedCapturesOnly: true, RemoveEmptyValues: true})
	expect.NoError(err)

	captures, err := g.ParseString("%{COMMONAPACHELOG}", `127.0.0.1 - - [23/Apr/2014:22:58:32 +0200] "GET /index.php HTTP/1.1" 404 207`)
	expect.NoError(err)
	expect.MapNotSet(captures, "rawrequest")
}

func TestCapturesAndNamedCapture(t *testing.T) {
	expect := ttesting.NewExpect(t)

	g, err := New(Config{NamedCapturesOnly: true})
	expect.NoError(err)

	captures, err := g.ParseString("%{DAY:jour}", "Tue May 15 11:21:42 [conn1047685] moveChunk deleted: 7157")
	expect.NoError(err)
	expect.MapEqual(captures, "jour", "Tue")

	g, err = New(Config{})
	expect.NoError(err)

	captures, err = g.ParseString("%{DAY}", "Tue May 15 11:21:42 [conn1047685] moveChunk deleted: 7157")
	expect.NoError(err)
	expect.MapEqual(captures, "DAY", "Tue")

	captures, err = g.ParseString("%{COMMONAPACHELOG}", `127.0.0.1 - - [23/Apr/2014:22:58:32 +0200] "GET /index.php HTTP/1.1" 404 207`)
	expect.NoError(err)
	expect.MapEqual(captures, "clientip", "127.0.0.1")
	expect.MapEqual(captures, "verb", "GET")
	expect.MapEqual(captures, "timestamp", "23/Apr/2014:22:58:32 +0200")
	expect.MapEqual(captures, "bytes", "207")

	//PATH
	captures, err = g.ParseString("%{WINPATH}", `s dfqs c:\winfows\sdf.txt`)
	expect.NoError(err)
	expect.MapEqual(captures, "WINPATH", `c:\winfows\sdf.txt`)

	captures, err = g.ParseString("%{WINPATH}", `s dfqs \\sdf\winfows\sdf.txt`)
	expect.NoError(err)
	expect.MapEqual(captures, "WINPATH", `\\sdf\winfows\sdf.txt`)

	captures, err = g.ParseString("%{UNIXPATH}", `s dfqs /usr/lib/ sqfd`)
	expect.NoError(err)
	expect.MapEqual(captures, "UNIXPATH", `/usr/lib/`)

	captures, err = g.ParseString("%{UNIXPATH}", `s dfqs /usr/lib sqfd`)
	expect.NoError(err)
	expect.MapEqual(captures, "UNIXPATH", `/usr/lib`)

	captures, err = g.ParseString("%{UNIXPATH}", `s dfqs /usr/ sqfd`)
	expect.NoError(err)
	expect.MapEqual(captures, "UNIXPATH", `/usr/`)

	captures, err = g.ParseString("%{UNIXPATH}", `s dfqs /usr sqfd`)
	expect.NoError(err)
	expect.MapEqual(captures, "UNIXPATH", `/usr`)

	captures, err = g.ParseString("%{UNIXPATH}", `s dfqs / sqfd`)
	expect.NoError(err)
	expect.MapEqual(captures, "UNIXPATH", `/`)

	//YEAR
	captures, err = g.ParseString("%{YEAR}", `s d9fq4999s ../ sdf`)
	expect.NoError(err)
	expect.MapEqual(captures, "YEAR", `4999`)

	captures, err = g.ParseString("%{YEAR}", `s d79fq4999s ../ sdf`)
	expect.NoError(err)
	expect.MapEqual(captures, "YEAR", `79`)

	captures, err = g.ParseString("%{TIMESTAMP_ISO8601}", `s d9fq4999s ../ sdf 2013-11-06 04:50:17,1599sd`)
	expect.NoError(err)
	expect.MapEqual(captures, "TIMESTAMP_ISO8601", `2013-11-06 04:50:17,1599`)

	//MAC
	captures, err = g.ParseString("%{MAC}", `s d9fq4999s ../ sdf 2013- 01:02:03:04:ab:cf  11-06 04:50:17,1599sd`)
	expect.NoError(err)
	expect.MapEqual(captures, "MAC", `01:02:03:04:ab:cf`)

	captures, err = g.ParseString("%{MAC}", `s d9fq4999s ../ sdf 2013- 01-02-03-04-ab-cd  11-06 04:50:17,1599sd`)
	expect.NoError(err)
	expect.MapEqual(captures, "MAC", `01-02-03-04-ab-cd`)

	//QUOTEDSTRING
	captures, err = g.ParseString("%{QUOTEDSTRING}", `qsdklfjqsd fk"lkj"mkj`)
	expect.NoError(err)
	expect.MapEqual(captures, "QUOTEDSTRING", `"lkj"`)

	captures, err = g.ParseString("%{QUOTEDSTRING}", `qsdklfjqsd fk'lkj'mkj`)
	expect.NoError(err)
	expect.MapEqual(captures, "QUOTEDSTRING", `'lkj'`)

	captures, err = g.ParseString("%{QUOTEDSTRING}", `qsdklfjqsd "fk'lkj'm"kj`)
	expect.NoError(err)
	expect.MapEqual(captures, "QUOTEDSTRING", `"fk'lkj'm"`)

	captures, err = g.ParseString("%{QUOTEDSTRING}", `qsdklfjqsd 'fk"lkj"m'kj`)
	expect.NoError(err)
	expect.MapEqual(captures, "QUOTEDSTRING", `'fk"lkj"m'`)

	//BASE10NUM
	captures, err = g.ParseString("%{BASE10NUM}", `1`) // this is a nice one
	expect.NoError(err)
	expect.MapEqual(captures, "BASE10NUM", `1`)

	captures, err = g.ParseString("%{BASE10NUM}", `qsfd8080qsfd`)
	expect.NoError(err)
	expect.MapEqual(captures, "BASE10NUM", `8080`)
}

// Should be run with -race
func TestConcurentParse(t *testing.T) {
	expect := ttesting.NewExpect(t)

	g, err := New(Config{})
	expect.NoError(err)

	check := func(key, value, pattern, text string) {

		captures, err := g.ParseString(pattern, text)
		expect.NoError(err)
		expect.MapEqual(captures, key, value)
	}

	go check("QUOTEDSTRING", `"lkj"`, "%{QUOTEDSTRING}", `qsdklfjqsd fk"lkj"mkj`)
	go check("QUOTEDSTRING", `'lkj'`, "%{QUOTEDSTRING}", `qsdklfjqsd fk'lkj'mkj`)
	go check("QUOTEDSTRING", `'lkj'`, "%{QUOTEDSTRING}", `qsdklfjqsd fk'lkj'mkj`)
	go check("QUOTEDSTRING", `"fk'lkj'm"`, "%{QUOTEDSTRING}", `qsdklfjqsd "fk'lkj'm"kj`)
	go check("QUOTEDSTRING", `'fk"lkj"m'`, "%{QUOTEDSTRING}", `qsdklfjqsd 'fk"lkj"m'kj`)
}

func TestParseTypedWithDefaultCaptureMode(t *testing.T) {
	expect := ttesting.NewExpect(t)

	g, err := New(Config{NamedCapturesOnly: true})
	expect.NoError(err)

	captures, err := g.ParseStringTyped("%{IPV4:ip:string} %{NUMBER:status:int} %{NUMBER:duration:float}", `127.0.0.1 200 0.8`)
	expect.NoError(err)
	expect.MapEqual(captures, "ip", "127.0.0.1")
	expect.MapEqual(captures, "status", 200)
	expect.MapEqual(captures, "duration", 0.8)
}

func TestParseTypedWithNoTypeInfo(t *testing.T) {
	expect := ttesting.NewExpect(t)

	g, err := New(Config{NamedCapturesOnly: true})
	expect.NoError(err)

	captures, err := g.ParseStringTyped("%{COMMONAPACHELOG}", `127.0.0.1 - - [23/Apr/2014:22:58:32 +0200] "GET /index.php HTTP/1.1" 404 207`)
	expect.NoError(err)
	expect.MapEqual(captures, "timestamp", "23/Apr/2014:22:58:32 +0200")
	expect.MapNotSet(captures, "TIME")

	g, err = New(Config{})
	expect.NoError(err)

	captures, err = g.ParseStringTyped("%{COMMONAPACHELOG}", `127.0.0.1 - - [23/Apr/2014:22:58:32 +0200] "GET /index.php HTTP/1.1" 404 207`)
	expect.NoError(err)
	expect.MapEqual(captures, "timestamp", "23/Apr/2014:22:58:32 +0200")
	expect.MapEqual(captures, "TIME", "22:58:32")
}

func TestParseTypedWithIntegerTypeCoercion(t *testing.T) {
	expect := ttesting.NewExpect(t)

	g, err := New(Config{NamedCapturesOnly: true})
	expect.NoError(err)

	captures, err := g.ParseStringTyped("%{WORD:coerced:int}", `5.75`)
	expect.NoError(err)
	expect.MapEqual(captures, "coerced", 5)
}

func TestParseTypedWithUnknownType(t *testing.T) {
	expect := ttesting.NewExpect(t)

	g, err := New(Config{NamedCapturesOnly: true})
	expect.NoError(err)

	_, err = g.ParseStringTyped("%{WORD:word:unknown}", `hello`)
	expect.NotNil(err)
}

func TestParseTypedErrorCaptureUnknowPattern(t *testing.T) {
	expect := ttesting.NewExpect(t)

	g, err := New(Config{})
	expect.NoError(err)

	_, err = g.ParseStringTyped("%{UNKNOWPATTERN}", "")
	expect.NotNil(err)
}

func TestParseTypedWithTypedParents(t *testing.T) {
	expect := ttesting.NewExpect(t)

	g, err := New(Config{
		NamedCapturesOnly: true,
		Patterns: map[string]string{
			"TESTCOMMON": `%{IPORHOST:clientip} %{USER:ident} %{USER:auth} \[%{HTTPDATE:timestamp}\] "(?:%{WORD:verb} %{NOTSPACE:request}(?: HTTP/%{NUMBER:httpversion})?|%{DATA:rawrequest})" %{NUMBER:response} (?:%{NUMBER:bytes:int}|-)`,
		}})
	expect.NoError(err)

	captures, err := g.ParseStringTyped("%{TESTCOMMON}", `127.0.0.1 - - [23/Apr/2014:22:58:32 +0200] "GET /index.php HTTP/1.1" 404 207`)
	expect.NoError(err)
	expect.MapEqual(captures, "bytes", 207)
}

func TestParseTypedWithSemanticHomonyms(t *testing.T) {
	expect := ttesting.NewExpect(t)

	g, err := New(Config{
		NamedCapturesOnly:   true,
		SkipDefaultPatterns: true,
		Patterns: map[string]string{
			"BASE10NUM": `([+-]?(?:[0-9]+(?:\.[0-9]+)?)|\.[0-9]+)`,
			"NUMBER":    `(?:%{BASE10NUM})`,
			"MYNUM":     `%{NUMBER:bytes:int}`,
			"MYSTR":     `%{NUMBER:bytes:string}`,
		}})

	expect.NoError(err)

	captures, err := g.ParseStringTyped("%{MYNUM}", `207`)
	expect.NoError(err)
	expect.MapEqual(captures, "bytes", 207)

	captures, err = g.ParseStringTyped("%{MYSTR}", `207`)
	expect.NoError(err)
	expect.MapEqual(captures, "bytes", "207")
}

var resultNew *Grok

func BenchmarkNew(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	var g *Grok
	// run the check function b.N times
	for n := 0; n < b.N; n++ {
		g, _ = New(Config{NamedCapturesOnly: true})
	}
	resultNew = g
}

func BenchmarkCaptures(b *testing.B) {
	g, _ := New(Config{NamedCapturesOnly: true})
	b.ReportAllocs()
	b.ResetTimer()
	// run the check function b.N times
	c, _ := g.Compile(`%{IPORHOST:clientip} %{USER:ident} %{USER:auth} \[%{HTTPDATE:timestamp}\] "(?:%{WORD:verb} %{NOTSPACE:request}(?: HTTP/%{NUMBER:httpversion})?|%{DATA:rawrequest})" %{NUMBER:response} (?:%{NUMBER:bytes}|-)`)
	for n := 0; n < b.N; n++ {
		c.ParseString(`127.0.0.1 - - [23/Apr/2014:22:58:32 +0200] "GET /index.php HTTP/1.1" 404 207`)
	}
}

func BenchmarkParallelCaptures(b *testing.B) {
	g, _ := New(Config{NamedCapturesOnly: true})
	b.ReportAllocs()
	b.ResetTimer()

	c, _ := g.Compile(`%{IPORHOST:clientip} %{USER:ident} %{USER:auth} \[%{HTTPDATE:timestamp}\] "(?:%{WORD:verb} %{NOTSPACE:request}(?: HTTP/%{NUMBER:httpversion})?|%{DATA:rawrequest})" %{NUMBER:response} (?:%{NUMBER:bytes}|-)`)
	b.RunParallel(func(b *testing.PB) {
		for b.Next() {
			c.ParseString(`127.0.0.1 - - [23/Apr/2014:22:58:32 +0200] "GET /index.php HTTP/1.1" 404 207`)
		}
	})
}

func BenchmarkCapturesTypedFake(b *testing.B) {
	g, _ := New(Config{NamedCapturesOnly: true})
	b.ReportAllocs()
	b.ResetTimer()
	// run the check function b.N times
	c, _ := g.Compile(`%{IPORHOST:clientip} %{USER:ident} %{USER:auth} \[%{HTTPDATE:timestamp}\] "(?:%{WORD:verb} %{NOTSPACE:request}(?: HTTP/%{NUMBER:httpversion})?|%{DATA:rawrequest})" %{NUMBER:response} (?:%{NUMBER:bytes}|-)`)
	for n := 0; n < b.N; n++ {
		c.ParseString(`127.0.0.1 - - [23/Apr/2014:22:58:32 +0200] "GET /index.php HTTP/1.1" 404 207`)
	}
}

func BenchmarkCapturesTypedReal(b *testing.B) {
	g, _ := New(Config{NamedCapturesOnly: true})
	b.ReportAllocs()
	b.ResetTimer()
	// run the check function b.N times
	c, _ := g.Compile(`%{IPORHOST:clientip} %{USER:ident} %{USER:auth} \[%{HTTPDATE:timestamp}\] "(?:%{WORD:verb} %{NOTSPACE:request}(?: HTTP/%{NUMBER:httpversion:int})?|%{DATA:rawrequest})" %{NUMBER:response:int} (?:%{NUMBER:bytes:int}|-)`)
	for n := 0; n < b.N; n++ {
		c.ParseStringTyped(`127.0.0.1 - - [23/Apr/2014:22:58:32 +0200] "GET /index.php HTTP/1.1" 404 207`)
	}
}
