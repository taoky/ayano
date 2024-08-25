package parser

import (
	"log"
	"os"

	"github.com/taoky/goaccessfmt/pkg/goaccessfmt"
)

func init() {
	RegisterParser("goaccess", func() Parser {
		parser, err := GoAccessFormatParser{}.new()
		if err != nil {
			log.Fatalln("goaccess init failed (You might need to set GOACCESS_CONFIG env)\n", err)
		}
		return parser
	})
}

type GoAccessFormatParser struct {
	conf goaccessfmt.Config
}

func (p GoAccessFormatParser) new() (GoAccessFormatParser, error) {
	confFile := os.Getenv("GOACCESS_CONFIG")
	file, err := os.Open(confFile)
	if err != nil {
		return p, err
	}
	conf, err := goaccessfmt.ParseConfigReader(file)
	if err != nil {
		return p, err
	}
	p.conf = conf
	return p, nil
}

func (p GoAccessFormatParser) Parse(line []byte) (LogItem, error) {
	glogitem, err := goaccessfmt.ParseLine(p.conf, string(line))
	if err != nil {
		return LogItem{}, err
	}

	return LogItem{
		Size:   glogitem.RespSize,
		Client: glogitem.Host,
		Time:   glogitem.Dt,
		URL:    glogitem.Req,
		Server: glogitem.Server,
	}, nil
}
