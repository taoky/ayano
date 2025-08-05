package grep

import (
	"errors"
	"fmt"
	"io"
	"log"

	"github.com/spf13/pflag"
	"github.com/taoky/ayano/pkg/fileiter"
	"github.com/taoky/ayano/pkg/parser"
	"github.com/taoky/ayano/pkg/util"
)

type Grepper struct {
	f   *Filter
	p   parser.Parser
	out io.Writer
}

type GrepperConfig struct {
	f      *Filter
	Parser string
}

func DefaultConfig() GrepperConfig {
	return GrepperConfig{
		f:      &Filter{},
		Parser: "nginx-json",
	}
}

func (c *GrepperConfig) InstallFlags(flags *pflag.FlagSet) {
	c.f.InstallFlags(flags)

	flags.StringVarP(&c.Parser, "parser", "p", c.Parser, "Log parser (see \"ayano list parsers\")")
}

func New(c GrepperConfig, w io.Writer) (*Grepper, error) {
	p, err := parser.GetParser(c.Parser)
	if err != nil {
		return nil, err
	}
	g := &Grepper{
		f:   c.f,
		p:   p,
		out: w,
	}
	return g, nil
}

func (g *Grepper) IsEmpty() bool {
	return g.f.IsEmpty()
}

func (g *Grepper) RunLoop(iter fileiter.Iterator) error {
	for {
		line, err := iter.Next()
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		if line == nil || errors.Is(err, io.EOF) {
			break
		}
		if err := g.handleLine(line); err != nil {
			log.Printf("grep error: %v", err)
		}
	}
	return nil
}

func (g *Grepper) GrepFile(filename string) error {
	f, err := util.OpenFile(filename)
	if err != nil {
		return err
	}
	defer f.Close()
	return g.RunLoop(fileiter.NewWithScanner(f))
}

func (g *Grepper) handleLine(line []byte) error {
	item, err := g.p.Parse(line)
	if err != nil {
		return fmt.Errorf("parse error: %w\ngot line: %q", err, line)
	}
	if err := g.f.Match(item); err == nil {
		g.out.Write(line)
		if len(line) > 0 && line[len(line)-1] != '\n' {
			g.out.Write([]byte{'\n'})
		}
	}
	return nil
}
