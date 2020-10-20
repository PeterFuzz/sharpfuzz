package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"
)

const (
	CoverSize              = 64 << 10
	MaxInputSize           = 1 << 24
	SonarRegionSize        = 1 << 20
	ReturnResultSize       = 1 << 25
	ReturnResultValuesSize = 24
)

type Mapping struct {
	comm *os.File
	f    *os.File
	size int
	mem  []byte

	mapName string
	mapping syscall.Handle
	addr    uintptr
}

var utf16Names = make([][200]uint16, 4)

var writebuf [10]byte

func main() {
	flagExePath := flag.String("exepath", "", "path for exe on local filesystem")
	flag.Parse()

	var mappings = make([]Mapping, 4)
	mappings[0].size = MaxInputSize
	mappings[1].size = ReturnResultSize
	mappings[2].size = CoverSize
	mappings[3].size = SonarRegionSize

	for i := 0; i < len(mappings); i++ {
		var err error
		var mapping = &mappings[i]

		mapping.comm, err = ioutil.TempFile("", "base-fuzz-comm")
		if err != nil {
			log.Fatalf("failed to create comm file: %v", err)
		}
		mapping.comm.Truncate(int64(mapping.size))
		mapping.comm.Close()

		createMapping(i, mapping)
	}

	var inputRegion = mappings[0].mem
	var resultRegion = mappings[1].mem
	var sensorRegion = mappings[2].mem
	var sonarRegion = mappings[3].mem
	var buffer = make([]byte, SonarRegionSize)

	var testee = newTestee(*flagExePath, mappings, sensorRegion, inputRegion, resultRegion, sonarRegion, 0, buffer)

	res, ns, cover, sonar, extractData, crashed, hanged, retry := testee.sendTest()

	log.Println(res, ns, cover, sonar, extractData, crashed, hanged, retry)

}

func mapNameString(i int) string {
	var result = make([]string, 20)
	result = append(result, []string{"comm", strconv.Itoa(i), "_"}...)
	for j := 0; j < 10; j++ {
		result = append(result, strconv.Itoa(rand.Intn(10)))
	}
	return strings.Join(result, "")
}

func createMapping(i int, mapping *Mapping) {
	var err error
	mapping.f, err = os.OpenFile(mapping.comm.Name(), os.O_RDWR, 0)
	if err != nil {
		log.Fatalf("failed to open comm file: %v", err)
	}
	defer mapping.f.Close()

	// create utf16 map name string, zero terminated
	mapping.mapName = mapNameString(i)
	var nameRunes = []rune(mapping.mapName)
	var utf16Slice = utf16.Encode(nameRunes)
	for j, r := range utf16Slice {
		utf16Names[i][j] = r
	}
	utf16Names[i][len(utf16Slice)] = 0x00

	var mapName *uint16 = &utf16Names[i][0]
	mapping.mapping, err = syscall.CreateFileMapping(syscall.InvalidHandle, nil, syscall.PAGE_READWRITE, 0, uint32(mapping.size), mapName)
	if err != nil {
		log.Fatalf("failed to create file mapping: %v", err)
	}
	const FILE_MAP_ALL_ACCESS = 0xF001F
	mapping.addr, err = syscall.MapViewOfFile(mapping.mapping, FILE_MAP_ALL_ACCESS, 0, 0, uintptr(mapping.size))
	if err != nil {
		log.Fatalf("failed to mmap comm file: %v", err)
	}
	hdr := reflect.SliceHeader{mapping.addr, mapping.size, mapping.size}
	mapping.mem = *(*[]byte)(unsafe.Pointer(&hdr))
	mapping.mem[0] = 7 // test access
}

func setupCommMapping(cmd *exec.Cmd, rOut, wIn *os.File, comm []Mapping) { //TODO this is broken on Windows
	syscall.SetHandleInformation(syscall.Handle(wIn.Fd()), syscall.HANDLE_FLAG_INHERIT, 1)
	syscall.SetHandleInformation(syscall.Handle(rOut.Fd()), syscall.HANDLE_FLAG_INHERIT, 1)
	for _, m := range comm {
		syscall.SetHandleInformation(syscall.Handle(m.mapping), syscall.HANDLE_FLAG_INHERIT, 1)
	}

	log.Printf("%v %v %v %v %v %v %s %s %s %s\n", rOut.Fd(), wIn.Fd(), comm[0].mapping, comm[1].mapping, comm[2].mapping, comm[3].mapping,
		comm[0].mapName, comm[1].mapName, comm[2].mapName, comm[3].mapName) //TODO

	cmd.Env = append(cmd.Env, fmt.Sprintf("GO_FUZZ_IN_FD=%v", rOut.Fd()))
	cmd.Env = append(cmd.Env, fmt.Sprintf("GO_FUZZ_OUT_FD=%v", wIn.Fd()))
	cmd.Env = append(cmd.Env, fmt.Sprintf("GO_FUZZ_COMM_FD_0=%v", comm[0].mapping))
	cmd.Env = append(cmd.Env, fmt.Sprintf("GO_FUZZ_COMM_FD_1=%v", comm[1].mapping))
	cmd.Env = append(cmd.Env, fmt.Sprintf("GO_FUZZ_COMM_FD_2=%v", comm[2].mapping))
	cmd.Env = append(cmd.Env, fmt.Sprintf("GO_FUZZ_COMM_FD_3=%v", comm[3].mapping))

	cmd.Args = append(cmd.Args, fmt.Sprintf("%v", rOut.Fd()))
	cmd.Args = append(cmd.Args, fmt.Sprintf("%v", wIn.Fd()))
	cmd.Args = append(cmd.Args, fmt.Sprintf("%v", comm[0].mapping))
	cmd.Args = append(cmd.Args, fmt.Sprintf("%v", comm[1].mapping))
	cmd.Args = append(cmd.Args, fmt.Sprintf("%v", comm[2].mapping))
	cmd.Args = append(cmd.Args, fmt.Sprintf("%v", comm[3].mapping))
	cmd.Args = append(cmd.Args, comm[0].mapName)
	cmd.Args = append(cmd.Args, comm[1].mapName)
	cmd.Args = append(cmd.Args, comm[2].mapName)
	cmd.Args = append(cmd.Args, comm[3].mapName)

}

type Reply struct {
	Res   uint64
	Ns    uint64
	Sonar uint64
}

type FuzzPipe interface {
	ReadIndexAndLength() (uint16, uint64)
	WriteReply(*Reply)
	ReadBuffer([]byte) error
	ReadAllInto(b []byte) (int, error)
	WriteBuffer([]byte) error
	Close()
}

type StandardFuzzPipe struct {
	readPipe  *os.File
	writePipe *os.File
}

func NewFuzzPipe(readPipe, writePipe *os.File) FuzzPipe {
	result := &StandardFuzzPipe{
		readPipe:  readPipe,
		writePipe: writePipe,
	}
	return result
}

func (p *StandardFuzzPipe) ReadBuffer(buf []byte) error {
	_, err := io.ReadFull(p.readPipe, buf)
	return err
}

func (p *StandardFuzzPipe) ReadAllInto(data []byte) (int, error) {
	return p.readPipe.Read(data)
}

func (p *StandardFuzzPipe) WriteBuffer(buf []byte) error {
	_, err := p.writePipe.Write(buf)
	return err
}

func (p *StandardFuzzPipe) ReadIndexAndLength() (uint16, uint64) {
	return 0, 0
}

func (p *StandardFuzzPipe) WriteReply(r *Reply) {

}

func (p *StandardFuzzPipe) Close() {
	p.readPipe.Close()
	p.writePipe.Close()
}

type FuzzCmd interface {
	Kill()
	KillProcess()
	Abort()
	Wait() error
	AddEnviron(...string)
	SetCommand(string)
	SetDir(string)
	SetStdoutStdErr(io.Writer, io.Writer)
	Start() error
	SetupCommMapping(rOut, wIn *os.File, comm []Mapping)
}

type standardFuzzCmd struct {
	cmd *exec.Cmd
}

func (c *standardFuzzCmd) Kill() {
	c.cmd.Process.Signal(syscall.SIGKILL)
}

func (c *standardFuzzCmd) KillProcess() {
	if c.cmd.Process != nil {
		c.cmd.Process.Kill()
	}
}

func (c *standardFuzzCmd) Abort() {
	c.cmd.Process.Signal(syscall.SIGABRT)
}

func (c *standardFuzzCmd) Wait() error {
	return c.cmd.Wait()
}

func (c *standardFuzzCmd) AddEnviron(env ...string) {
	c.cmd.Env = append(c.cmd.Env, env...)
}

func (c *standardFuzzCmd) SetCommand(bin string) {
	c.cmd = exec.Command(bin)
}

func (c *standardFuzzCmd) SetDir(dir string) {
	c.cmd.Dir = dir
}

func (c *standardFuzzCmd) SetStdoutStdErr(stdout io.Writer, stderr io.Writer) {
	c.cmd.Stdout = stdout //NOTE make sure we don't leave this scaffolded with os.Stdout!
	c.cmd.Stderr = stdout //NOTE make sure we don't leave this scaffolded with os.Stdout!
	if c.cmd.Stdout == os.Stdout || c.cmd.Stderr == os.Stderr ||
		c.cmd.Stderr == os.Stdout || c.cmd.Stdout == os.Stderr {
		panic("stdout/stderr is scaffolded!")
	}
}

func (c *standardFuzzCmd) Start() error {
	return c.cmd.Start()
}

func (c *standardFuzzCmd) SetupCommMapping(rOut, wIn *os.File, comm []Mapping) {
	setupCommMapping(c.cmd, rOut, wIn, comm)
}

type Testee struct {
	sensorRegion   []byte
	inputRegion    []byte
	resultRegion   []byte
	sonarRegion    []byte
	fuzzCmd        FuzzCmd
	inFuzzPipe     FuzzPipe
	outFuzzPipe    FuzzPipe
	stdoutFuzzPipe FuzzPipe
	writebuf       [10]byte                     // reusable write buffer
	resbuf         [ReturnResultValuesSize]byte // reusable results buffer
	execs          int
	startTime      int64
	outputC        chan []byte
	downC          chan bool
	down           bool
	fnidx          uint16
}

func newTestee(bin string, comm []Mapping, sensorRegion, inputRegion, resultRegion, sonarRegion []byte, fnidx uint16, buffer []byte) *Testee {
retry:
	rIn, wIn, err := os.Pipe()
	if err != nil {
		log.Fatalf("failed to pipe: %v", err)
	}
	rOut, wOut, err := os.Pipe()
	if err != nil {
		log.Fatalf("failed to pipe: %v", err)
	}
	rStdout, wStdout, err := os.Pipe()
	if err != nil {
		log.Fatalf("failed to pipe: %v", err)
	}

	var inFuzzPipe FuzzPipe
	var outFuzzPipe FuzzPipe
	var stdoutFuzzPipe FuzzPipe

	var fuzzCmd FuzzCmd

	inFuzzPipe = NewFuzzPipe(rIn, wIn)
	outFuzzPipe = NewFuzzPipe(rOut, wOut)
	stdoutFuzzPipe = NewFuzzPipe(rStdout, wStdout)

	fuzzCmd = new(standardFuzzCmd)

	dir := filepath.Dir(bin)
	path, err := filepath.Abs(bin)
	if err != nil {
		panic("could not resolve exe path")
	}
	fuzzCmd.SetCommand(path)
	fuzzCmd.SetDir(dir)

	fuzzCmd.SetStdoutStdErr(wStdout, wStdout)

	fuzzCmd.AddEnviron(os.Environ()...)
	fuzzCmd.AddEnviron("GOTRACEBACK=1")
	fuzzCmd.SetupCommMapping(rOut, wIn, comm)

	if err = fuzzCmd.Start(); err != nil {
		// This can be a transient failure like "cannot allocate memory" or "text file is busy".
		log.Printf("failed to start test binary: %v", err)
		inFuzzPipe.Close()
		outFuzzPipe.Close()
		stdoutFuzzPipe.Close()
		time.Sleep(time.Second)
		goto retry
	}

	rOut.Close()
	wIn.Close()
	wStdout.Close()

	var t = &Testee{
		sensorRegion:   sensorRegion,
		inputRegion:    inputRegion,
		resultRegion:   resultRegion,
		sonarRegion:    sonarRegion,
		fuzzCmd:        fuzzCmd,
		inFuzzPipe:     inFuzzPipe,
		outFuzzPipe:    outFuzzPipe,
		stdoutFuzzPipe: stdoutFuzzPipe,
		outputC:        make(chan []byte),
		downC:          make(chan bool),
		fnidx:          fnidx,
		writebuf:       writebuf,
	}

	return t
}

// test passes data for testing.
func (t *Testee) sendTest() (res int, ns uint64, cover []byte, sonar, extractData []byte, crashed, hanged, retry bool) {

	var dataBytes []byte
	var err error

	dataBytes = []byte(`{"seed":{"data":[{"tag":"stuff","type":"string","v":"Gray","used":true}]},"skip":false,"init":false,"got_up":true,"depth":5,"meta":[{"k":"fuzzData"}]}`)

	copy(t.inputRegion[:], dataBytes)
	atomic.StoreInt64(&t.startTime, time.Now().UnixNano())
	t.writebuf[0] = byte(t.fnidx & 0xFF)
	t.writebuf[1] = byte(t.fnidx >> 8)
	binary.LittleEndian.PutUint64(t.writebuf[2:], uint64(len(dataBytes)))

	// Do the write
	if err = t.outFuzzPipe.WriteBuffer(t.writebuf[0:10]); err != nil {
		log.Printf("write to testee failed: %v", err)
		retry = true
		return
	}

	// Once we do the write, the test is running.
	// Once we read the reply below, the test is done.
	// This is parallelled by type Reply struct in base-fuzz-dep/main.go
	type Reply struct {
		Res   uint64
		Ns    uint64
		Sonar uint64
	}

	// read the reply
	err = t.inFuzzPipe.ReadBuffer(t.resbuf[:])

	cover = t.sensorRegion
	return
}
