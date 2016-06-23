// PcapParser project main.go
package main

import (
	"bufio"
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"os"
	"strconv"
	"strings"
)

/*
func writeData(w *pcapgo.Writer, source *gopacket.PacketSource) error {
	defragger := ip4defrag.NewIPv4Defragmenter()
	w.WriteFileHeader(65536, layers.LinkTypeEthernet)
	for packet := range source.Packets() {
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer != nil {
			// do assemble
		} else {
			v6Layer := packet.Layer(layers.LayerTypeIPv6)
			if v6Layer != nil {
				// do v6 defrag
			} else {
				v4Layer := packet.Layer(layers.LayerTypeIPv4)
				if v4Layer == nil {
					continue
				}
				in, err := defragger.DefragIPv4(v4Layer)
				if err != nil {
					return err
				} else if in == nil { //part of fragment continue
					continue
				} else {
					err := w.WritePacket(packet.Metadata().CaptureInfo, in.LayerContents()) //write the header
					if err != nil {
						return err
					}
					err := w.WritePacket(packet.Metadata().CaptureInfo, in.LayerPayload()) // write the payload
					if err != nil {
						return err
					}
				}
			}
		}

	}
	return nil

}*/
func readSource(source *gopacket.PacketDataSource, tcpPack chan *gopacket.Packet,
	normalPack chan *gopacket.Packet, fragV4Pack chan *gopacket.Packet) {
	for packet := range source.Packets() {
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer != nil {
			tcpPack <- packet
			// send packet to tcp ASSEMBLER
		} else {
			v6Layer := packet.Layer(layers.LayerTypeIPv6)
			if v6Layer != nil {
				// do v6 process
			} else {
				v4Layer := packet.Layer(layers.LayerTypeIPv4)
				if v4Layer == nil {
					//write it
				}
				if notFraV4(v4Layer) {
					normalPack <- packet
				} else {
					fragV4Pack <- packet
				}
				/*
					in, err := defragger.DefragIPv4(v4Layer)
					if err != nil {
						return err
					} else if in == nil { //part of fragment continue
						continue
					} else {
						err := w.WritePacket(packet.Metadata().CaptureInfo, in.LayerContents()) //write the header
						if err != nil {
							return err
						}
						err := w.WritePacket(packet.Metadata().CaptureInfo, in.LayerPayload()) // write the payload
						if err != nil {
							return err
						}
					}*/
			}
		}

	}

}
func pcapWrite(w *pcapgo.Writer, pack chan *gopacket.Packet) error {
	err := w.WritePacket(packet.Metadata().CaptureInfo, pack.Data()) // write the payload
	if err != nil {
		return err
	}
}
func v4Defrag(v4frag chan gopacket.Packet, normalPack chan gopacket.Packet) error {
	defragger := ip4defrag.NewIPv4Defragmenter()
	for {
		select {
		case <-v4frag:
			in, err := defragger.DefragIPv4(v4Layer)
			if err != nil {
				return err
			} else if in == nil { //part of fragment continue
				continue
			} else {
				length := len(in.LayerContents()) + len(in.LayerPayload())
				dataCopy := make([]byte, length)
				copy(datacopy, in.LayerContents())
				copy(datacopy, in.LayerPayload())
				resultPack := gopacket.NewPacket(datacopy, layers.LayerTypeIPv4, gopacket.Default)
				err := resultPack.ErrorLayer()
				if err != nil {
					fmt.Println("Error decoding some part of the packet:", err) //need error handle here
				}
				normalPack <- resultPack
			}
		}
	}
	return nil
}
func notFraV4(ip *layers.IPv4) bool {
	// don't defrag packet with DF flag
	if ip.Flags&layers.IPv4DontFragment != 0 {
		return true
	}
	// don't defrag not fragmented ones
	if ip.Flags&layers.IPv4MoreFragments == 0 && ip.FragOffset == 0 {
		return true
	}
	return false
}
func tcpAssemble(tcpPack chan *gopacket.Packet) {
	tcp := packet.TransportLayer().(*layers.TCP)
	assembler.AssembleWithTimestamp(packet.NetworkLayer().NetworkFlow(), tcp, packet.Metadata().Timestamp)
}

type DNSStreamFactory struct{}

// httpStream will handle the actual decoding of http requests.
type dnsStream struct {
	net, transport gopacket.Flow
	r              tcpreader.ReaderStream
}

func (h *DNSStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	hstream := &dnsStream{
		net:       net,
		transport: transport,
		r:         tcpreader.NewReaderStream(),
	}
	go hstream.run() // Important... we must guarantee that data from the reader stream is read.
	// ReaderStream implements tcpassembly.Stream, so we can return a pointer to it.
	return &hstream
}

func (h *dnsStream) run(nomalpack chan gopacket.Packet) {
	for {
		len_buf := make([]byte, 2, 2)
		nread, err := io.ReadFull(&h, len_buf)
		if nread < 2 || err != nil {
			err = nil
			continue // not sure
			// needs error handle there
		}
		msg_len := len_buf[0]<<8 | len_buf[1]
		msg_buf := make([]bytes, msg_len, msg_len)
		nread, err := io.ReadFull(&h, msg_buf)
		if err != nil {
			err = nil
			continue //not sure
			// need error handle there
		}
		h.creatPacket(msg_buf, nomalpack)
	}
}
func (h *dnsStream) creatPacket(msg_buf []byte, nomalPack chan gopacket.Packet) {
	var sourcePort, DesPort int16
	//read the port from tranport flow,
	b_buf := bytes.NewBuffer(h.transport.Src().Raw())
	binary.Read(b_buf, binary.BigEndian, &sourcePort)
	b_buf = bytes.NewBuffer(h.transport.Dst().Raw())
	binary.Read(b_buf, binary.BigEndian, &DesPort)
	//new a UDP layer
	udpLayer := &UDP{
		BaseLayer: BaseLayer{
			Contents: []byte{},
			Payload:  msg_buf,
		},
		SrcPort:  sourcePort,
		DstPort:  DesPort,
		Length:   1024,
		Checksum: 30026,
		sPort:    h.transport.Src().Raw(),
		dPort:    h.transport.Dst().Raw(),
	}
	seriousBuffer := gopacket.NewSerializeBuffer() // this buffer could be used as a payload of IP layer
	ops := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	err = udpLayer.SerializeTo(seriousBuffer, ops)
	if err != nil {
		err = nil
		//	need err handle there
	}
	if h.net.EndpointType() == layers.EndpointIPv4 {
		//parse NETWORK layer as IPV4
	} else if h.net.EndpointType() == layers.EndpointIPv6 {
		//parse NETWORK layer as IPV6
	} else {
		return //unknown network just return?
	}
	// make udp packet then IP, then send it need to add necessary information to DNS stream
}
func main() {
	var FilePathInput string
	var FilePathOutput string
	flag.StringVar(&FilePathInput, "in", "", "the path of PCAP file")
	flag.StringVar(&FilePathOutput, "out", "", "the output file")
	flag.Parse() // in mind if we need to do search in file.
	if FilePathInput == "" || FilePathOutput == "" {
		fmt.Print("lack of parameters!")
		return
	}
	handle, err := pcap.OpenOffline(FilePathInput)
	if err != nil {
		panic(err)
	}
	defer handle.Close()
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	//need to add tcp assemble and udp defrag here.
	Output, err := os.Create(FilePathOutput)
	w := pcapgo.NewWriter(Output)
	defer Output.Close()
	// need add function call here
}
