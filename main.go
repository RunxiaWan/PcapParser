// PcapParser project main.go
package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/ip4defrag"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
	"io"
	"os"
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
func readSource(source *gopacket.PacketSource, tcpPack chan gopacket.Packet,
	normalPack chan gopacket.Packet, fragV4Pack chan gopacket.Packet) {
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
func pcapWrite(w *pcapgo.Writer, pack chan gopacket.Packet) error {
	for {
		packet := <-pack
		err := w.WritePacket(packet.Metadata().CaptureInfo, packet.Data()) // write the payload
		if err != nil {
			return err
		}
	}
}
func v4Defrag(v4frag chan gopacket.Packet, normalPack chan gopacket.Packet) error {
	defragger := ip4defrag.NewIPv4Defragmenter()
	for {
		fragpack := <-v4frag
		in, err := defragger.DefragIPv4(fragpack.Layer(layers.LayerTypeIPv4))
		if err != nil {
			return err
		} else if in == nil { //part of fragment continue
			continue
		} else {
			b := gopacket.NewSerializeBuffer()
			ops := gopacket.SerializeOptions{
				FixLengths:       true,
				ComputeChecksums: true,
			}
			in.SerializeTo(b, ops)
			resultPack := gopacket.NewPacket(b.Bytes(), layers.LinkTypeIPv4, gopacket.Default)
			err := resultPack.ErrorLayer()
			if err != nil {
				fmt.Println("Error decoding some part of the packet:", err) //need error handle here
			}
			normalPack <- resultPack
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
func tcpAssemble(tcpPack chan gopacket.Packet, assembler *tcpassembly.Assembler) {
	packet := <-tcpPack
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
		msg_buf := make([]byte, msg_len, msg_len)
		nread, err = io.ReadFull(&h, msg_buf)
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
	//read the port from tranport flow
	b_buf := bytes.NewBuffer(h.transport.Src().Raw())
	binary.Read(b_buf, binary.BigEndian, &sourcePort)
	b_buf = bytes.NewBuffer(h.transport.Dst().Raw())
	binary.Read(b_buf, binary.BigEndian, &DesPort)
	//new a UDP layer
	udpLayer := layers.UDP{
		BaseLayer: layers.BaseLayer{
			Contents: []byte{},
			Payload:  msg_buf,
		},
		SrcPort:  layers.UDPPort(sourcePort),
		DstPort:  layers.UDPPort(DesPort),
		Length:   1024,
		Checksum: 30026,
	}
	UDPNewSerializBuffer := gopacket.NewSerializeBuffer() // this buffer could be used as a payload of IP layer
	ops := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	err := udpLayer.SerializeTo(UDPNewSerializBuffer, ops)
	if err != nil {
		err = nil
		//	need err handle there
	}
	if h.net.EndpointType() == layers.EndpointIPv4 { // if it is from ipv4, construct a ipv4 layer
		ip := layers.IPv4{
			BaseLayer: layers.BaseLayer{
				Contents: []byte{},
				Payload:  UDPNewSerializBuffer.Bytes(),
			},
			Version:    4,
			IHL:        0,
			TOS:        0,
			Length:     0,
			Id:         0,
			Flags:      0,
			FragOffset: 0,
			TTL:        0,
			Protocol:   0,
			Checksum:   0,
			SrcIP:      h.net.Src().Raw(),
			DstIP:      h.net.Dst().Raw(),
			Options:    []layers.IPv4Option{},
			Padding:    []byte{},
		}
		//serialize it and use the serilize buffer to new packet
		IPserializeBuffer := gopacket.NewSerializeBuffer()
		ip.SerializeTo(IPserializeBuffer, ops)
		resultPack := gopacket.NewPacket(IPserializeBuffer.Bytes(), layers.LayerTypeIPv4, gopacket.Default)
		nomalPack <- resultPack
		return

	} else if h.net.EndpointType() == layers.EndpointIPv6 {
		// if it is in IPV6 contruct ipv6 packet
		ip := layers.IPv6{
			BaseLayer: layers.BaseLayer{
				Contents: []byte{},
				Payload:  UDPNewSerializBuffer.Bytes(),
			},
			Version:      6,
			TrafficClass: 0,
			FlowLabel:    0,
			Length:       0,
			NextHeader:   0,
			HopLimit:     0,
			SrcIP:        h.net.Src().Raw(),
			DstIP:        h.net.Dst().Raw(),
			HopByHop:     nil,
			// hbh will be pointed to by HopByHop if that layer exists.
		}
		IPserializeBuffer := gopacket.NewSerializeBuffer()
		ip.SerializeTo(IPserializeBuffer, ops)
		resultPack := gopacket.NewPacket(IPserializeBuffer.Bytes(), layers.LayerTypeIPv6, gopacket.Default)
		nomalPack <- resultPack
		return
	} else {
		return //unknown network just return?
	}
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
	tcpPack := make(chan gopacket.Packet, 5) // maybe need change buffersize for chan
	nomalPack := make(chan gopacket.Packet, 5)
	fragV4Pack := make(chan gopacket.Packet, 5)
	go readSource(packetSource, tcpPack, nomalPack, fragV4Pack)
	go v4Defrag(fragV4Pack, nomalPack)
	go pcapWrite(w, nomalPack)
	streamFactory := &DNSStreamFactory{}
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)
	go tcpAssemble(tcpPack, assembler)

}