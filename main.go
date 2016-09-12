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
	//	"github.com/miekg/dns"
	"io"
	"os"
	"time"
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
	normalPack chan gopacket.Packet, fragV4Pack chan gopacket.Packet, fragv6Pack chan gopacket.Packet,
	endNotification chan bool) {
	for packet := range source.Packets() {
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer != nil {
			tcpPack <- packet
			// send packet to tcp ASSEMBLER
		} else {
			v6Layer := packet.Layer(layers.LayerTypeIPv6)
			if v6Layer != nil {
				v6frag := packet.Layer(layers.LayerTypeIPv6Fragment)
				if v6frag == nil {
					ipv6 := v6Layer.(*layers.IPv6)
					IPserializeBuffer := gopacket.NewSerializeBuffer()
					buf, _ := IPserializeBuffer.PrependBytes(len(ipv6.Payload))
					copy(buf, ipv6.Payload)
					ops := gopacket.SerializeOptions{
						FixLengths:       true,
						ComputeChecksums: true,
					}
					ipv6.SerializeTo(IPserializeBuffer, ops)
					sendPack := gopacket.NewPacket(IPserializeBuffer.Bytes(), layers.LayerTypeIPv6, gopacket.Default)
					err := sendPack.ErrorLayer()
					if err != nil {
						fmt.Println("Error decoding some part of the packet:", err)
						normalPack <- packet
					} else {
						sendPack.Metadata().CaptureLength = len(sendPack.Data())
						sendPack.Metadata().Length = len(sendPack.Data())
						normalPack <- sendPack
					}
				} else {
					fragv6Pack <- packet
				}
				// do v6 process
			} else {
				v4Layer := packet.Layer(layers.LayerTypeIPv4)
				if v4Layer == nil {
					continue
				}
				ip := v4Layer.(*layers.IPv4)

				if notFraV4(ip) {
					IPserializeBuffer := gopacket.NewSerializeBuffer()
					buf, _ := IPserializeBuffer.PrependBytes(len(ip.Payload))
					copy(buf, ip.Payload)
					ops := gopacket.SerializeOptions{
						FixLengths:       true,
						ComputeChecksums: true,
					}
					//	ipBuffer, _ := IPserializeBuffer.PrependBytes(len(ip.Payload))
					//	copy(ipBuffer, ip.Payload)
					ip.SerializeTo(IPserializeBuffer, ops)
					sendPack := gopacket.NewPacket(IPserializeBuffer.Bytes(), layers.LayerTypeIPv4, gopacket.Default)
					err := sendPack.ErrorLayer()
					if err != nil {
						fmt.Println("Error decoding some part of the packet:", err)
						normalPack <- packet
					} else {
						sendPack.Metadata().CaptureLength = len(sendPack.Data())
						sendPack.Metadata().Length = len(sendPack.Data())
						normalPack <- sendPack
					}
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
		time.Sleep(time.Millisecond * 500)
	}
	fmt.Printf("done reading in readSource()\n")
	// give a time to write file
	endNotification <- true

}
func pcapWrite(w *pcapgo.Writer, pack chan gopacket.Packet) error {
	var err error
	for {
		packet := <-pack
		fmt.Println("receive a package in pcap Write")
		err = w.WritePacket(packet.Metadata().CaptureInfo, packet.Data()) // write the payload
		if err != nil {
			fmt.Println("error in Write File: ", err)
			continue
		}
		fmt.Println("susccessfully write a package")
	}
	return err
}
func v6Defrag(v6frag chan gopacket.Packet, normalPack chan gopacket.Packet) error {
	defragger := NewIPv6Defragmenter()
	for {
		fragpack := <-v6frag
		in, err := defragger.DefragIPv6(fragpack)
		if err != nil {
			return err
		} else if in == nil {
			continue
		} else {
			normalPack <- in
		}
	}
}
func v4Defrag(v4frag chan gopacket.Packet, normalPack chan gopacket.Packet) error {
	defragger := ip4defrag.NewIPv4Defragmenter()
	for {
		fragpack := <-v4frag
		layer := fragpack.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		in, err := defragger.DefragIPv4(layer)
		if err != nil {
			return err //error handle
		} else if in == nil { //part of fragment continue
			continue
		} else {
			b := gopacket.NewSerializeBuffer()
			ops := gopacket.SerializeOptions{
				FixLengths:       true,
				ComputeChecksums: true,
			}
			// it should be remebered that you should copy the payload in when you use SerializeTo
			ip_payload, _ := b.PrependBytes(len(in.Payload))
			copy(ip_payload, in.Payload)
			in.SerializeTo(b, ops)
			resultPack := gopacket.NewPacket(b.Bytes(), layers.LayerTypeIPv4, gopacket.Default)
			err := resultPack.ErrorLayer()
			if err != nil {
				fmt.Println("Error decoding some part of the packet:", err) //need error handle here
				//return
				continue
			}
			resultPack.Metadata().CaptureLength = len(resultPack.Data())
			resultPack.Metadata().Length = len(resultPack.Data())
			fmt.Println("defrag a package")
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
	for packet := range tcpPack {
		tcp := packet.TransportLayer().(*layers.TCP)
		assembler.AssembleWithTimestamp(packet.NetworkLayer().NetworkFlow(), tcp, packet.Metadata().Timestamp)
	}
}

type DNSStreamFactory struct {
	normal chan gopacket.Packet
}

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
	go hstream.run(h.normal) // Important... we must guarantee that data from the reader stream is read.
	// ReaderStream implements tcpassembly.Stream, so we can return a pointer to it.
	return &hstream.r
}

func (h *dnsStream) run(nomalpack chan gopacket.Packet) {
	//fmt.Printf("reading rebuilt TCP stream\n")
	for {
		len_buf := make([]byte, 2, 2)
		nread, err := io.ReadFull(&h.r, len_buf)
		//fmt.Printf("Read %d bytes\n", nread)
		if nread < 2 || (err != nil && err != io.EOF) {
			// needs error handle there
			//		fmt.Println("error in reading first two bytes: %s", err)
			break
		}
		msg_len := uint(len_buf[0])<<8 | uint(len_buf[1])
		//	fmt.Printf("msg_len:%d\n", msg_len)
		msg_buf := make([]byte, msg_len, msg_len)
		nread, err = io.ReadFull(&h.r, msg_buf)
		if err != nil {
			//		fmt.Println("error in reading full tcp data: %s", err)
			break
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
	udpBuffer, _ := UDPNewSerializBuffer.PrependBytes(len(msg_buf))

	copy(udpBuffer, msg_buf)

	ops := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	if h.net.EndpointType() == layers.EndpointIPv4 {
		ip_checksum := layers.IPv4{}
		ip_checksum.Version = 4
		ip_checksum.TTL = 0
		ip_checksum.SrcIP = h.net.Src().Raw()
		ip_checksum.DstIP = h.net.Dst().Raw()
		udpLayer.SetNetworkLayerForChecksum(&ip_checksum)
	} else {
		ip6_checksum := layers.IPv6{}
		ip6_checksum.Version = 6
		ip6_checksum.NextHeader = layers.IPProtocolNoNextHeader
		ip6_checksum.HopLimit = 0
		ip6_checksum.SrcIP = h.net.Src().Raw()
		ip6_checksum.DstIP = h.net.Dst().Raw()
		udpLayer.SetNetworkLayerForChecksum(&ip6_checksum)
	}
	err := udpLayer.SerializeTo(UDPNewSerializBuffer, ops)
	if err != nil {
		fmt.Print("error in create udp Layer")
		return
		//err = nil
		//	need err handle there
	}

	fmt.Println("finished creat udplayer, the length is ", udpLayer.Length)
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
			Protocol:   layers.IPProtocolUDP,
			Checksum:   0,
			SrcIP:      h.net.Src().Raw(),
			DstIP:      h.net.Dst().Raw(),
			Options:    []layers.IPv4Option{},
			Padding:    []byte{},
		}
		//serialize it and use the serilize buffer to new packet
		IPserializeBuffer := gopacket.NewSerializeBuffer()

		ipBuffer, _ := IPserializeBuffer.PrependBytes(len(UDPNewSerializBuffer.Bytes()))
		copy(ipBuffer, UDPNewSerializBuffer.Bytes())
		err = ip.SerializeTo(IPserializeBuffer, ops)
		if err != nil {
			fmt.Print("error in create ipv4 Layer")
			return
			//err = nil
			//	need err handle there
		}

		fmt.Println("finished creat ip, the length is ", ip.Length)
		resultPack := gopacket.NewPacket(IPserializeBuffer.Bytes(), layers.LayerTypeIPv4, gopacket.Default)
		resultPack.Metadata().CaptureLength = len(resultPack.Data())
		resultPack.Metadata().Length = len(resultPack.Data())
		//seems the capture length is 0 so the pcapwrite cannot write it, try to give them a write value
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
			NextHeader:   layers.IPProtocolNoNextHeader, //no sure what next header should be used there
			HopLimit:     0,
			SrcIP:        h.net.Src().Raw(),
			DstIP:        h.net.Dst().Raw(),
			HopByHop:     nil,
			// hbh will be pointed to by HopByHop if that layer exists.
		}
		IPserializeBuffer := gopacket.NewSerializeBuffer()
		err := ip.SerializeTo(IPserializeBuffer, ops)
		if err != nil {
			fmt.Printf("error in creat IPV6 Layer")
			return
		}
		fmt.Println("finished creat ip, the length is ", ip.Length)
		resultPack := gopacket.NewPacket(IPserializeBuffer.Bytes(), layers.LayerTypeIPv6, gopacket.Default)
		resultPack.Metadata().CaptureLength = len(resultPack.Data())
		resultPack.Metadata().Length = len(resultPack.Data())
		//seems the capture length is 0 so the pcapwrite cannot write it, try to give them a write value
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
		flag.PrintDefaults()
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
	w.WriteFileHeader(65536, layers.LinkTypeRaw)
	defer Output.Close()
	// need add function call here
	tcpPack := make(chan gopacket.Packet, 5) // maybe need change buffersize for chan
	nomalPack := make(chan gopacket.Packet, 5)
	fragV4Pack := make(chan gopacket.Packet, 5)
	fragV6Pack := make(chan gopacket.Packet, 5)
	endNotification := make(chan bool)
	go readSource(packetSource, tcpPack, nomalPack, fragV4Pack, fragV6Pack, endNotification)
	go v6Defrag(fragV6Pack, nomalPack)
	go v4Defrag(fragV4Pack, nomalPack)
	go pcapWrite(w, nomalPack)
	streamFactory := &DNSStreamFactory{normal: nomalPack}
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)
	go tcpAssemble(tcpPack, assembler)

	// wait for the reading to finish
	<-endNotification
}
