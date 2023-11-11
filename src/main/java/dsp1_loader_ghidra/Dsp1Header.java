package dsp1_loader_ghidra;

import java.io.IOException;
import java.io.InputStream;

import ghidra.app.util.importer.MessageLog;

public class Dsp1Header {
    byte[] signature = new byte[0x100];
    byte[] magic = new byte[4];
    long binarySize;
    long memoryLayout;
    long specialSegmentType;
    long numSegments;
    long recvDataOnStart; 
    long loadSpecialSegment;
    //union {
    //    BitField<0, 1, u8> recv_data_on_start;
    //    BitField<1, 1, u8> load_special_segment;
    //};
    long specialSegmentAddress;
    long specialSegmentSize;
    long zero;
    class Segment {
        long offset;
        long address;
        long size;
        //INSERT_PADDING_BYTES(3);
        long memoryType;
        byte[] sha256 = new byte[0x10];
        
        boolean isData() {
            return memoryType == 2;
        }
    }
    Segment[] segments = new Segment[10];
    
    long byteArrayAsU32(byte[] in) 
    {
        assert(in.length == 4);
        return ((in[3] & 0xFF) << 24) | 
                ((in[2] & 0xFF) << 16) | 
                ((in[1] & 0xFF) << 8 ) | 
                ((in[0] & 0xFF) << 0 );
    }

    long byteArrayAsU16(byte[] in) 
    {
        assert(in.length == 2);
        return  ((in[1] & 0xFF) << 8 ) | 
                ((in[0] & 0xFF) << 0 );
    }
    
    Dsp1Header(InputStream is) throws IOException {
        signature = is.readNBytes(0x100);
        magic = is.readNBytes(4);
        binarySize = byteArrayAsU32(is.readNBytes(4));
        memoryLayout = byteArrayAsU16(is.readNBytes(2));
        is.skip(3);
        specialSegmentType = is.read();
        numSegments = is.read();
        recvDataOnStart = is.read();
        loadSpecialSegment = (recvDataOnStart & 2) >> 1;
        recvDataOnStart = recvDataOnStart & 1;
        specialSegmentAddress = byteArrayAsU32(is.readNBytes(4));
        specialSegmentSize = byteArrayAsU32(is.readNBytes(4));
        is.skip(8); // Zeros

         for (int i = 0; i < Math.min(numSegments, 10); i ++) {
             Segment s = new Segment();
             s.offset = byteArrayAsU32(is.readNBytes(4));
             s.address = byteArrayAsU32(is.readNBytes(4));
             s.size = byteArrayAsU32(is.readNBytes(4));
             is.skip(3);
             s.memoryType = is.read();
             s.sha256 =  is.readNBytes(0x20);
             segments[i] = s;
         }
    }
    
    public void logFields(MessageLog log) {
        log.appendMsg("binarySize="+binarySize);
        log.appendMsg("memoryLayout="+memoryLayout);
        log.appendMsg("specialSegmentType="+specialSegmentType);
        log.appendMsg("numSegments="+numSegments);
        log.appendMsg("recvDataOnStart="+recvDataOnStart);
        log.appendMsg("loadSpecialSegment="+loadSpecialSegment);
        log.appendMsg("specialSegmentAddress="+specialSegmentAddress);
        log.appendMsg("specialSegmentSize="+specialSegmentSize);
        log.appendMsg("binarySize="+binarySize);
        log.appendMsg("");
        
        for (int i = 0; i < Math.min(numSegments, 10); i ++) {
            Segment s = segments[i];
        
            log.appendMsg("i=" + i);
            log.appendMsg("s.offset=" + s.offset);
            log.appendMsg("s.address=" + s.address);
            log.appendMsg("s.size="+ s.size);
            log.appendMsg("s.memoryType=" + s.memoryType);
            log.appendMsg("");
        }
    } 
    
}
