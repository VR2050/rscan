package com.coremedia.iso;

import java.nio.ByteBuffer;

/* JADX INFO: loaded from: classes.dex */
public final class IsoTypeReaderVariable {
    public static long read(ByteBuffer bb, int bytes) {
        if (bytes == 1) {
            return IsoTypeReader.readUInt8(bb);
        }
        if (bytes == 2) {
            return IsoTypeReader.readUInt16(bb);
        }
        if (bytes == 3) {
            return IsoTypeReader.readUInt24(bb);
        }
        if (bytes == 4) {
            return IsoTypeReader.readUInt32(bb);
        }
        if (bytes == 8) {
            return IsoTypeReader.readUInt64(bb);
        }
        throw new RuntimeException("I don't know how to read " + bytes + " bytes");
    }
}
