package com.google.protobuf;

import java.io.IOException;
import java.nio.ByteBuffer;

/* JADX INFO: loaded from: classes.dex */
public final class UnsafeByteOperations {
    private UnsafeByteOperations() {
    }

    public static ByteString unsafeWrap(ByteBuffer buffer) {
        if (buffer.hasArray()) {
            int offset = buffer.arrayOffset();
            return ByteString.wrap(buffer.array(), buffer.position() + offset, buffer.remaining());
        }
        return new NioByteString(buffer);
    }

    public static void unsafeWriteTo(ByteString bytes, ByteOutput output) throws IOException {
        bytes.writeTo(output);
    }
}
