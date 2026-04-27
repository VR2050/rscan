package com.google.protobuf;

import com.google.android.exoplayer2.extractor.ts.PsExtractor;
import java.nio.ByteBuffer;

/* JADX INFO: loaded from: classes.dex */
final class Utf8 {
    private static final long ASCII_MASK_LONG = -9187201950435737472L;
    public static final int COMPLETE = 0;
    public static final int MALFORMED = -1;
    static final int MAX_BYTES_PER_CHAR = 3;
    private static final int UNSAFE_COUNT_ASCII_THRESHOLD = 16;
    private static final Processor processor;

    static {
        processor = UnsafeProcessor.isAvailable() ? new UnsafeProcessor() : new SafeProcessor();
    }

    public static boolean isValidUtf8(byte[] bytes) {
        return processor.isValidUtf8(bytes, 0, bytes.length);
    }

    public static boolean isValidUtf8(byte[] bytes, int index, int limit) {
        return processor.isValidUtf8(bytes, index, limit);
    }

    public static int partialIsValidUtf8(int state, byte[] bytes, int index, int limit) {
        return processor.partialIsValidUtf8(state, bytes, index, limit);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static int incompleteStateFor(int byte1) {
        if (byte1 > -12) {
            return -1;
        }
        return byte1;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static int incompleteStateFor(int byte1, int byte2) {
        if (byte1 > -12 || byte2 > -65) {
            return -1;
        }
        return (byte2 << 8) ^ byte1;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static int incompleteStateFor(int byte1, int byte2, int byte3) {
        if (byte1 > -12 || byte2 > -65 || byte3 > -65) {
            return -1;
        }
        return ((byte2 << 8) ^ byte1) ^ (byte3 << 16);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static int incompleteStateFor(byte[] bytes, int index, int limit) {
        int byte1 = bytes[index - 1];
        int i = limit - index;
        if (i == 0) {
            return incompleteStateFor(byte1);
        }
        if (i == 1) {
            return incompleteStateFor(byte1, bytes[index]);
        }
        if (i == 2) {
            return incompleteStateFor(byte1, bytes[index], bytes[index + 1]);
        }
        throw new AssertionError();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static int incompleteStateFor(ByteBuffer buffer, int byte1, int index, int remaining) {
        if (remaining == 0) {
            return incompleteStateFor(byte1);
        }
        if (remaining == 1) {
            return incompleteStateFor(byte1, buffer.get(index));
        }
        if (remaining == 2) {
            return incompleteStateFor(byte1, buffer.get(index), buffer.get(index + 1));
        }
        throw new AssertionError();
    }

    static class UnpairedSurrogateException extends IllegalArgumentException {
        UnpairedSurrogateException(int index, int length) {
            super("Unpaired surrogate at index " + index + " of " + length);
        }
    }

    static int encodedLength(CharSequence sequence) {
        int utf16Length = sequence.length();
        int utf8Length = utf16Length;
        int i = 0;
        while (i < utf16Length && sequence.charAt(i) < 128) {
            i++;
        }
        while (true) {
            if (i < utf16Length) {
                char c = sequence.charAt(i);
                if (c < 2048) {
                    utf8Length += (127 - c) >>> 31;
                    i++;
                } else {
                    utf8Length += encodedLengthGeneral(sequence, i);
                    break;
                }
            } else {
                break;
            }
        }
        if (utf8Length < utf16Length) {
            throw new IllegalArgumentException("UTF-8 length does not fit in int: " + (((long) utf8Length) + 4294967296L));
        }
        return utf8Length;
    }

    private static int encodedLengthGeneral(CharSequence sequence, int start) {
        int utf16Length = sequence.length();
        int utf8Length = 0;
        int i = start;
        while (i < utf16Length) {
            char c = sequence.charAt(i);
            if (c < 2048) {
                utf8Length += (127 - c) >>> 31;
            } else {
                utf8Length += 2;
                if (55296 <= c && c <= 57343) {
                    int cp = Character.codePointAt(sequence, i);
                    if (cp < 65536) {
                        throw new UnpairedSurrogateException(i, utf16Length);
                    }
                    i++;
                }
            }
            i++;
        }
        return utf8Length;
    }

    static int encode(CharSequence in, byte[] out, int offset, int length) {
        return processor.encodeUtf8(in, out, offset, length);
    }

    static boolean isValidUtf8(ByteBuffer buffer) {
        return processor.isValidUtf8(buffer, buffer.position(), buffer.remaining());
    }

    static int partialIsValidUtf8(int state, ByteBuffer buffer, int index, int limit) {
        return processor.partialIsValidUtf8(state, buffer, index, limit);
    }

    static void encodeUtf8(CharSequence in, ByteBuffer out) {
        processor.encodeUtf8(in, out);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static int estimateConsecutiveAscii(ByteBuffer buffer, int index, int limit) {
        int i = index;
        int lim = limit - 7;
        while (i < lim && (buffer.getLong(i) & ASCII_MASK_LONG) == 0) {
            i += 8;
        }
        return i - index;
    }

    static abstract class Processor {
        abstract int encodeUtf8(CharSequence charSequence, byte[] bArr, int i, int i2);

        abstract void encodeUtf8Direct(CharSequence charSequence, ByteBuffer byteBuffer);

        abstract int partialIsValidUtf8(int i, byte[] bArr, int i2, int i3);

        abstract int partialIsValidUtf8Direct(int i, ByteBuffer byteBuffer, int i2, int i3);

        Processor() {
        }

        final boolean isValidUtf8(byte[] bytes, int index, int limit) {
            return partialIsValidUtf8(0, bytes, index, limit) == 0;
        }

        final boolean isValidUtf8(ByteBuffer buffer, int index, int limit) {
            return partialIsValidUtf8(0, buffer, index, limit) == 0;
        }

        final int partialIsValidUtf8(int state, ByteBuffer buffer, int index, int limit) {
            if (buffer.hasArray()) {
                int offset = buffer.arrayOffset();
                return partialIsValidUtf8(state, buffer.array(), offset + index, offset + limit);
            }
            if (buffer.isDirect()) {
                return partialIsValidUtf8Direct(state, buffer, index, limit);
            }
            return partialIsValidUtf8Default(state, buffer, index, limit);
        }

        final int partialIsValidUtf8Default(int state, ByteBuffer buffer, int index, int limit) {
            if (state != 0) {
                if (index >= limit) {
                    return state;
                }
                byte byte1 = (byte) state;
                if (byte1 < -32) {
                    if (byte1 >= -62) {
                        int index2 = index + 1;
                        if (buffer.get(index) <= -65) {
                            index = index2;
                        }
                    }
                    return -1;
                }
                if (byte1 < -16) {
                    byte byte2 = (byte) (~(state >> 8));
                    if (byte2 == 0) {
                        int index3 = index + 1;
                        byte2 = buffer.get(index);
                        if (index3 >= limit) {
                            return Utf8.incompleteStateFor(byte1, byte2);
                        }
                        index = index3;
                    }
                    if (byte2 <= -65 && ((byte1 != -32 || byte2 >= -96) && (byte1 != -19 || byte2 < -96))) {
                        int index4 = index + 1;
                        if (buffer.get(index) <= -65) {
                            index = index4;
                        }
                    }
                    return -1;
                }
                byte byte22 = (byte) (~(state >> 8));
                byte byte3 = 0;
                if (byte22 == 0) {
                    int index5 = index + 1;
                    byte22 = buffer.get(index);
                    if (index5 >= limit) {
                        return Utf8.incompleteStateFor(byte1, byte22);
                    }
                    index = index5;
                } else {
                    byte3 = (byte) (state >> 16);
                }
                if (byte3 == 0) {
                    int index6 = index + 1;
                    byte3 = buffer.get(index);
                    if (index6 >= limit) {
                        return Utf8.incompleteStateFor(byte1, byte22, byte3);
                    }
                    index = index6;
                }
                if (byte22 <= -65 && (((byte1 << 28) + (byte22 + 112)) >> 30) == 0 && byte3 <= -65) {
                    int index7 = index + 1;
                    if (buffer.get(index) <= -65) {
                        index = index7;
                    }
                }
                return -1;
            }
            return partialIsValidUtf8(buffer, index, limit);
        }

        private static int partialIsValidUtf8(ByteBuffer buffer, int index, int limit) {
            int index2 = index + Utf8.estimateConsecutiveAscii(buffer, index, limit);
            while (index2 < limit) {
                int index3 = index2 + 1;
                int byte1 = buffer.get(index2);
                if (byte1 >= 0) {
                    index2 = index3;
                } else if (byte1 < -32) {
                    if (index3 >= limit) {
                        return byte1;
                    }
                    if (byte1 < -62 || buffer.get(index3) > -65) {
                        return -1;
                    }
                    index2 = index3 + 1;
                } else if (byte1 < -16) {
                    if (index3 >= limit - 1) {
                        return Utf8.incompleteStateFor(buffer, byte1, index3, limit - index3);
                    }
                    int index4 = index3 + 1;
                    byte byte2 = buffer.get(index3);
                    if (byte2 > -65 || ((byte1 == -32 && byte2 < -96) || ((byte1 == -19 && byte2 >= -96) || buffer.get(index4) > -65))) {
                        return -1;
                    }
                    index2 = index4 + 1;
                } else {
                    if (index3 >= limit - 2) {
                        return Utf8.incompleteStateFor(buffer, byte1, index3, limit - index3);
                    }
                    int index5 = index3 + 1;
                    int byte22 = buffer.get(index3);
                    if (byte22 <= -65 && (((byte1 << 28) + (byte22 + 112)) >> 30) == 0) {
                        int index6 = index5 + 1;
                        if (buffer.get(index5) <= -65) {
                            index2 = index6 + 1;
                            if (buffer.get(index6) > -65) {
                            }
                        }
                    }
                    return -1;
                }
            }
            return 0;
        }

        final void encodeUtf8(CharSequence in, ByteBuffer out) {
            if (out.hasArray()) {
                int offset = out.arrayOffset();
                int endIndex = Utf8.encode(in, out.array(), out.position() + offset, out.remaining());
                out.position(endIndex - offset);
            } else if (out.isDirect()) {
                encodeUtf8Direct(in, out);
            } else {
                encodeUtf8Default(in, out);
            }
        }

        final void encodeUtf8Default(CharSequence in, ByteBuffer out) {
            int inLength = in.length();
            int outIx = out.position();
            int inIx = 0;
            while (inIx < inLength) {
                try {
                    char c = in.charAt(inIx);
                    if (c >= 128) {
                        break;
                    }
                    out.put(outIx + inIx, (byte) c);
                    inIx++;
                } catch (IndexOutOfBoundsException e) {
                    int badWriteIndex = out.position() + Math.max(inIx, (outIx - out.position()) + 1);
                    throw new ArrayIndexOutOfBoundsException("Failed writing " + in.charAt(inIx) + " at index " + badWriteIndex);
                }
            }
            if (inIx == inLength) {
                out.position(outIx + inIx);
                return;
            }
            int outIx2 = outIx + inIx;
            while (inIx < inLength) {
                char c2 = in.charAt(inIx);
                if (c2 < 128) {
                    out.put(outIx2, (byte) c2);
                } else if (c2 < 2048) {
                    int outIx3 = outIx2 + 1;
                    try {
                        out.put(outIx2, (byte) ((c2 >>> 6) | PsExtractor.AUDIO_STREAM));
                        out.put(outIx3, (byte) ((c2 & '?') | 128));
                        outIx2 = outIx3;
                    } catch (IndexOutOfBoundsException e2) {
                        outIx = outIx3;
                        int badWriteIndex2 = out.position() + Math.max(inIx, (outIx - out.position()) + 1);
                        throw new ArrayIndexOutOfBoundsException("Failed writing " + in.charAt(inIx) + " at index " + badWriteIndex2);
                    }
                } else if (c2 < 55296 || 57343 < c2) {
                    int outIx4 = outIx2 + 1;
                    out.put(outIx2, (byte) ((c2 >>> '\f') | 224));
                    outIx2 = outIx4 + 1;
                    out.put(outIx4, (byte) (((c2 >>> 6) & 63) | 128));
                    out.put(outIx2, (byte) ((c2 & '?') | 128));
                } else {
                    if (inIx + 1 != inLength) {
                        inIx++;
                        char low = in.charAt(inIx);
                        if (Character.isSurrogatePair(c2, low)) {
                            int codePoint = Character.toCodePoint(c2, low);
                            int outIx5 = outIx2 + 1;
                            try {
                                out.put(outIx2, (byte) ((codePoint >>> 18) | PsExtractor.VIDEO_STREAM_MASK));
                                int outIx6 = outIx5 + 1;
                                out.put(outIx5, (byte) (((codePoint >>> 12) & 63) | 128));
                                int outIx7 = outIx6 + 1;
                                out.put(outIx6, (byte) (((codePoint >>> 6) & 63) | 128));
                                out.put(outIx7, (byte) ((codePoint & 63) | 128));
                                outIx2 = outIx7;
                            } catch (IndexOutOfBoundsException e3) {
                                outIx = outIx5;
                                int badWriteIndex22 = out.position() + Math.max(inIx, (outIx - out.position()) + 1);
                                throw new ArrayIndexOutOfBoundsException("Failed writing " + in.charAt(inIx) + " at index " + badWriteIndex22);
                            }
                        }
                    }
                    throw new UnpairedSurrogateException(inIx, inLength);
                }
                inIx++;
                outIx2++;
            }
            out.position(outIx2);
        }
    }

    static final class SafeProcessor extends Processor {
        SafeProcessor() {
        }

        @Override // com.google.protobuf.Utf8.Processor
        int partialIsValidUtf8(int state, byte[] bytes, int index, int limit) {
            if (state != 0) {
                if (index >= limit) {
                    return state;
                }
                int byte1 = (byte) state;
                if (byte1 < -32) {
                    if (byte1 >= -62) {
                        int index2 = index + 1;
                        if (bytes[index] <= -65) {
                            index = index2;
                        }
                    }
                    return -1;
                }
                if (byte1 < -16) {
                    int byte2 = (byte) (~(state >> 8));
                    if (byte2 == 0) {
                        int index3 = index + 1;
                        byte2 = bytes[index];
                        if (index3 >= limit) {
                            return Utf8.incompleteStateFor(byte1, byte2);
                        }
                        index = index3;
                    }
                    if (byte2 <= -65 && ((byte1 != -32 || byte2 >= -96) && (byte1 != -19 || byte2 < -96))) {
                        int index4 = index + 1;
                        if (bytes[index] <= -65) {
                            index = index4;
                        }
                    }
                    return -1;
                }
                int byte22 = (byte) (~(state >> 8));
                int byte3 = 0;
                if (byte22 == 0) {
                    int index5 = index + 1;
                    byte22 = bytes[index];
                    if (index5 >= limit) {
                        return Utf8.incompleteStateFor(byte1, byte22);
                    }
                    index = index5;
                } else {
                    byte3 = (byte) (state >> 16);
                }
                if (byte3 == 0) {
                    int index6 = index + 1;
                    byte3 = bytes[index];
                    if (index6 >= limit) {
                        return Utf8.incompleteStateFor(byte1, byte22, byte3);
                    }
                    index = index6;
                }
                if (byte22 <= -65 && (((byte1 << 28) + (byte22 + 112)) >> 30) == 0 && byte3 <= -65) {
                    int index7 = index + 1;
                    if (bytes[index] <= -65) {
                        index = index7;
                    }
                }
                return -1;
            }
            return partialIsValidUtf8(bytes, index, limit);
        }

        @Override // com.google.protobuf.Utf8.Processor
        int partialIsValidUtf8Direct(int state, ByteBuffer buffer, int index, int limit) {
            return partialIsValidUtf8Default(state, buffer, index, limit);
        }

        @Override // com.google.protobuf.Utf8.Processor
        int encodeUtf8(CharSequence in, byte[] out, int offset, int length) {
            char c;
            int utf16Length = in.length();
            int i = 0;
            int limit = offset + length;
            while (i < utf16Length && i + offset < limit && (c = in.charAt(i)) < 128) {
                out[offset + i] = (byte) c;
                i++;
            }
            if (i == utf16Length) {
                return offset + utf16Length;
            }
            int j = offset + i;
            while (i < utf16Length) {
                char c2 = in.charAt(i);
                if (c2 < 128 && j < limit) {
                    out[j] = (byte) c2;
                    j++;
                } else if (c2 < 2048 && j <= limit - 2) {
                    int j2 = j + 1;
                    out[j] = (byte) ((c2 >>> 6) | 960);
                    j = j2 + 1;
                    out[j2] = (byte) ((c2 & '?') | 128);
                } else if ((c2 < 55296 || 57343 < c2) && j <= limit - 3) {
                    int j3 = j + 1;
                    out[j] = (byte) ((c2 >>> '\f') | 480);
                    int j4 = j3 + 1;
                    out[j3] = (byte) (((c2 >>> 6) & 63) | 128);
                    out[j4] = (byte) ((c2 & '?') | 128);
                    j = j4 + 1;
                } else {
                    if (j <= limit - 4) {
                        if (i + 1 != in.length()) {
                            i++;
                            char low = in.charAt(i);
                            if (Character.isSurrogatePair(c2, low)) {
                                int codePoint = Character.toCodePoint(c2, low);
                                int j5 = j + 1;
                                out[j] = (byte) ((codePoint >>> 18) | PsExtractor.VIDEO_STREAM_MASK);
                                int j6 = j5 + 1;
                                out[j5] = (byte) (((codePoint >>> 12) & 63) | 128);
                                int j7 = j6 + 1;
                                out[j6] = (byte) (((codePoint >>> 6) & 63) | 128);
                                j = j7 + 1;
                                out[j7] = (byte) ((codePoint & 63) | 128);
                            }
                        }
                        throw new UnpairedSurrogateException(i - 1, utf16Length);
                    }
                    if (55296 <= c2 && c2 <= 57343 && (i + 1 == in.length() || !Character.isSurrogatePair(c2, in.charAt(i + 1)))) {
                        throw new UnpairedSurrogateException(i, utf16Length);
                    }
                    throw new ArrayIndexOutOfBoundsException("Failed writing " + c2 + " at index " + j);
                }
                i++;
            }
            return j;
        }

        @Override // com.google.protobuf.Utf8.Processor
        void encodeUtf8Direct(CharSequence in, ByteBuffer out) {
            encodeUtf8Default(in, out);
        }

        private static int partialIsValidUtf8(byte[] bytes, int index, int limit) {
            while (index < limit && bytes[index] >= 0) {
                index++;
            }
            if (index >= limit) {
                return 0;
            }
            return partialIsValidUtf8NonAscii(bytes, index, limit);
        }

        private static int partialIsValidUtf8NonAscii(byte[] bytes, int index, int limit) {
            while (index < limit) {
                int index2 = index + 1;
                int byte1 = bytes[index];
                if (byte1 >= 0) {
                    index = index2;
                } else {
                    if (byte1 < -32) {
                        if (index2 >= limit) {
                            return byte1;
                        }
                        if (byte1 >= -62) {
                            index = index2 + 1;
                            if (bytes[index2] > -65) {
                            }
                        }
                        return -1;
                    }
                    if (byte1 < -16) {
                        if (index2 >= limit - 1) {
                            return Utf8.incompleteStateFor(bytes, index2, limit);
                        }
                        int index3 = index2 + 1;
                        int byte2 = bytes[index2];
                        if (byte2 <= -65 && ((byte1 != -32 || byte2 >= -96) && (byte1 != -19 || byte2 < -96))) {
                            index = index3 + 1;
                            if (bytes[index3] > -65) {
                            }
                        }
                        return -1;
                    }
                    if (index2 >= limit - 2) {
                        return Utf8.incompleteStateFor(bytes, index2, limit);
                    }
                    int index4 = index2 + 1;
                    int byte22 = bytes[index2];
                    if (byte22 <= -65 && (((byte1 << 28) + (byte22 + 112)) >> 30) == 0) {
                        int index5 = index4 + 1;
                        if (bytes[index4] <= -65) {
                            index = index5 + 1;
                            if (bytes[index5] > -65) {
                            }
                        }
                    }
                    return -1;
                }
            }
            return 0;
        }
    }

    static final class UnsafeProcessor extends Processor {
        UnsafeProcessor() {
        }

        static boolean isAvailable() {
            return UnsafeUtil.hasUnsafeArrayOperations() && UnsafeUtil.hasUnsafeByteBufferOperations();
        }

        @Override // com.google.protobuf.Utf8.Processor
        int partialIsValidUtf8(int state, byte[] bytes, int index, int limit) {
            if ((index | limit | (bytes.length - limit)) < 0) {
                throw new ArrayIndexOutOfBoundsException(String.format("Array length=%d, index=%d, limit=%d", Integer.valueOf(bytes.length), Integer.valueOf(index), Integer.valueOf(limit)));
            }
            long offset = UnsafeUtil.getArrayBaseOffset() + ((long) index);
            long offsetLimit = UnsafeUtil.getArrayBaseOffset() + ((long) limit);
            if (state != 0) {
                if (offset >= offsetLimit) {
                    return state;
                }
                int byte1 = (byte) state;
                if (byte1 < -32) {
                    if (byte1 >= -62) {
                        long offset2 = 1 + offset;
                        if (UnsafeUtil.getByte(bytes, offset) <= -65) {
                            offset = offset2;
                        }
                    }
                    return -1;
                }
                if (byte1 < -16) {
                    int byte2 = (byte) (~(state >> 8));
                    if (byte2 == 0) {
                        long offset3 = offset + 1;
                        byte2 = UnsafeUtil.getByte(bytes, offset);
                        if (offset3 >= offsetLimit) {
                            return Utf8.incompleteStateFor(byte1, byte2);
                        }
                        offset = offset3;
                    }
                    if (byte2 <= -65 && ((byte1 != -32 || byte2 >= -96) && (byte1 != -19 || byte2 < -96))) {
                        long offset4 = 1 + offset;
                        if (UnsafeUtil.getByte(bytes, offset) <= -65) {
                            offset = offset4;
                        }
                    }
                    return -1;
                }
                int byte22 = (byte) (~(state >> 8));
                int byte3 = 0;
                if (byte22 == 0) {
                    long offset5 = offset + 1;
                    byte22 = UnsafeUtil.getByte(bytes, offset);
                    if (offset5 >= offsetLimit) {
                        return Utf8.incompleteStateFor(byte1, byte22);
                    }
                    offset = offset5;
                } else {
                    byte3 = (byte) (state >> 16);
                }
                if (byte3 == 0) {
                    long offset6 = offset + 1;
                    byte3 = UnsafeUtil.getByte(bytes, offset);
                    if (offset6 >= offsetLimit) {
                        return Utf8.incompleteStateFor(byte1, byte22, byte3);
                    }
                    offset = offset6;
                }
                if (byte22 <= -65 && (((byte1 << 28) + (byte22 + 112)) >> 30) == 0 && byte3 <= -65) {
                    long offset7 = 1 + offset;
                    if (UnsafeUtil.getByte(bytes, offset) <= -65) {
                        offset = offset7;
                    }
                }
                return -1;
            }
            return partialIsValidUtf8(bytes, offset, (int) (offsetLimit - offset));
        }

        @Override // com.google.protobuf.Utf8.Processor
        int partialIsValidUtf8Direct(int state, ByteBuffer buffer, int index, int limit) {
            if ((index | limit | (buffer.limit() - limit)) < 0) {
                throw new ArrayIndexOutOfBoundsException(String.format("buffer limit=%d, index=%d, limit=%d", Integer.valueOf(buffer.limit()), Integer.valueOf(index), Integer.valueOf(limit)));
            }
            long address = UnsafeUtil.addressOffset(buffer) + ((long) index);
            long addressLimit = ((long) (limit - index)) + address;
            if (state != 0) {
                if (address >= addressLimit) {
                    return state;
                }
                int byte1 = (byte) state;
                if (byte1 < -32) {
                    if (byte1 >= -62) {
                        long address2 = 1 + address;
                        if (UnsafeUtil.getByte(address) <= -65) {
                            address = address2;
                        }
                    }
                    return -1;
                }
                if (byte1 < -16) {
                    int byte2 = (byte) (~(state >> 8));
                    if (byte2 == 0) {
                        long address3 = address + 1;
                        byte2 = UnsafeUtil.getByte(address);
                        if (address3 >= addressLimit) {
                            return Utf8.incompleteStateFor(byte1, byte2);
                        }
                        address = address3;
                    }
                    if (byte2 <= -65 && ((byte1 != -32 || byte2 >= -96) && (byte1 != -19 || byte2 < -96))) {
                        long address4 = 1 + address;
                        if (UnsafeUtil.getByte(address) <= -65) {
                            address = address4;
                        }
                    }
                    return -1;
                }
                int byte22 = (byte) (~(state >> 8));
                int byte3 = 0;
                if (byte22 == 0) {
                    long address5 = address + 1;
                    byte22 = UnsafeUtil.getByte(address);
                    if (address5 >= addressLimit) {
                        return Utf8.incompleteStateFor(byte1, byte22);
                    }
                    address = address5;
                } else {
                    byte3 = (byte) (state >> 16);
                }
                if (byte3 == 0) {
                    long address6 = address + 1;
                    byte3 = UnsafeUtil.getByte(address);
                    if (address6 >= addressLimit) {
                        return Utf8.incompleteStateFor(byte1, byte22, byte3);
                    }
                    address = address6;
                }
                if (byte22 <= -65 && (((byte1 << 28) + (byte22 + 112)) >> 30) == 0 && byte3 <= -65) {
                    long address7 = 1 + address;
                    if (UnsafeUtil.getByte(address) <= -65) {
                        address = address7;
                    }
                }
                return -1;
            }
            return partialIsValidUtf8(address, (int) (addressLimit - address));
        }

        @Override // com.google.protobuf.Utf8.Processor
        int encodeUtf8(CharSequence in, byte[] out, int offset, int length) {
            char c;
            long j;
            long outIx;
            char c2;
            long outIx2 = UnsafeUtil.getArrayBaseOffset() + ((long) offset);
            long outLimit = ((long) length) + outIx2;
            int inLimit = in.length();
            if (inLimit > length || out.length - length < offset) {
                throw new ArrayIndexOutOfBoundsException("Failed writing " + in.charAt(inLimit - 1) + " at index " + (offset + length));
            }
            int inIx = 0;
            while (true) {
                c = 128;
                j = 1;
                if (inIx >= inLimit || (c2 = in.charAt(inIx)) >= 128) {
                    break;
                }
                UnsafeUtil.putByte(out, outIx2, (byte) c2);
                inIx++;
                outIx2++;
            }
            if (inIx == inLimit) {
                return (int) (outIx2 - UnsafeUtil.getArrayBaseOffset());
            }
            while (inIx < inLimit) {
                char c3 = in.charAt(inIx);
                if (c3 < c && outIx2 < outLimit) {
                    UnsafeUtil.putByte(out, outIx2, (byte) c3);
                    outIx2 += j;
                    c = 128;
                    outIx = outLimit;
                } else if (c3 < 2048 && outIx2 <= outLimit - 2) {
                    long outIx3 = outIx2 + j;
                    UnsafeUtil.putByte(out, outIx2, (byte) ((c3 >>> 6) | 960));
                    outIx2 = outIx3 + j;
                    UnsafeUtil.putByte(out, outIx3, (byte) ((c3 & '?') | 128));
                    outIx = outLimit;
                    c = 128;
                } else {
                    if ((c3 >= 55296 && 57343 >= c3) || outIx2 > outLimit - 3) {
                        if (outIx2 > outLimit - 4) {
                            if (55296 > c3 || c3 > 57343 || (inIx + 1 != inLimit && Character.isSurrogatePair(c3, in.charAt(inIx + 1)))) {
                                throw new ArrayIndexOutOfBoundsException("Failed writing " + c3 + " at index " + outIx2);
                            }
                            throw new UnpairedSurrogateException(inIx, inLimit);
                        }
                        if (inIx + 1 != inLimit) {
                            inIx++;
                            char low = in.charAt(inIx);
                            if (Character.isSurrogatePair(c3, low)) {
                                int codePoint = Character.toCodePoint(c3, low);
                                outIx = outLimit;
                                long outLimit2 = outIx2 + 1;
                                UnsafeUtil.putByte(out, outIx2, (byte) ((codePoint >>> 18) | PsExtractor.VIDEO_STREAM_MASK));
                                long outIx4 = outLimit2 + 1;
                                c = 128;
                                UnsafeUtil.putByte(out, outLimit2, (byte) (((codePoint >>> 12) & 63) | 128));
                                long outIx5 = outIx4 + 1;
                                UnsafeUtil.putByte(out, outIx4, (byte) (((codePoint >>> 6) & 63) | 128));
                                outIx2 = outIx5 + 1;
                                UnsafeUtil.putByte(out, outIx5, (byte) ((codePoint & 63) | 128));
                            }
                        }
                        throw new UnpairedSurrogateException(inIx - 1, inLimit);
                    }
                    long outIx6 = outIx2 + 1;
                    UnsafeUtil.putByte(out, outIx2, (byte) ((c3 >>> '\f') | 480));
                    long outIx7 = outIx6 + 1;
                    UnsafeUtil.putByte(out, outIx6, (byte) (((c3 >>> 6) & 63) | 128));
                    UnsafeUtil.putByte(out, outIx7, (byte) ((c3 & '?') | 128));
                    outIx = outLimit;
                    outIx2 = outIx7 + 1;
                    c = 128;
                }
                inIx++;
                outLimit = outIx;
                j = 1;
            }
            return (int) (outIx2 - UnsafeUtil.getArrayBaseOffset());
        }

        @Override // com.google.protobuf.Utf8.Processor
        void encodeUtf8Direct(CharSequence in, ByteBuffer out) {
            char c;
            long j;
            long outIx;
            long j2;
            String str;
            char c2;
            long address = UnsafeUtil.addressOffset(out);
            long outIx2 = ((long) out.position()) + address;
            long outLimit = ((long) out.limit()) + address;
            int inLimit = in.length();
            String str2 = " at index ";
            if (inLimit > outLimit - outIx2) {
                throw new ArrayIndexOutOfBoundsException("Failed writing " + in.charAt(inLimit - 1) + " at index " + out.limit());
            }
            int inIx = 0;
            while (true) {
                c = 128;
                j = 1;
                if (inIx >= inLimit || (c2 = in.charAt(inIx)) >= 128) {
                    break;
                }
                UnsafeUtil.putByte(outIx2, (byte) c2);
                inIx++;
                outIx2++;
            }
            if (inIx == inLimit) {
                out.position((int) (outIx2 - address));
                return;
            }
            while (inIx < inLimit) {
                char c3 = in.charAt(inIx);
                if (c3 < c && outIx2 < outLimit) {
                    long outIx3 = outIx2 + j;
                    UnsafeUtil.putByte(outIx2, (byte) c3);
                    j2 = j;
                    str = str2;
                    outIx2 = outIx3;
                    outIx = address;
                } else if (c3 >= 2048 || outIx2 > outLimit - 2) {
                    outIx = address;
                    if ((c3 >= 55296 && 57343 >= c3) || outIx2 > outLimit - 3) {
                        if (outIx2 <= outLimit - 4) {
                            if (inIx + 1 != inLimit) {
                                inIx++;
                                char low = in.charAt(inIx);
                                if (Character.isSurrogatePair(c3, low)) {
                                    int codePoint = Character.toCodePoint(c3, low);
                                    long outIx4 = outIx2 + j;
                                    UnsafeUtil.putByte(outIx2, (byte) ((codePoint >>> 18) | PsExtractor.VIDEO_STREAM_MASK));
                                    long outIx5 = outIx4 + 1;
                                    UnsafeUtil.putByte(outIx4, (byte) (((codePoint >>> 12) & 63) | 128));
                                    str = str2;
                                    long outIx6 = outIx5 + 1;
                                    UnsafeUtil.putByte(outIx5, (byte) (((codePoint >>> 6) & 63) | 128));
                                    j2 = 1;
                                    outIx2 = outIx6 + 1;
                                    UnsafeUtil.putByte(outIx6, (byte) ((codePoint & 63) | 128));
                                }
                            }
                            throw new UnpairedSurrogateException(inIx - 1, inLimit);
                        }
                        String str3 = str2;
                        if (55296 <= c3 && c3 <= 57343 && (inIx + 1 == inLimit || !Character.isSurrogatePair(c3, in.charAt(inIx + 1)))) {
                            throw new UnpairedSurrogateException(inIx, inLimit);
                        }
                        throw new ArrayIndexOutOfBoundsException("Failed writing " + c3 + str3 + outIx2);
                    }
                    long outIx7 = outIx2 + j;
                    UnsafeUtil.putByte(outIx2, (byte) ((c3 >>> '\f') | 480));
                    long outIx8 = outIx7 + j;
                    UnsafeUtil.putByte(outIx7, (byte) (((c3 >>> 6) & 63) | 128));
                    UnsafeUtil.putByte(outIx8, (byte) ((c3 & '?') | 128));
                    outIx2 = outIx8 + j;
                    j2 = j;
                    str = str2;
                } else {
                    outIx = address;
                    long outIx9 = outIx2 + j;
                    UnsafeUtil.putByte(outIx2, (byte) ((c3 >>> 6) | 960));
                    UnsafeUtil.putByte(outIx9, (byte) ((c3 & '?') | 128));
                    outIx2 = outIx9 + j;
                    j2 = j;
                    str = str2;
                }
                inIx++;
                str2 = str;
                address = outIx;
                j = j2;
                c = 128;
            }
            out.position((int) (outIx2 - address));
        }

        private static int unsafeEstimateConsecutiveAscii(byte[] bytes, long offset, int maxChars) {
            if (maxChars < 16) {
                return 0;
            }
            int unaligned = ((int) offset) & 7;
            int j = unaligned;
            while (j > 0) {
                long offset2 = 1 + offset;
                if (UnsafeUtil.getByte(bytes, offset) >= 0) {
                    j--;
                    offset = offset2;
                } else {
                    return unaligned - j;
                }
            }
            int remaining = maxChars - unaligned;
            while (remaining >= 8 && (UnsafeUtil.getLong(bytes, offset) & Utf8.ASCII_MASK_LONG) == 0) {
                offset += 8;
                remaining -= 8;
            }
            return maxChars - remaining;
        }

        private static int unsafeEstimateConsecutiveAscii(long address, int maxChars) {
            if (maxChars < 16) {
                return 0;
            }
            int unaligned = ((int) address) & 7;
            int j = unaligned;
            while (j > 0) {
                long address2 = 1 + address;
                if (UnsafeUtil.getByte(address) >= 0) {
                    j--;
                    address = address2;
                } else {
                    return unaligned - j;
                }
            }
            int remaining = maxChars - unaligned;
            while (remaining >= 8 && (UnsafeUtil.getLong(address) & Utf8.ASCII_MASK_LONG) == 0) {
                address += 8;
                remaining -= 8;
            }
            return maxChars - remaining;
        }

        /* JADX WARN: Code restructure failed: missing block: B:23:0x003b, code lost:
        
            return -1;
         */
        /* JADX WARN: Code restructure failed: missing block: B:42:0x006a, code lost:
        
            return -1;
         */
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        private static int partialIsValidUtf8(byte[] r11, long r12, int r14) {
            /*
                int r0 = unsafeEstimateConsecutiveAscii(r11, r12, r14)
                int r14 = r14 - r0
                long r1 = (long) r0
                long r12 = r12 + r1
            L7:
                r1 = 0
            L8:
                r2 = 1
                if (r14 <= 0) goto L1a
                long r4 = r12 + r2
                byte r12 = com.google.protobuf.UnsafeUtil.getByte(r11, r12)
                r1 = r12
                if (r12 < 0) goto L19
                int r14 = r14 + (-1)
                r12 = r4
                goto L8
            L19:
                r12 = r4
            L1a:
                if (r14 != 0) goto L1e
                r2 = 0
                return r2
            L1e:
                int r14 = r14 + (-1)
                r4 = -32
                r5 = -65
                r6 = -1
                if (r1 >= r4) goto L3c
                if (r14 != 0) goto L2a
                return r1
            L2a:
                int r14 = r14 + (-1)
                r4 = -62
                if (r1 < r4) goto L3b
                long r2 = r2 + r12
                byte r12 = com.google.protobuf.UnsafeUtil.getByte(r11, r12)
                if (r12 <= r5) goto L39
                r12 = r2
                goto L3b
            L39:
                r12 = r2
                goto L99
            L3b:
                return r6
            L3c:
                r7 = -16
                if (r1 >= r7) goto L6b
                r7 = 2
                if (r14 >= r7) goto L48
                int r2 = unsafeIncompleteStateFor(r11, r1, r12, r14)
                return r2
            L48:
                int r14 = r14 + (-2)
                long r7 = r12 + r2
                byte r12 = com.google.protobuf.UnsafeUtil.getByte(r11, r12)
                r13 = r12
                if (r12 > r5) goto L6a
                r12 = -96
                if (r1 != r4) goto L59
                if (r13 < r12) goto L6a
            L59:
                r4 = -19
                if (r1 != r4) goto L5f
                if (r13 >= r12) goto L6a
            L5f:
                long r2 = r2 + r7
                byte r12 = com.google.protobuf.UnsafeUtil.getByte(r11, r7)
                if (r12 <= r5) goto L68
                r7 = r2
                goto L6a
            L68:
                r12 = r2
                goto L99
            L6a:
                return r6
            L6b:
                r4 = 3
                if (r14 >= r4) goto L73
                int r2 = unsafeIncompleteStateFor(r11, r1, r12, r14)
                return r2
            L73:
                int r14 = r14 + (-3)
                long r7 = r12 + r2
                byte r12 = com.google.protobuf.UnsafeUtil.getByte(r11, r12)
                r13 = r12
                if (r12 > r5) goto L9c
                int r12 = r1 << 28
                int r4 = r13 + 112
                int r12 = r12 + r4
                int r12 = r12 >> 30
                if (r12 != 0) goto L9c
                long r9 = r7 + r2
                byte r12 = com.google.protobuf.UnsafeUtil.getByte(r11, r7)
                if (r12 > r5) goto L9b
                long r7 = r9 + r2
                byte r12 = com.google.protobuf.UnsafeUtil.getByte(r11, r9)
                if (r12 <= r5) goto L98
                goto L9c
            L98:
                r12 = r7
            L99:
                goto L7
            L9b:
                r7 = r9
            L9c:
                return r6
            */
            throw new UnsupportedOperationException("Method not decompiled: com.google.protobuf.Utf8.UnsafeProcessor.partialIsValidUtf8(byte[], long, int):int");
        }

        /* JADX WARN: Code restructure failed: missing block: B:23:0x003b, code lost:
        
            return -1;
         */
        /* JADX WARN: Code restructure failed: missing block: B:42:0x0069, code lost:
        
            return -1;
         */
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        private static int partialIsValidUtf8(long r11, int r13) {
            /*
                int r0 = unsafeEstimateConsecutiveAscii(r11, r13)
                long r1 = (long) r0
                long r11 = r11 + r1
                int r13 = r13 - r0
            L7:
                r1 = 0
            L8:
                r2 = 1
                if (r13 <= 0) goto L1a
                long r4 = r11 + r2
                byte r11 = com.google.protobuf.UnsafeUtil.getByte(r11)
                r1 = r11
                if (r11 < 0) goto L19
                int r13 = r13 + (-1)
                r11 = r4
                goto L8
            L19:
                r11 = r4
            L1a:
                if (r13 != 0) goto L1e
                r2 = 0
                return r2
            L1e:
                int r13 = r13 + (-1)
                r4 = -32
                r5 = -65
                r6 = -1
                if (r1 >= r4) goto L3c
                if (r13 != 0) goto L2a
                return r1
            L2a:
                int r13 = r13 + (-1)
                r4 = -62
                if (r1 < r4) goto L3b
                long r2 = r2 + r11
                byte r11 = com.google.protobuf.UnsafeUtil.getByte(r11)
                if (r11 <= r5) goto L39
                r11 = r2
                goto L3b
            L39:
                r11 = r2
                goto L97
            L3b:
                return r6
            L3c:
                r7 = -16
                if (r1 >= r7) goto L6a
                r7 = 2
                if (r13 >= r7) goto L48
                int r2 = unsafeIncompleteStateFor(r11, r1, r13)
                return r2
            L48:
                int r13 = r13 + (-2)
                long r7 = r11 + r2
                byte r11 = com.google.protobuf.UnsafeUtil.getByte(r11)
                if (r11 > r5) goto L69
                r12 = -96
                if (r1 != r4) goto L58
                if (r11 < r12) goto L69
            L58:
                r4 = -19
                if (r1 != r4) goto L5e
                if (r11 >= r12) goto L69
            L5e:
                long r2 = r2 + r7
                byte r12 = com.google.protobuf.UnsafeUtil.getByte(r7)
                if (r12 <= r5) goto L67
                r7 = r2
                goto L69
            L67:
                r11 = r2
                goto L97
            L69:
                return r6
            L6a:
                r4 = 3
                if (r13 >= r4) goto L72
                int r2 = unsafeIncompleteStateFor(r11, r1, r13)
                return r2
            L72:
                int r13 = r13 + (-3)
                long r7 = r11 + r2
                byte r11 = com.google.protobuf.UnsafeUtil.getByte(r11)
                if (r11 > r5) goto L9a
                int r12 = r1 << 28
                int r4 = r11 + 112
                int r12 = r12 + r4
                int r12 = r12 >> 30
                if (r12 != 0) goto L9a
                long r9 = r7 + r2
                byte r12 = com.google.protobuf.UnsafeUtil.getByte(r7)
                if (r12 > r5) goto L99
                long r7 = r9 + r2
                byte r12 = com.google.protobuf.UnsafeUtil.getByte(r9)
                if (r12 <= r5) goto L96
                goto L9a
            L96:
                r11 = r7
            L97:
                goto L7
            L99:
                r7 = r9
            L9a:
                return r6
            */
            throw new UnsupportedOperationException("Method not decompiled: com.google.protobuf.Utf8.UnsafeProcessor.partialIsValidUtf8(long, int):int");
        }

        private static int unsafeIncompleteStateFor(byte[] bytes, int byte1, long offset, int remaining) {
            if (remaining == 0) {
                return Utf8.incompleteStateFor(byte1);
            }
            if (remaining == 1) {
                return Utf8.incompleteStateFor(byte1, UnsafeUtil.getByte(bytes, offset));
            }
            if (remaining == 2) {
                return Utf8.incompleteStateFor(byte1, UnsafeUtil.getByte(bytes, offset), UnsafeUtil.getByte(bytes, 1 + offset));
            }
            throw new AssertionError();
        }

        private static int unsafeIncompleteStateFor(long address, int byte1, int remaining) {
            if (remaining == 0) {
                return Utf8.incompleteStateFor(byte1);
            }
            if (remaining == 1) {
                return Utf8.incompleteStateFor(byte1, UnsafeUtil.getByte(address));
            }
            if (remaining == 2) {
                return Utf8.incompleteStateFor(byte1, UnsafeUtil.getByte(address), UnsafeUtil.getByte(1 + address));
            }
            throw new AssertionError();
        }
    }

    private Utf8() {
    }
}
