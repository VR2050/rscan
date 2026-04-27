package com.google.android.exoplayer2.extractor.ogg;

import com.google.android.exoplayer2.Format;
import com.google.android.exoplayer2.extractor.ogg.StreamReader;
import com.google.android.exoplayer2.util.MimeTypes;
import com.google.android.exoplayer2.util.ParsableByteArray;
import com.google.android.exoplayer2.util.Util;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import kotlin.UByte;

/* JADX INFO: loaded from: classes2.dex */
final class OpusReader extends StreamReader {
    private static final int DEFAULT_SEEK_PRE_ROLL_SAMPLES = 3840;
    private static final int OPUS_CODE = Util.getIntegerCodeForString("Opus");
    private static final byte[] OPUS_SIGNATURE = {79, 112, 117, 115, 72, 101, 97, 100};
    private static final int SAMPLE_RATE = 48000;
    private boolean headerRead;

    OpusReader() {
    }

    public static boolean verifyBitstreamType(ParsableByteArray data) {
        int iBytesLeft = data.bytesLeft();
        byte[] bArr = OPUS_SIGNATURE;
        if (iBytesLeft < bArr.length) {
            return false;
        }
        byte[] header = new byte[bArr.length];
        data.readBytes(header, 0, bArr.length);
        return Arrays.equals(header, OPUS_SIGNATURE);
    }

    @Override // com.google.android.exoplayer2.extractor.ogg.StreamReader
    protected void reset(boolean headerData) {
        super.reset(headerData);
        if (headerData) {
            this.headerRead = false;
        }
    }

    @Override // com.google.android.exoplayer2.extractor.ogg.StreamReader
    protected long preparePayload(ParsableByteArray packet) {
        return convertTimeToGranule(getPacketDurationUs(packet.data));
    }

    @Override // com.google.android.exoplayer2.extractor.ogg.StreamReader
    protected boolean readHeaders(ParsableByteArray packet, long position, StreamReader.SetupData setupData) {
        if (!this.headerRead) {
            byte[] metadata = Arrays.copyOf(packet.data, packet.limit());
            int channelCount = metadata[9] & UByte.MAX_VALUE;
            int preskip = ((metadata[11] & UByte.MAX_VALUE) << 8) | (metadata[10] & UByte.MAX_VALUE);
            List<byte[]> initializationData = new ArrayList<>(3);
            initializationData.add(metadata);
            putNativeOrderLong(initializationData, preskip);
            putNativeOrderLong(initializationData, DEFAULT_SEEK_PRE_ROLL_SAMPLES);
            setupData.format = Format.createAudioSampleFormat(null, MimeTypes.AUDIO_OPUS, null, -1, -1, channelCount, SAMPLE_RATE, initializationData, null, 0, null);
            this.headerRead = true;
            return true;
        }
        boolean headerPacket = packet.readInt() == OPUS_CODE;
        packet.setPosition(0);
        return headerPacket;
    }

    private void putNativeOrderLong(List<byte[]> initializationData, int samples) {
        long ns = (((long) samples) * 1000000000) / 48000;
        byte[] array = ByteBuffer.allocate(8).order(ByteOrder.nativeOrder()).putLong(ns).array();
        initializationData.add(array);
    }

    private long getPacketDurationUs(byte[] packet) {
        int frames;
        int length;
        int toc = packet[0] & UByte.MAX_VALUE;
        int i = toc & 3;
        if (i == 0) {
            frames = 1;
        } else if (i == 1 || i == 2) {
            frames = 2;
        } else {
            frames = packet[1] & 63;
        }
        int config = toc >> 3;
        int length2 = config & 3;
        if (config >= 16) {
            length = 2500 << length2;
        } else if (config >= 12) {
            length = 10000 << (length2 & 1);
        } else if (length2 == 3) {
            length = 60000;
        } else {
            length = 10000 << length2;
        }
        return ((long) frames) * ((long) length);
    }
}
