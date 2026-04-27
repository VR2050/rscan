package com.google.android.exoplayer2.extractor.ts;

import android.util.Pair;
import com.google.android.exoplayer2.Format;
import com.google.android.exoplayer2.ParserException;
import com.google.android.exoplayer2.extractor.ExtractorOutput;
import com.google.android.exoplayer2.extractor.TrackOutput;
import com.google.android.exoplayer2.extractor.ts.TsPayloadReader;
import com.google.android.exoplayer2.util.CodecSpecificDataUtil;
import com.google.android.exoplayer2.util.MimeTypes;
import com.google.android.exoplayer2.util.ParsableBitArray;
import com.google.android.exoplayer2.util.ParsableByteArray;
import java.util.Collections;

/* JADX INFO: loaded from: classes2.dex */
public final class LatmReader implements ElementaryStreamReader {
    private static final int INITIAL_BUFFER_SIZE = 1024;
    private static final int STATE_FINDING_SYNC_1 = 0;
    private static final int STATE_FINDING_SYNC_2 = 1;
    private static final int STATE_READING_HEADER = 2;
    private static final int STATE_READING_SAMPLE = 3;
    private static final int SYNC_BYTE_FIRST = 86;
    private static final int SYNC_BYTE_SECOND = 224;
    private int audioMuxVersionA;
    private int bytesRead;
    private int channelCount;
    private Format format;
    private String formatId;
    private int frameLengthType;
    private final String language;
    private int numSubframes;
    private long otherDataLenBits;
    private boolean otherDataPresent;
    private TrackOutput output;
    private final ParsableBitArray sampleBitArray;
    private final ParsableByteArray sampleDataBuffer;
    private long sampleDurationUs;
    private int sampleRateHz;
    private int sampleSize;
    private int secondHeaderByte;
    private int state;
    private boolean streamMuxRead;
    private long timeUs;

    public LatmReader(String language) {
        this.language = language;
        ParsableByteArray parsableByteArray = new ParsableByteArray(1024);
        this.sampleDataBuffer = parsableByteArray;
        this.sampleBitArray = new ParsableBitArray(parsableByteArray.data);
    }

    @Override // com.google.android.exoplayer2.extractor.ts.ElementaryStreamReader
    public void seek() {
        this.state = 0;
        this.streamMuxRead = false;
    }

    @Override // com.google.android.exoplayer2.extractor.ts.ElementaryStreamReader
    public void createTracks(ExtractorOutput extractorOutput, TsPayloadReader.TrackIdGenerator idGenerator) {
        idGenerator.generateNewId();
        this.output = extractorOutput.track(idGenerator.getTrackId(), 1);
        this.formatId = idGenerator.getFormatId();
    }

    @Override // com.google.android.exoplayer2.extractor.ts.ElementaryStreamReader
    public void packetStarted(long pesTimeUs, int flags) {
        this.timeUs = pesTimeUs;
    }

    @Override // com.google.android.exoplayer2.extractor.ts.ElementaryStreamReader
    public void consume(ParsableByteArray data) throws ParserException {
        while (data.bytesLeft() > 0) {
            int i = this.state;
            if (i != 0) {
                if (i == 1) {
                    int secondByte = data.readUnsignedByte();
                    if ((secondByte & 224) == 224) {
                        this.secondHeaderByte = secondByte;
                        this.state = 2;
                    } else if (secondByte != 86) {
                        this.state = 0;
                    }
                } else if (i == 2) {
                    int unsignedByte = ((this.secondHeaderByte & (-225)) << 8) | data.readUnsignedByte();
                    this.sampleSize = unsignedByte;
                    if (unsignedByte > this.sampleDataBuffer.data.length) {
                        resetBufferForSize(this.sampleSize);
                    }
                    this.bytesRead = 0;
                    this.state = 3;
                } else if (i == 3) {
                    int bytesToRead = Math.min(data.bytesLeft(), this.sampleSize - this.bytesRead);
                    data.readBytes(this.sampleBitArray.data, this.bytesRead, bytesToRead);
                    int i2 = this.bytesRead + bytesToRead;
                    this.bytesRead = i2;
                    if (i2 == this.sampleSize) {
                        this.sampleBitArray.setPosition(0);
                        parseAudioMuxElement(this.sampleBitArray);
                        this.state = 0;
                    }
                } else {
                    throw new IllegalStateException();
                }
            } else if (data.readUnsignedByte() == 86) {
                this.state = 1;
            }
        }
    }

    @Override // com.google.android.exoplayer2.extractor.ts.ElementaryStreamReader
    public void packetFinished() {
    }

    private void parseAudioMuxElement(ParsableBitArray data) throws ParserException {
        boolean useSameStreamMux = data.readBit();
        if (!useSameStreamMux) {
            this.streamMuxRead = true;
            parseStreamMuxConfig(data);
        } else if (!this.streamMuxRead) {
            return;
        }
        if (this.audioMuxVersionA == 0) {
            if (this.numSubframes != 0) {
                throw new ParserException();
            }
            int muxSlotLengthBytes = parsePayloadLengthInfo(data);
            parsePayloadMux(data, muxSlotLengthBytes);
            if (this.otherDataPresent) {
                data.skipBits((int) this.otherDataLenBits);
                return;
            }
            return;
        }
        throw new ParserException();
    }

    private void parseStreamMuxConfig(ParsableBitArray data) throws ParserException {
        boolean otherDataLenEsc;
        int audioMuxVersion = data.readBits(1);
        int bits = audioMuxVersion == 1 ? data.readBits(1) : 0;
        this.audioMuxVersionA = bits;
        if (bits == 0) {
            if (audioMuxVersion == 1) {
                latmGetValue(data);
            }
            if (data.readBit()) {
                this.numSubframes = data.readBits(6);
                int numProgram = data.readBits(4);
                int numLayer = data.readBits(3);
                if (numProgram != 0 || numLayer != 0) {
                    throw new ParserException();
                }
                if (audioMuxVersion == 0) {
                    int startPosition = data.getPosition();
                    int readBits = parseAudioSpecificConfig(data);
                    data.setPosition(startPosition);
                    byte[] initData = new byte[(readBits + 7) / 8];
                    data.readBits(initData, 0, readBits);
                    Format format = Format.createAudioSampleFormat(this.formatId, MimeTypes.AUDIO_AAC, null, -1, -1, this.channelCount, this.sampleRateHz, Collections.singletonList(initData), null, 0, this.language);
                    if (!format.equals(this.format)) {
                        this.format = format;
                        this.sampleDurationUs = 1024000000 / ((long) format.sampleRate);
                        this.output.format(format);
                    }
                } else {
                    int ascLen = (int) latmGetValue(data);
                    int bitsRead = parseAudioSpecificConfig(data);
                    data.skipBits(ascLen - bitsRead);
                }
                parseFrameLength(data);
                boolean bit = data.readBit();
                this.otherDataPresent = bit;
                this.otherDataLenBits = 0L;
                if (bit) {
                    if (audioMuxVersion == 1) {
                        this.otherDataLenBits = latmGetValue(data);
                    } else {
                        do {
                            otherDataLenEsc = data.readBit();
                            this.otherDataLenBits = (this.otherDataLenBits << 8) + ((long) data.readBits(8));
                        } while (otherDataLenEsc);
                    }
                }
                boolean crcCheckPresent = data.readBit();
                if (crcCheckPresent) {
                    data.skipBits(8);
                    return;
                }
                return;
            }
            throw new ParserException();
        }
        throw new ParserException();
    }

    private void parseFrameLength(ParsableBitArray data) {
        int bits = data.readBits(3);
        this.frameLengthType = bits;
        if (bits == 0) {
            data.skipBits(8);
            return;
        }
        if (bits != 1) {
            if (bits == 3 || bits == 4 || bits == 5) {
                data.skipBits(6);
                return;
            } else {
                if (bits == 6 || bits == 7) {
                    data.skipBits(1);
                    return;
                }
                throw new IllegalStateException();
            }
        }
        data.skipBits(9);
    }

    private int parseAudioSpecificConfig(ParsableBitArray data) throws ParserException {
        int bitsLeft = data.bitsLeft();
        Pair<Integer, Integer> config = CodecSpecificDataUtil.parseAacAudioSpecificConfig(data, true);
        this.sampleRateHz = ((Integer) config.first).intValue();
        this.channelCount = ((Integer) config.second).intValue();
        return bitsLeft - data.bitsLeft();
    }

    private int parsePayloadLengthInfo(ParsableBitArray data) throws ParserException {
        int tmp;
        int muxSlotLengthBytes = 0;
        if (this.frameLengthType == 0) {
            do {
                tmp = data.readBits(8);
                muxSlotLengthBytes += tmp;
            } while (tmp == 255);
            return muxSlotLengthBytes;
        }
        throw new ParserException();
    }

    private void parsePayloadMux(ParsableBitArray data, int muxLengthBytes) {
        int bitPosition = data.getPosition();
        if ((bitPosition & 7) == 0) {
            this.sampleDataBuffer.setPosition(bitPosition >> 3);
        } else {
            data.readBits(this.sampleDataBuffer.data, 0, muxLengthBytes * 8);
            this.sampleDataBuffer.setPosition(0);
        }
        this.output.sampleData(this.sampleDataBuffer, muxLengthBytes);
        this.output.sampleMetadata(this.timeUs, 1, muxLengthBytes, 0, null);
        this.timeUs += this.sampleDurationUs;
    }

    private void resetBufferForSize(int newSize) {
        this.sampleDataBuffer.reset(newSize);
        this.sampleBitArray.reset(this.sampleDataBuffer.data);
    }

    private static long latmGetValue(ParsableBitArray data) {
        int bytesForValue = data.readBits(2);
        return data.readBits((bytesForValue + 1) * 8);
    }
}
