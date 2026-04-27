package com.google.android.exoplayer2.audio;

import com.google.android.exoplayer2.Format;
import com.google.android.exoplayer2.drm.DrmInitData;
import com.google.android.exoplayer2.extractor.ts.PsExtractor;
import com.google.android.exoplayer2.util.MimeTypes;
import com.google.android.exoplayer2.util.ParsableBitArray;
import com.google.android.exoplayer2.util.ParsableByteArray;
import im.uwrkaxlmjj.ui.utils.translate.common.AudioEditConstant;
import java.lang.annotation.Documented;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.nio.ByteBuffer;
import kotlin.UByte;

/* JADX INFO: loaded from: classes2.dex */
public final class Ac3Util {
    private static final int AC3_SYNCFRAME_AUDIO_SAMPLE_COUNT = 1536;
    private static final int AUDIO_SAMPLES_PER_AUDIO_BLOCK = 256;
    public static final int TRUEHD_RECHUNK_SAMPLE_COUNT = 16;
    public static final int TRUEHD_SYNCFRAME_PREFIX_LENGTH = 10;
    private static final int[] BLOCKS_PER_SYNCFRAME_BY_NUMBLKSCOD = {1, 2, 3, 6};
    private static final int[] SAMPLE_RATE_BY_FSCOD = {48000, 44100, 32000};
    private static final int[] SAMPLE_RATE_BY_FSCOD2 = {24000, 22050, AudioEditConstant.ExportSampleRate};
    private static final int[] CHANNEL_COUNT_BY_ACMOD = {2, 1, 2, 3, 3, 4, 4, 5};
    private static final int[] BITRATE_BY_HALF_FRMSIZECOD = {32, 40, 48, 56, 64, 80, 96, 112, 128, 160, PsExtractor.AUDIO_STREAM, 224, 256, 320, 384, 448, 512, 576, 640};
    private static final int[] SYNCFRAME_SIZE_WORDS_BY_HALF_FRMSIZECOD_44_1 = {69, 87, 104, 121, 139, 174, 208, 243, 278, 348, 417, 487, 557, 696, 835, 975, 1114, 1253, 1393};

    public static final class SyncFrameInfo {
        public static final int STREAM_TYPE_TYPE0 = 0;
        public static final int STREAM_TYPE_TYPE1 = 1;
        public static final int STREAM_TYPE_TYPE2 = 2;
        public static final int STREAM_TYPE_UNDEFINED = -1;
        public final int channelCount;
        public final int frameSize;
        public final String mimeType;
        public final int sampleCount;
        public final int sampleRate;
        public final int streamType;

        @Documented
        @Retention(RetentionPolicy.SOURCE)
        public @interface StreamType {
        }

        private SyncFrameInfo(String mimeType, int streamType, int channelCount, int sampleRate, int frameSize, int sampleCount) {
            this.mimeType = mimeType;
            this.streamType = streamType;
            this.channelCount = channelCount;
            this.sampleRate = sampleRate;
            this.frameSize = frameSize;
            this.sampleCount = sampleCount;
        }
    }

    public static Format parseAc3AnnexFFormat(ParsableByteArray data, String trackId, String language, DrmInitData drmInitData) {
        int channelCount;
        int fscod = (data.readUnsignedByte() & PsExtractor.AUDIO_STREAM) >> 6;
        int sampleRate = SAMPLE_RATE_BY_FSCOD[fscod];
        int nextByte = data.readUnsignedByte();
        int channelCount2 = CHANNEL_COUNT_BY_ACMOD[(nextByte & 56) >> 3];
        if ((nextByte & 4) == 0) {
            channelCount = channelCount2;
        } else {
            channelCount = channelCount2 + 1;
        }
        return Format.createAudioSampleFormat(trackId, MimeTypes.AUDIO_AC3, null, -1, -1, channelCount, sampleRate, null, drmInitData, 0, language);
    }

    /* JADX WARN: Removed duplicated region for block: B:10:0x003a  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static com.google.android.exoplayer2.Format parseEAc3AnnexFFormat(com.google.android.exoplayer2.util.ParsableByteArray r18, java.lang.String r19, java.lang.String r20, com.google.android.exoplayer2.drm.DrmInitData r21) {
        /*
            r0 = 2
            r1 = r18
            r1.skipBytes(r0)
            int r0 = r18.readUnsignedByte()
            r0 = r0 & 192(0xc0, float:2.69E-43)
            int r0 = r0 >> 6
            int[] r2 = com.google.android.exoplayer2.audio.Ac3Util.SAMPLE_RATE_BY_FSCOD
            r2 = r2[r0]
            int r3 = r18.readUnsignedByte()
            int[] r4 = com.google.android.exoplayer2.audio.Ac3Util.CHANNEL_COUNT_BY_ACMOD
            r5 = r3 & 14
            int r5 = r5 >> 1
            r4 = r4[r5]
            r5 = r3 & 1
            if (r5 == 0) goto L24
            int r4 = r4 + 1
        L24:
            int r3 = r18.readUnsignedByte()
            r5 = r3 & 30
            int r14 = r5 >> 1
            if (r14 <= 0) goto L3a
            int r5 = r18.readUnsignedByte()
            r6 = r5 & 2
            if (r6 == 0) goto L3a
            int r4 = r4 + 2
            r15 = r4
            goto L3b
        L3a:
            r15 = r4
        L3b:
            java.lang.String r4 = "audio/eac3"
            int r5 = r18.bytesLeft()
            if (r5 <= 0) goto L57
            int r3 = r18.readUnsignedByte()
            r5 = r3 & 1
            if (r5 == 0) goto L52
            java.lang.String r4 = "audio/eac3-joc"
            r16 = r3
            r17 = r4
            goto L5b
        L52:
            r16 = r3
            r17 = r4
            goto L5b
        L57:
            r16 = r3
            r17 = r4
        L5b:
            r5 = 0
            r6 = -1
            r7 = -1
            r10 = 0
            r12 = 0
            r3 = r19
            r4 = r17
            r8 = r15
            r9 = r2
            r11 = r21
            r13 = r20
            com.google.android.exoplayer2.Format r3 = com.google.android.exoplayer2.Format.createAudioSampleFormat(r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, r13)
            return r3
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.exoplayer2.audio.Ac3Util.parseEAc3AnnexFFormat(com.google.android.exoplayer2.util.ParsableByteArray, java.lang.String, java.lang.String, com.google.android.exoplayer2.drm.DrmInitData):com.google.android.exoplayer2.Format");
    }

    public static SyncFrameInfo parseAc3SyncframeInfo(ParsableBitArray parsableBitArray) {
        String str;
        int ac3SyncframeSize;
        int i;
        int i2;
        int i3;
        int i4;
        int bits;
        int i5;
        int i6;
        int i7;
        int i8;
        int i9;
        int i10;
        int position = parsableBitArray.getPosition();
        parsableBitArray.skipBits(40);
        boolean z = parsableBitArray.readBits(5) == 16;
        parsableBitArray.setPosition(position);
        int i11 = -1;
        if (z) {
            parsableBitArray.skipBits(16);
            int bits2 = parsableBitArray.readBits(2);
            if (bits2 == 0) {
                i11 = 0;
            } else if (bits2 == 1) {
                i11 = 1;
            } else if (bits2 == 2) {
                i11 = 2;
            } else {
                i11 = -1;
            }
            parsableBitArray.skipBits(3);
            ac3SyncframeSize = (parsableBitArray.readBits(11) + 1) * 2;
            int bits3 = parsableBitArray.readBits(2);
            if (bits3 == 3) {
                bits = 3;
                i2 = SAMPLE_RATE_BY_FSCOD2[parsableBitArray.readBits(2)];
                i5 = 6;
            } else {
                bits = parsableBitArray.readBits(2);
                i5 = BLOCKS_PER_SYNCFRAME_BY_NUMBLKSCOD[bits];
                i2 = SAMPLE_RATE_BY_FSCOD[bits3];
            }
            i3 = i5 * 256;
            int bits4 = parsableBitArray.readBits(3);
            boolean bit = parsableBitArray.readBit();
            i4 = CHANNEL_COUNT_BY_ACMOD[bits4] + (bit ? 1 : 0);
            parsableBitArray.skipBits(10);
            if (parsableBitArray.readBit()) {
                parsableBitArray.skipBits(8);
            }
            if (bits4 == 0) {
                parsableBitArray.skipBits(5);
                if (parsableBitArray.readBit()) {
                    parsableBitArray.skipBits(8);
                }
            }
            if (i11 == 1 && parsableBitArray.readBit()) {
                parsableBitArray.skipBits(16);
            }
            if (parsableBitArray.readBit()) {
                if (bits4 > 2) {
                    parsableBitArray.skipBits(2);
                }
                if ((bits4 & 1) == 0 || bits4 <= 2) {
                    i9 = 6;
                } else {
                    i9 = 6;
                    parsableBitArray.skipBits(6);
                }
                if ((bits4 & 4) != 0) {
                    parsableBitArray.skipBits(i9);
                }
                if (bit && parsableBitArray.readBit()) {
                    parsableBitArray.skipBits(5);
                }
                if (i11 == 0) {
                    if (!parsableBitArray.readBit()) {
                        i10 = 6;
                    } else {
                        i10 = 6;
                        parsableBitArray.skipBits(6);
                    }
                    if (bits4 == 0 && parsableBitArray.readBit()) {
                        parsableBitArray.skipBits(i10);
                    }
                    if (parsableBitArray.readBit()) {
                        parsableBitArray.skipBits(i10);
                    }
                    int bits5 = parsableBitArray.readBits(2);
                    if (bits5 == 1) {
                        parsableBitArray.skipBits(5);
                    } else if (bits5 == 2) {
                        parsableBitArray.skipBits(12);
                    } else if (bits5 == 3) {
                        int bits6 = parsableBitArray.readBits(5);
                        if (parsableBitArray.readBit()) {
                            parsableBitArray.skipBits(5);
                            if (parsableBitArray.readBit()) {
                                parsableBitArray.skipBits(4);
                            }
                            if (parsableBitArray.readBit()) {
                                parsableBitArray.skipBits(4);
                            }
                            if (parsableBitArray.readBit()) {
                                parsableBitArray.skipBits(4);
                            }
                            if (parsableBitArray.readBit()) {
                                parsableBitArray.skipBits(4);
                            }
                            if (parsableBitArray.readBit()) {
                                parsableBitArray.skipBits(4);
                            }
                            if (parsableBitArray.readBit()) {
                                parsableBitArray.skipBits(4);
                            }
                            if (parsableBitArray.readBit()) {
                                parsableBitArray.skipBits(4);
                            }
                            if (parsableBitArray.readBit()) {
                                if (parsableBitArray.readBit()) {
                                    parsableBitArray.skipBits(4);
                                }
                                if (parsableBitArray.readBit()) {
                                    parsableBitArray.skipBits(4);
                                }
                            }
                        }
                        if (parsableBitArray.readBit()) {
                            parsableBitArray.skipBits(5);
                            if (parsableBitArray.readBit()) {
                                parsableBitArray.skipBits(7);
                                if (parsableBitArray.readBit()) {
                                    parsableBitArray.skipBits(8);
                                }
                            }
                        }
                        parsableBitArray.skipBits((bits6 + 2) * 8);
                        parsableBitArray.byteAlign();
                    }
                    if (bits4 < 2) {
                        if (parsableBitArray.readBit()) {
                            parsableBitArray.skipBits(14);
                        }
                        if (bits4 == 0 && parsableBitArray.readBit()) {
                            parsableBitArray.skipBits(14);
                        }
                    }
                    if (parsableBitArray.readBit()) {
                        if (bits == 0) {
                            parsableBitArray.skipBits(5);
                        } else {
                            for (int i12 = 0; i12 < i5; i12++) {
                                if (parsableBitArray.readBit()) {
                                    parsableBitArray.skipBits(5);
                                }
                            }
                        }
                    }
                }
            }
            if (!parsableBitArray.readBit()) {
                i6 = 3;
            } else {
                parsableBitArray.skipBits(5);
                if (bits4 == 2) {
                    parsableBitArray.skipBits(4);
                }
                if (bits4 >= 6) {
                    parsableBitArray.skipBits(2);
                }
                if (!parsableBitArray.readBit()) {
                    i8 = 8;
                } else {
                    i8 = 8;
                    parsableBitArray.skipBits(8);
                }
                if (bits4 == 0 && parsableBitArray.readBit()) {
                    parsableBitArray.skipBits(i8);
                }
                i6 = 3;
                if (bits3 < 3) {
                    parsableBitArray.skipBit();
                }
            }
            if (i11 == 0 && bits != i6) {
                parsableBitArray.skipBit();
            }
            if (i11 != 2) {
                i7 = 6;
            } else if (bits == i6 || parsableBitArray.readBit()) {
                i7 = 6;
                parsableBitArray.skipBits(6);
            } else {
                i7 = 6;
            }
            str = MimeTypes.AUDIO_E_AC3;
            if (parsableBitArray.readBit() && parsableBitArray.readBits(i7) == 1 && parsableBitArray.readBits(8) == 1) {
                str = MimeTypes.AUDIO_E_AC3_JOC;
            }
        } else {
            str = MimeTypes.AUDIO_AC3;
            parsableBitArray.skipBits(32);
            int bits7 = parsableBitArray.readBits(2);
            ac3SyncframeSize = getAc3SyncframeSize(bits7, parsableBitArray.readBits(6));
            parsableBitArray.skipBits(8);
            int bits8 = parsableBitArray.readBits(3);
            if ((bits8 & 1) == 0 || bits8 == 1) {
                i = 2;
            } else {
                i = 2;
                parsableBitArray.skipBits(2);
            }
            if ((bits8 & 4) != 0) {
                parsableBitArray.skipBits(i);
            }
            if (bits8 == i) {
                parsableBitArray.skipBits(i);
            }
            i2 = SAMPLE_RATE_BY_FSCOD[bits7];
            i3 = AC3_SYNCFRAME_AUDIO_SAMPLE_COUNT;
            i4 = CHANNEL_COUNT_BY_ACMOD[bits8] + (parsableBitArray.readBit() ? 1 : 0);
        }
        return new SyncFrameInfo(str, i11, i4, i2, ac3SyncframeSize, i3);
    }

    public static int parseAc3SyncframeSize(byte[] data) {
        if (data.length < 6) {
            return -1;
        }
        boolean isEac3 = ((data[5] & UByte.MAX_VALUE) >> 3) == 16;
        if (isEac3) {
            int frmsiz = (data[2] & 7) << 8;
            return (((data[3] & UByte.MAX_VALUE) | frmsiz) + 1) * 2;
        }
        int fscod = (data[4] & 192) >> 6;
        int frmsizecod = data[4] & 63;
        return getAc3SyncframeSize(fscod, frmsizecod);
    }

    public static int getAc3SyncframeAudioSampleCount() {
        return AC3_SYNCFRAME_AUDIO_SAMPLE_COUNT;
    }

    public static int parseEAc3SyncframeAudioSampleCount(ByteBuffer buffer) {
        int fscod = (buffer.get(buffer.position() + 4) & 192) >> 6;
        return (fscod != 3 ? BLOCKS_PER_SYNCFRAME_BY_NUMBLKSCOD[(buffer.get(buffer.position() + 4) & 48) >> 4] : 6) * 256;
    }

    public static int findTrueHdSyncframeOffset(ByteBuffer buffer) {
        int startIndex = buffer.position();
        int endIndex = buffer.limit() - 10;
        for (int i = startIndex; i <= endIndex; i++) {
            if ((buffer.getInt(i + 4) & (-16777217)) == -1167101192) {
                return i - startIndex;
            }
        }
        return -1;
    }

    public static int parseTrueHdSyncframeAudioSampleCount(byte[] syncframe) {
        if (syncframe[4] != -8 || syncframe[5] != 114 || syncframe[6] != 111 || (syncframe[7] & 254) != 186) {
            return 0;
        }
        boolean isMlp = (syncframe[7] & UByte.MAX_VALUE) == 187;
        return 40 << ((syncframe[isMlp ? '\t' : '\b'] >> 4) & 7);
    }

    public static int parseTrueHdSyncframeAudioSampleCount(ByteBuffer buffer, int offset) {
        boolean isMlp = (buffer.get((buffer.position() + offset) + 7) & UByte.MAX_VALUE) == 187;
        return 40 << ((buffer.get((buffer.position() + offset) + (isMlp ? 9 : 8)) >> 4) & 7);
    }

    private static int getAc3SyncframeSize(int fscod, int frmsizecod) {
        int halfFrmsizecod = frmsizecod / 2;
        if (fscod < 0) {
            return -1;
        }
        int[] iArr = SAMPLE_RATE_BY_FSCOD;
        if (fscod >= iArr.length || frmsizecod < 0) {
            return -1;
        }
        int[] iArr2 = SYNCFRAME_SIZE_WORDS_BY_HALF_FRMSIZECOD_44_1;
        if (halfFrmsizecod >= iArr2.length) {
            return -1;
        }
        int sampleRate = iArr[fscod];
        if (sampleRate == 44100) {
            return (iArr2[halfFrmsizecod] + (frmsizecod % 2)) * 2;
        }
        int bitrate = BITRATE_BY_HALF_FRMSIZECOD[halfFrmsizecod];
        if (sampleRate == 32000) {
            return bitrate * 6;
        }
        return bitrate * 4;
    }

    private Ac3Util() {
    }
}
