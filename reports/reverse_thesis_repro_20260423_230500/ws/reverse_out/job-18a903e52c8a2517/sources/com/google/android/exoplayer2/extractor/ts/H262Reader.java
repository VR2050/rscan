package com.google.android.exoplayer2.extractor.ts;

import android.util.Pair;
import com.google.android.exoplayer2.C;
import com.google.android.exoplayer2.Format;
import com.google.android.exoplayer2.extractor.ExtractorOutput;
import com.google.android.exoplayer2.extractor.TrackOutput;
import com.google.android.exoplayer2.extractor.ts.TsPayloadReader;
import com.google.android.exoplayer2.util.NalUnitUtil;
import com.google.android.exoplayer2.util.ParsableByteArray;
import java.util.Arrays;
import kotlin.UByte;

/* JADX INFO: loaded from: classes2.dex */
public final class H262Reader implements ElementaryStreamReader {
    private static final double[] FRAME_RATE_VALUES = {23.976023976023978d, 24.0d, 25.0d, 29.97002997002997d, 30.0d, 50.0d, 59.94005994005994d, 60.0d};
    private static final int START_EXTENSION = 181;
    private static final int START_GROUP = 184;
    private static final int START_PICTURE = 0;
    private static final int START_SEQUENCE_HEADER = 179;
    private static final int START_USER_DATA = 178;
    private final CsdBuffer csdBuffer;
    private String formatId;
    private long frameDurationUs;
    private boolean hasOutputFormat;
    private TrackOutput output;
    private long pesTimeUs;
    private final boolean[] prefixFlags;
    private boolean sampleHasPicture;
    private boolean sampleIsKeyframe;
    private long samplePosition;
    private long sampleTimeUs;
    private boolean startedFirstSample;
    private long totalBytesWritten;
    private final NalUnitTargetBuffer userData;
    private final ParsableByteArray userDataParsable;
    private final UserDataReader userDataReader;

    public H262Reader() {
        this(null);
    }

    public H262Reader(UserDataReader userDataReader) {
        this.userDataReader = userDataReader;
        this.prefixFlags = new boolean[4];
        this.csdBuffer = new CsdBuffer(128);
        if (userDataReader != null) {
            this.userData = new NalUnitTargetBuffer(START_USER_DATA, 128);
            this.userDataParsable = new ParsableByteArray();
        } else {
            this.userData = null;
            this.userDataParsable = null;
        }
    }

    @Override // com.google.android.exoplayer2.extractor.ts.ElementaryStreamReader
    public void seek() {
        NalUnitUtil.clearPrefixFlags(this.prefixFlags);
        this.csdBuffer.reset();
        if (this.userDataReader != null) {
            this.userData.reset();
        }
        this.totalBytesWritten = 0L;
        this.startedFirstSample = false;
    }

    @Override // com.google.android.exoplayer2.extractor.ts.ElementaryStreamReader
    public void createTracks(ExtractorOutput extractorOutput, TsPayloadReader.TrackIdGenerator idGenerator) {
        idGenerator.generateNewId();
        this.formatId = idGenerator.getFormatId();
        this.output = extractorOutput.track(idGenerator.getTrackId(), 2);
        UserDataReader userDataReader = this.userDataReader;
        if (userDataReader != null) {
            userDataReader.createTracks(extractorOutput, idGenerator);
        }
    }

    @Override // com.google.android.exoplayer2.extractor.ts.ElementaryStreamReader
    public void packetStarted(long pesTimeUs, int flags) {
        this.pesTimeUs = pesTimeUs;
    }

    /* JADX WARN: Type inference fix 'apply assigned field type' failed
    java.lang.UnsupportedOperationException: ArgType.getObject(), call class: class jadx.core.dex.instructions.args.ArgType$PrimitiveArg
    	at jadx.core.dex.instructions.args.ArgType.getObject(ArgType.java:593)
    	at jadx.core.dex.attributes.nodes.ClassTypeVarsAttr.getTypeVarsMapFor(ClassTypeVarsAttr.java:35)
    	at jadx.core.dex.nodes.utils.TypeUtils.replaceClassGenerics(TypeUtils.java:177)
    	at jadx.core.dex.visitors.typeinference.FixTypesVisitor.insertExplicitUseCast(FixTypesVisitor.java:397)
    	at jadx.core.dex.visitors.typeinference.FixTypesVisitor.tryFieldTypeWithNewCasts(FixTypesVisitor.java:359)
    	at jadx.core.dex.visitors.typeinference.FixTypesVisitor.applyFieldType(FixTypesVisitor.java:309)
    	at jadx.core.dex.visitors.typeinference.FixTypesVisitor.visit(FixTypesVisitor.java:94)
     */
    @Override // com.google.android.exoplayer2.extractor.ts.ElementaryStreamReader
    public void consume(ParsableByteArray parsableByteArray) {
        boolean z;
        int position = parsableByteArray.getPosition();
        int iLimit = parsableByteArray.limit();
        byte[] bArr = parsableByteArray.data;
        this.totalBytesWritten += (long) parsableByteArray.bytesLeft();
        this.output.sampleData(parsableByteArray, parsableByteArray.bytesLeft());
        while (true) {
            int iFindNalUnit = NalUnitUtil.findNalUnit(bArr, position, iLimit, this.prefixFlags);
            if (iFindNalUnit == iLimit) {
                break;
            }
            int i = parsableByteArray.data[iFindNalUnit + 3] & UByte.MAX_VALUE;
            int i2 = iFindNalUnit - position;
            if (!this.hasOutputFormat) {
                if (i2 > 0) {
                    this.csdBuffer.onData(bArr, position, iFindNalUnit);
                }
                if (this.csdBuffer.onStartCode(i, i2 < 0 ? -i2 : 0)) {
                    Pair<Format, Long> csdBuffer = parseCsdBuffer(this.csdBuffer, this.formatId);
                    this.output.format((Format) csdBuffer.first);
                    this.frameDurationUs = ((Long) csdBuffer.second).longValue();
                    this.hasOutputFormat = true;
                }
            }
            if (this.userDataReader != null) {
                int i3 = 0;
                if (i2 > 0) {
                    this.userData.appendToNalUnit(bArr, position, iFindNalUnit);
                } else {
                    i3 = -i2;
                }
                if (this.userData.endNalUnit(i3)) {
                    this.userDataParsable.reset(this.userData.nalData, NalUnitUtil.unescapeStream(this.userData.nalData, this.userData.nalLength));
                    this.userDataReader.consume(this.sampleTimeUs, this.userDataParsable);
                }
                if (i == START_USER_DATA && parsableByteArray.data[iFindNalUnit + 2] == 1) {
                    this.userData.startNalUnit(i);
                }
            }
            if (i == 0 || i == START_SEQUENCE_HEADER) {
                int i4 = iLimit - iFindNalUnit;
                if (this.startedFirstSample && this.sampleHasPicture && this.hasOutputFormat) {
                    this.output.sampleMetadata(this.sampleTimeUs, this.sampleIsKeyframe ? 1 : 0, ((int) (this.totalBytesWritten - this.samplePosition)) - i4, i4, null);
                }
                if (!this.startedFirstSample || this.sampleHasPicture) {
                    this.samplePosition = this.totalBytesWritten - ((long) i4);
                    long j = this.pesTimeUs;
                    if (j == C.TIME_UNSET) {
                        j = this.startedFirstSample ? this.sampleTimeUs + this.frameDurationUs : 0L;
                    }
                    this.sampleTimeUs = j;
                    z = false;
                    this.sampleIsKeyframe = false;
                    this.pesTimeUs = C.TIME_UNSET;
                    this.startedFirstSample = true;
                } else {
                    z = false;
                }
                if (i == 0) {
                    z = true;
                }
                this.sampleHasPicture = z;
            } else if (i == START_GROUP) {
                this.sampleIsKeyframe = true;
            }
            position = iFindNalUnit + 3;
        }
        if (!this.hasOutputFormat) {
            this.csdBuffer.onData(bArr, position, iLimit);
        }
        if (this.userDataReader != null) {
            this.userData.appendToNalUnit(bArr, position, iLimit);
        }
    }

    @Override // com.google.android.exoplayer2.extractor.ts.ElementaryStreamReader
    public void packetFinished() {
    }

    /* JADX WARN: Removed duplicated region for block: B:20:0x00b6  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private static android.util.Pair<com.google.android.exoplayer2.Format, java.lang.Long> parseCsdBuffer(com.google.android.exoplayer2.extractor.ts.H262Reader.CsdBuffer r23, java.lang.String r24) {
        /*
            r0 = r23
            byte[] r1 = r0.data
            int r2 = r0.length
            byte[] r1 = java.util.Arrays.copyOf(r1, r2)
            r2 = 4
            r3 = r1[r2]
            r3 = r3 & 255(0xff, float:3.57E-43)
            r4 = 5
            r5 = r1[r4]
            r5 = r5 & 255(0xff, float:3.57E-43)
            r6 = 6
            r6 = r1[r6]
            r6 = r6 & 255(0xff, float:3.57E-43)
            int r7 = r3 << 4
            int r8 = r5 >> 4
            r7 = r7 | r8
            r8 = r5 & 15
            int r8 = r8 << 8
            r8 = r8 | r6
            r9 = 1065353216(0x3f800000, float:1.0)
            r21 = 7
            r10 = r1[r21]
            r10 = r10 & 240(0xf0, float:3.36E-43)
            int r15 = r10 >> 4
            r10 = 2
            if (r15 == r10) goto L4b
            r10 = 3
            if (r15 == r10) goto L41
            if (r15 == r2) goto L37
            r2 = r9
            goto L54
        L37:
            int r2 = r8 * 121
            float r2 = (float) r2
            int r10 = r7 * 100
            float r10 = (float) r10
            float r9 = r2 / r10
            r2 = r9
            goto L54
        L41:
            int r2 = r8 * 16
            float r2 = (float) r2
            int r10 = r7 * 9
            float r10 = (float) r10
            float r9 = r2 / r10
            r2 = r9
            goto L54
        L4b:
            int r2 = r8 * 4
            float r2 = (float) r2
            int r10 = r7 * 3
            float r10 = (float) r10
            float r9 = r2 / r10
            r2 = r9
        L54:
            r11 = 0
            r12 = -1
            r13 = -1
            r16 = -1082130432(0xffffffffbf800000, float:-1.0)
            java.util.List r17 = java.util.Collections.singletonList(r1)
            r18 = -1
            r20 = 0
            java.lang.String r10 = "video/mpeg2"
            r9 = r24
            r14 = r7
            r22 = r15
            r15 = r8
            r19 = r2
            com.google.android.exoplayer2.Format r9 = com.google.android.exoplayer2.Format.createVideoSampleFormat(r9, r10, r11, r12, r13, r14, r15, r16, r17, r18, r19, r20)
            r10 = 0
            r12 = r1[r21]
            r12 = r12 & 15
            int r12 = r12 + (-1)
            if (r12 < 0) goto Lb6
            double[] r13 = com.google.android.exoplayer2.extractor.ts.H262Reader.FRAME_RATE_VALUES
            int r14 = r13.length
            if (r12 >= r14) goto Lb6
            r14 = r13[r12]
            int r13 = r0.sequenceExtensionPosition
            int r16 = r13 + 9
            r16 = r1[r16]
            r16 = r16 & 96
            int r4 = r16 >> 5
            int r16 = r13 + 9
            r16 = r1[r16]
            r0 = r16 & 31
            if (r4 == r0) goto La6
            r16 = r1
            r17 = r2
            double r1 = (double) r4
            r18 = 4607182418800017408(0x3ff0000000000000, double:1.0)
            double r1 = r1 + r18
            r18 = r3
            int r3 = r0 + 1
            r19 = r4
            double r3 = (double) r3
            double r1 = r1 / r3
            double r14 = r14 * r1
            goto Lae
        La6:
            r16 = r1
            r17 = r2
            r18 = r3
            r19 = r4
        Lae:
            r1 = 4696837146684686336(0x412e848000000000, double:1000000.0)
            double r1 = r1 / r14
            long r10 = (long) r1
            goto Lbc
        Lb6:
            r16 = r1
            r17 = r2
            r18 = r3
        Lbc:
            java.lang.Long r0 = java.lang.Long.valueOf(r10)
            android.util.Pair r0 = android.util.Pair.create(r9, r0)
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.exoplayer2.extractor.ts.H262Reader.parseCsdBuffer(com.google.android.exoplayer2.extractor.ts.H262Reader$CsdBuffer, java.lang.String):android.util.Pair");
    }

    private static final class CsdBuffer {
        private static final byte[] START_CODE = {0, 0, 1};
        public byte[] data;
        private boolean isFilling;
        public int length;
        public int sequenceExtensionPosition;

        public CsdBuffer(int initialCapacity) {
            this.data = new byte[initialCapacity];
        }

        public void reset() {
            this.isFilling = false;
            this.length = 0;
            this.sequenceExtensionPosition = 0;
        }

        public boolean onStartCode(int startCodeValue, int bytesAlreadyPassed) {
            if (this.isFilling) {
                int i = this.length - bytesAlreadyPassed;
                this.length = i;
                if (this.sequenceExtensionPosition == 0 && startCodeValue == H262Reader.START_EXTENSION) {
                    this.sequenceExtensionPosition = i;
                } else {
                    this.isFilling = false;
                    return true;
                }
            } else if (startCodeValue == H262Reader.START_SEQUENCE_HEADER) {
                this.isFilling = true;
            }
            byte[] bArr = START_CODE;
            onData(bArr, 0, bArr.length);
            return false;
        }

        public void onData(byte[] newData, int offset, int limit) {
            if (!this.isFilling) {
                return;
            }
            int readLength = limit - offset;
            byte[] bArr = this.data;
            int length = bArr.length;
            int i = this.length;
            if (length < i + readLength) {
                this.data = Arrays.copyOf(bArr, (i + readLength) * 2);
            }
            System.arraycopy(newData, offset, this.data, this.length, readLength);
            this.length += readLength;
        }
    }
}
