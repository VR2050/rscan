package com.googlecode.mp4parser.authoring.tracks;

import com.coremedia.iso.boxes.CompositionTimeToSample;
import com.coremedia.iso.boxes.SampleDependencyTypeBox;
import com.coremedia.iso.boxes.SampleDescriptionBox;
import com.coremedia.iso.boxes.sampleentry.AudioSampleEntry;
import com.google.android.exoplayer2.extractor.ts.PsExtractor;
import com.googlecode.mp4parser.DataSource;
import com.googlecode.mp4parser.authoring.AbstractTrack;
import com.googlecode.mp4parser.authoring.Sample;
import com.googlecode.mp4parser.authoring.TrackMetaData;
import com.googlecode.mp4parser.boxes.DTSSpecificBox;
import im.uwrkaxlmjj.ui.utils.translate.common.AudioEditConstant;
import io.reactivex.annotations.SchedulerSupport;
import java.io.EOFException;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.Buffer;
import java.nio.ByteBuffer;
import java.nio.channels.WritableByteChannel;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import kotlin.jvm.internal.ByteCompanionObject;

/* JADX INFO: loaded from: classes.dex */
public class DTSTrackImpl extends AbstractTrack {
    private static final int BUFFER = 67108864;
    int bcCoreBitRate;
    int bcCoreChannelMask;
    int bcCoreMaxSampleRate;
    int bitrate;
    int channelCount;
    int channelMask;
    int codecDelayAtMaxFs;
    int coreBitRate;
    int coreChannelMask;
    int coreFramePayloadInBytes;
    int coreMaxSampleRate;
    boolean coreSubStreamPresent;
    private int dataOffset;
    private DataSource dataSource;
    DTSSpecificBox ddts;
    int extAvgBitrate;
    int extFramePayloadInBytes;
    int extPeakBitrate;
    int extSmoothBuffSize;
    boolean extensionSubStreamPresent;
    int frameSize;
    boolean isVBR;
    private String lang;
    int lbrCodingPresent;
    int lsbTrimPercent;
    int maxSampleRate;
    int numExtSubStreams;
    int numFramesTotal;
    int numSamplesOrigAudioAtMaxFs;
    SampleDescriptionBox sampleDescriptionBox;
    private long[] sampleDurations;
    int sampleSize;
    int samplerate;
    private List<Sample> samples;
    int samplesPerFrame;
    int samplesPerFrameAtMaxFs;
    TrackMetaData trackMetaData;
    String type;

    public DTSTrackImpl(DataSource dataSource, String lang) throws IOException {
        super(dataSource.toString());
        this.trackMetaData = new TrackMetaData();
        this.frameSize = 0;
        this.dataOffset = 0;
        this.ddts = new DTSSpecificBox();
        this.isVBR = false;
        this.coreSubStreamPresent = false;
        this.extensionSubStreamPresent = false;
        this.numExtSubStreams = 0;
        this.coreMaxSampleRate = 0;
        this.coreBitRate = 0;
        this.coreChannelMask = 0;
        this.coreFramePayloadInBytes = 0;
        this.extAvgBitrate = 0;
        this.extPeakBitrate = 0;
        this.extSmoothBuffSize = 0;
        this.extFramePayloadInBytes = 0;
        this.maxSampleRate = 0;
        this.lbrCodingPresent = 0;
        this.numFramesTotal = 0;
        this.samplesPerFrameAtMaxFs = 0;
        this.numSamplesOrigAudioAtMaxFs = 0;
        this.channelMask = 0;
        this.codecDelayAtMaxFs = 0;
        this.bcCoreMaxSampleRate = 0;
        this.bcCoreBitRate = 0;
        this.bcCoreChannelMask = 0;
        this.lsbTrimPercent = 0;
        this.type = SchedulerSupport.NONE;
        this.lang = "eng";
        this.lang = lang;
        this.dataSource = dataSource;
        parse();
    }

    public DTSTrackImpl(DataSource dataSource) throws IOException {
        super(dataSource.toString());
        this.trackMetaData = new TrackMetaData();
        this.frameSize = 0;
        this.dataOffset = 0;
        this.ddts = new DTSSpecificBox();
        this.isVBR = false;
        this.coreSubStreamPresent = false;
        this.extensionSubStreamPresent = false;
        this.numExtSubStreams = 0;
        this.coreMaxSampleRate = 0;
        this.coreBitRate = 0;
        this.coreChannelMask = 0;
        this.coreFramePayloadInBytes = 0;
        this.extAvgBitrate = 0;
        this.extPeakBitrate = 0;
        this.extSmoothBuffSize = 0;
        this.extFramePayloadInBytes = 0;
        this.maxSampleRate = 0;
        this.lbrCodingPresent = 0;
        this.numFramesTotal = 0;
        this.samplesPerFrameAtMaxFs = 0;
        this.numSamplesOrigAudioAtMaxFs = 0;
        this.channelMask = 0;
        this.codecDelayAtMaxFs = 0;
        this.bcCoreMaxSampleRate = 0;
        this.bcCoreBitRate = 0;
        this.bcCoreChannelMask = 0;
        this.lsbTrimPercent = 0;
        this.type = SchedulerSupport.NONE;
        this.lang = "eng";
        this.dataSource = dataSource;
        parse();
    }

    @Override // java.io.Closeable, java.lang.AutoCloseable
    public void close() throws IOException {
        this.dataSource.close();
    }

    private void parse() throws IOException {
        if (!readVariables()) {
            throw new IOException();
        }
        this.sampleDescriptionBox = new SampleDescriptionBox();
        AudioSampleEntry audioSampleEntry = new AudioSampleEntry(this.type);
        audioSampleEntry.setChannelCount(this.channelCount);
        audioSampleEntry.setSampleRate(this.samplerate);
        audioSampleEntry.setDataReferenceIndex(1);
        audioSampleEntry.setSampleSize(16);
        audioSampleEntry.addBox(this.ddts);
        this.sampleDescriptionBox.addBox(audioSampleEntry);
        this.trackMetaData.setCreationTime(new Date());
        this.trackMetaData.setModificationTime(new Date());
        this.trackMetaData.setLanguage(this.lang);
        this.trackMetaData.setTimescale(this.samplerate);
    }

    @Override // com.googlecode.mp4parser.authoring.Track
    public List<Sample> getSamples() {
        return this.samples;
    }

    @Override // com.googlecode.mp4parser.authoring.Track
    public SampleDescriptionBox getSampleDescriptionBox() {
        return this.sampleDescriptionBox;
    }

    @Override // com.googlecode.mp4parser.authoring.Track
    public long[] getSampleDurations() {
        return this.sampleDurations;
    }

    @Override // com.googlecode.mp4parser.authoring.AbstractTrack, com.googlecode.mp4parser.authoring.Track
    public List<CompositionTimeToSample.Entry> getCompositionTimeEntries() {
        return null;
    }

    @Override // com.googlecode.mp4parser.authoring.AbstractTrack, com.googlecode.mp4parser.authoring.Track
    public long[] getSyncSamples() {
        return null;
    }

    @Override // com.googlecode.mp4parser.authoring.AbstractTrack, com.googlecode.mp4parser.authoring.Track
    public List<SampleDependencyTypeBox.Entry> getSampleDependencies() {
        return null;
    }

    @Override // com.googlecode.mp4parser.authoring.Track
    public TrackMetaData getTrackMetaData() {
        return this.trackMetaData;
    }

    @Override // com.googlecode.mp4parser.authoring.Track
    public String getHandler() {
        return "soun";
    }

    private void parseDtshdhdr(int size, ByteBuffer bb) {
        bb.getInt();
        bb.get();
        bb.getInt();
        bb.get();
        int bitwStreamMetadata = bb.getShort();
        bb.get();
        this.numExtSubStreams = bb.get();
        if ((bitwStreamMetadata & 1) == 1) {
            this.isVBR = true;
        }
        if ((bitwStreamMetadata & 8) == 8) {
            this.coreSubStreamPresent = true;
        }
        if ((bitwStreamMetadata & 16) == 16) {
            this.extensionSubStreamPresent = true;
            this.numExtSubStreams++;
        } else {
            this.numExtSubStreams = 0;
        }
        for (int i = 14; i < size; i++) {
            bb.get();
        }
    }

    private boolean parseCoressmd(int size, ByteBuffer bb) {
        int cmsr_1 = bb.get();
        int cmsr_2 = bb.getShort();
        this.coreMaxSampleRate = (cmsr_1 << 16) | (65535 & cmsr_2);
        this.coreBitRate = bb.getShort();
        this.coreChannelMask = bb.getShort();
        this.coreFramePayloadInBytes = bb.getInt();
        for (int i = 11; i < size; i++) {
            bb.get();
        }
        return true;
    }

    private boolean parseAuprhdr(int size, ByteBuffer bb) {
        bb.get();
        int bitwAupresData = bb.getShort();
        int a = bb.get();
        int b = bb.getShort();
        this.maxSampleRate = (a << 16) | (b & 65535);
        this.numFramesTotal = bb.getInt();
        this.samplesPerFrameAtMaxFs = bb.getShort();
        int a2 = bb.get();
        int b2 = bb.getInt();
        this.numSamplesOrigAudioAtMaxFs = (a2 << 32) | (b2 & 65535);
        this.channelMask = bb.getShort();
        this.codecDelayAtMaxFs = bb.getShort();
        int c = 21;
        if ((bitwAupresData & 3) == 3) {
            int a3 = bb.get();
            int b3 = bb.getShort();
            this.bcCoreMaxSampleRate = (65535 & b3) | (a3 << 16);
            this.bcCoreBitRate = bb.getShort();
            this.bcCoreChannelMask = bb.getShort();
            c = 21 + 7;
        }
        if ((bitwAupresData & 4) > 0) {
            this.lsbTrimPercent = bb.get();
            c++;
        }
        if ((bitwAupresData & 8) > 0) {
            this.lbrCodingPresent = 1;
        }
        while (c < size) {
            bb.get();
            c++;
        }
        return true;
    }

    private boolean parseExtssmd(int size, ByteBuffer bb) {
        int i;
        int a = bb.get();
        int b = bb.getShort();
        this.extAvgBitrate = (a << 16) | (b & 65535);
        if (this.isVBR) {
            int a2 = bb.get();
            int b2 = bb.getShort();
            this.extPeakBitrate = (65535 & b2) | (a2 << 16);
            this.extSmoothBuffSize = bb.getShort();
            i = 3 + 5;
        } else {
            this.extFramePayloadInBytes = bb.getInt();
            i = 3 + 4;
        }
        while (i < size) {
            bb.get();
            i++;
        }
        return true;
    }

    /* JADX WARN: Code restructure failed: missing block: B:100:0x017e, code lost:
    
        if (r2 != 0) goto L105;
     */
    /* JADX WARN: Code restructure failed: missing block: B:101:0x0180, code lost:
    
        if (r0 != 1) goto L105;
     */
    /* JADX WARN: Code restructure failed: missing block: B:102:0x0182, code lost:
    
        if (r12 != 0) goto L105;
     */
    /* JADX WARN: Code restructure failed: missing block: B:103:0x0184, code lost:
    
        if (r7 != 0) goto L105;
     */
    /* JADX WARN: Code restructure failed: missing block: B:104:0x0186, code lost:
    
        r15 = 9;
     */
    /* JADX WARN: Code restructure failed: missing block: B:105:0x018b, code lost:
    
        if (r8 != 0) goto L113;
     */
    /* JADX WARN: Code restructure failed: missing block: B:106:0x018d, code lost:
    
        if (r4 != 0) goto L113;
     */
    /* JADX WARN: Code restructure failed: missing block: B:108:0x0190, code lost:
    
        if (r2 != 1) goto L113;
     */
    /* JADX WARN: Code restructure failed: missing block: B:109:0x0192, code lost:
    
        if (r0 != 0) goto L113;
     */
    /* JADX WARN: Code restructure failed: missing block: B:110:0x0194, code lost:
    
        if (r12 != 0) goto L113;
     */
    /* JADX WARN: Code restructure failed: missing block: B:111:0x0196, code lost:
    
        if (r7 != 0) goto L113;
     */
    /* JADX WARN: Code restructure failed: missing block: B:112:0x0198, code lost:
    
        r15 = 10;
     */
    /* JADX WARN: Code restructure failed: missing block: B:113:0x019d, code lost:
    
        if (r8 != 0) goto L121;
     */
    /* JADX WARN: Code restructure failed: missing block: B:115:0x01a0, code lost:
    
        if (r4 != 1) goto L121;
     */
    /* JADX WARN: Code restructure failed: missing block: B:116:0x01a2, code lost:
    
        if (r2 != 1) goto L121;
     */
    /* JADX WARN: Code restructure failed: missing block: B:117:0x01a4, code lost:
    
        if (r0 != 0) goto L121;
     */
    /* JADX WARN: Code restructure failed: missing block: B:118:0x01a6, code lost:
    
        if (r12 != 0) goto L121;
     */
    /* JADX WARN: Code restructure failed: missing block: B:119:0x01a8, code lost:
    
        if (r7 != 0) goto L121;
     */
    /* JADX WARN: Code restructure failed: missing block: B:120:0x01aa, code lost:
    
        r15 = 13;
     */
    /* JADX WARN: Code restructure failed: missing block: B:121:0x01af, code lost:
    
        if (r8 != 0) goto L186;
     */
    /* JADX WARN: Code restructure failed: missing block: B:122:0x01b1, code lost:
    
        if (r4 != 0) goto L186;
     */
    /* JADX WARN: Code restructure failed: missing block: B:123:0x01b3, code lost:
    
        if (r2 != 0) goto L186;
     */
    /* JADX WARN: Code restructure failed: missing block: B:124:0x01b5, code lost:
    
        if (r0 != 0) goto L186;
     */
    /* JADX WARN: Code restructure failed: missing block: B:126:0x01b8, code lost:
    
        if (r12 != 1) goto L186;
     */
    /* JADX WARN: Code restructure failed: missing block: B:127:0x01ba, code lost:
    
        if (r7 != 0) goto L186;
     */
    /* JADX WARN: Code restructure failed: missing block: B:128:0x01bc, code lost:
    
        r15 = 14;
     */
    /* JADX WARN: Code restructure failed: missing block: B:129:0x01c1, code lost:
    
        if (r13 != 0) goto L138;
     */
    /* JADX WARN: Code restructure failed: missing block: B:130:0x01c3, code lost:
    
        if (r8 != 0) goto L138;
     */
    /* JADX WARN: Code restructure failed: missing block: B:131:0x01c5, code lost:
    
        if (r4 != 0) goto L138;
     */
    /* JADX WARN: Code restructure failed: missing block: B:132:0x01c7, code lost:
    
        if (r2 != 0) goto L138;
     */
    /* JADX WARN: Code restructure failed: missing block: B:134:0x01ca, code lost:
    
        if (r0 != 1) goto L138;
     */
    /* JADX WARN: Code restructure failed: missing block: B:135:0x01cc, code lost:
    
        if (r12 != 0) goto L138;
     */
    /* JADX WARN: Code restructure failed: missing block: B:136:0x01ce, code lost:
    
        if (r7 != 0) goto L138;
     */
    /* JADX WARN: Code restructure failed: missing block: B:137:0x01d0, code lost:
    
        r15 = 7;
     */
    /* JADX WARN: Code restructure failed: missing block: B:139:0x01d5, code lost:
    
        if (r13 != 6) goto L148;
     */
    /* JADX WARN: Code restructure failed: missing block: B:13:0x0032, code lost:
    
        r10 = r7.getLong();
        r39.dataOffset = r7.position();
        r5 = -1;
        r19 = false;
        r20 = 0;
        r21 = 0;
        r22 = 0;
        r12 = -1;
        r0 = 0;
        r15 = -1;
        r4 = 0;
        r13 = 0;
        r2 = 0;
        r14 = 0;
        r3 = 0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:140:0x01d7, code lost:
    
        if (r8 != 0) goto L148;
     */
    /* JADX WARN: Code restructure failed: missing block: B:141:0x01d9, code lost:
    
        if (r4 != 0) goto L148;
     */
    /* JADX WARN: Code restructure failed: missing block: B:142:0x01db, code lost:
    
        if (r2 != 0) goto L148;
     */
    /* JADX WARN: Code restructure failed: missing block: B:144:0x01de, code lost:
    
        if (r0 != 1) goto L148;
     */
    /* JADX WARN: Code restructure failed: missing block: B:145:0x01e0, code lost:
    
        if (r12 != 0) goto L148;
     */
    /* JADX WARN: Code restructure failed: missing block: B:146:0x01e2, code lost:
    
        if (r7 != 0) goto L148;
     */
    /* JADX WARN: Code restructure failed: missing block: B:147:0x01e4, code lost:
    
        r15 = 8;
     */
    /* JADX WARN: Code restructure failed: missing block: B:148:0x01e9, code lost:
    
        if (r13 != 0) goto L157;
     */
    /* JADX WARN: Code restructure failed: missing block: B:149:0x01eb, code lost:
    
        if (r8 != 0) goto L157;
     */
    /* JADX WARN: Code restructure failed: missing block: B:14:0x005e, code lost:
    
        if (r19 == false) goto L227;
     */
    /* JADX WARN: Code restructure failed: missing block: B:150:0x01ed, code lost:
    
        if (r4 != 0) goto L157;
     */
    /* JADX WARN: Code restructure failed: missing block: B:152:0x01f0, code lost:
    
        if (r2 != 1) goto L157;
     */
    /* JADX WARN: Code restructure failed: missing block: B:153:0x01f2, code lost:
    
        if (r0 != 0) goto L157;
     */
    /* JADX WARN: Code restructure failed: missing block: B:154:0x01f4, code lost:
    
        if (r12 != 0) goto L157;
     */
    /* JADX WARN: Code restructure failed: missing block: B:155:0x01f6, code lost:
    
        if (r7 != 0) goto L157;
     */
    /* JADX WARN: Code restructure failed: missing block: B:156:0x01f8, code lost:
    
        r15 = 11;
     */
    /* JADX WARN: Code restructure failed: missing block: B:158:0x01fd, code lost:
    
        if (r13 != 6) goto L167;
     */
    /* JADX WARN: Code restructure failed: missing block: B:159:0x01ff, code lost:
    
        if (r8 != 0) goto L167;
     */
    /* JADX WARN: Code restructure failed: missing block: B:15:0x0060, code lost:
    
        r1 = r39.samplesPerFrame;
        r29 = r3;
     */
    /* JADX WARN: Code restructure failed: missing block: B:160:0x0201, code lost:
    
        if (r4 != 0) goto L167;
     */
    /* JADX WARN: Code restructure failed: missing block: B:162:0x0204, code lost:
    
        if (r2 != 1) goto L167;
     */
    /* JADX WARN: Code restructure failed: missing block: B:163:0x0206, code lost:
    
        if (r0 != 0) goto L167;
     */
    /* JADX WARN: Code restructure failed: missing block: B:164:0x0208, code lost:
    
        if (r12 != 0) goto L167;
     */
    /* JADX WARN: Code restructure failed: missing block: B:165:0x020a, code lost:
    
        if (r7 != 0) goto L167;
     */
    /* JADX WARN: Code restructure failed: missing block: B:166:0x020c, code lost:
    
        r15 = 12;
     */
    /* JADX WARN: Code restructure failed: missing block: B:167:0x0210, code lost:
    
        if (r13 != 0) goto L176;
     */
    /* JADX WARN: Code restructure failed: missing block: B:168:0x0212, code lost:
    
        if (r8 != 0) goto L176;
     */
    /* JADX WARN: Code restructure failed: missing block: B:169:0x0214, code lost:
    
        if (r4 != 0) goto L176;
     */
    /* JADX WARN: Code restructure failed: missing block: B:16:0x006c, code lost:
    
        if (r1 == 512) goto L26;
     */
    /* JADX WARN: Code restructure failed: missing block: B:170:0x0216, code lost:
    
        if (r2 != 0) goto L176;
     */
    /* JADX WARN: Code restructure failed: missing block: B:171:0x0218, code lost:
    
        if (r0 != 0) goto L176;
     */
    /* JADX WARN: Code restructure failed: missing block: B:173:0x021b, code lost:
    
        if (r12 != 1) goto L176;
     */
    /* JADX WARN: Code restructure failed: missing block: B:174:0x021d, code lost:
    
        if (r7 != 0) goto L176;
     */
    /* JADX WARN: Code restructure failed: missing block: B:175:0x021f, code lost:
    
        r15 = 15;
     */
    /* JADX WARN: Code restructure failed: missing block: B:177:0x0224, code lost:
    
        if (r13 != 2) goto L186;
     */
    /* JADX WARN: Code restructure failed: missing block: B:178:0x0226, code lost:
    
        if (r8 != 0) goto L186;
     */
    /* JADX WARN: Code restructure failed: missing block: B:179:0x0228, code lost:
    
        if (r4 != 0) goto L186;
     */
    /* JADX WARN: Code restructure failed: missing block: B:180:0x022a, code lost:
    
        if (r2 != 0) goto L186;
     */
    /* JADX WARN: Code restructure failed: missing block: B:181:0x022c, code lost:
    
        if (r0 != 0) goto L186;
     */
    /* JADX WARN: Code restructure failed: missing block: B:183:0x022f, code lost:
    
        if (r12 != 1) goto L186;
     */
    /* JADX WARN: Code restructure failed: missing block: B:184:0x0231, code lost:
    
        if (r7 != 0) goto L186;
     */
    /* JADX WARN: Code restructure failed: missing block: B:185:0x0233, code lost:
    
        r15 = 16;
     */
    /* JADX WARN: Code restructure failed: missing block: B:186:0x0237, code lost:
    
        r15 = 0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:187:0x0239, code lost:
    
        r26 = r4;
        r39.ddts.setDTSSamplingFrequency(r39.maxSampleRate);
     */
    /* JADX WARN: Code restructure failed: missing block: B:188:0x0245, code lost:
    
        if (r39.isVBR == false) goto L190;
     */
    /* JADX WARN: Code restructure failed: missing block: B:189:0x0247, code lost:
    
        r39.ddts.setMaxBitRate((r39.coreBitRate + r39.extPeakBitrate) * 1000);
     */
    /* JADX WARN: Code restructure failed: missing block: B:18:0x0070, code lost:
    
        if (r1 == 1024) goto L25;
     */
    /* JADX WARN: Code restructure failed: missing block: B:190:0x0255, code lost:
    
        r39.ddts.setMaxBitRate((r39.coreBitRate + r39.extAvgBitrate) * 1000);
     */
    /* JADX WARN: Code restructure failed: missing block: B:191:0x0262, code lost:
    
        r39.ddts.setAvgBitRate((r39.coreBitRate + r39.extAvgBitrate) * 1000);
        r39.ddts.setPcmSampleDepth(r39.sampleSize);
        r39.ddts.setFrameDuration(r3);
        r39.ddts.setStreamConstruction(r15);
        r1 = r39.coreChannelMask;
     */
    /* JADX WARN: Code restructure failed: missing block: B:192:0x0284, code lost:
    
        if ((r1 & 8) > 0) goto L197;
     */
    /* JADX WARN: Code restructure failed: missing block: B:194:0x0289, code lost:
    
        if ((r1 & 4096) <= 0) goto L196;
     */
    /* JADX WARN: Code restructure failed: missing block: B:196:0x028c, code lost:
    
        r39.ddts.setCoreLFEPresent(0);
     */
    /* JADX WARN: Code restructure failed: missing block: B:197:0x0293, code lost:
    
        r39.ddts.setCoreLFEPresent(1);
     */
    /* JADX WARN: Code restructure failed: missing block: B:198:0x029a, code lost:
    
        r39.ddts.setCoreLayout(r9);
        r39.ddts.setCoreSize(r39.coreFramePayloadInBytes);
        r39.ddts.setStereoDownmix(0);
        r39.ddts.setRepresentationType(4);
        r39.ddts.setChannelLayout(r39.channelMask);
     */
    /* JADX WARN: Code restructure failed: missing block: B:199:0x02bb, code lost:
    
        if (r39.coreMaxSampleRate <= 0) goto L203;
     */
    /* JADX WARN: Code restructure failed: missing block: B:201:0x02bf, code lost:
    
        if (r39.extAvgBitrate <= 0) goto L203;
     */
    /* JADX WARN: Code restructure failed: missing block: B:202:0x02c1, code lost:
    
        r39.ddts.setMultiAssetFlag(1);
        r5 = 0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:203:0x02c9, code lost:
    
        r5 = 0;
        r39.ddts.setMultiAssetFlag(0);
     */
    /* JADX WARN: Code restructure failed: missing block: B:204:0x02d0, code lost:
    
        r39.ddts.setLBRDurationMod(r39.lbrCodingPresent);
        r39.ddts.setReservedBoxPresent(r5);
        r39.channelCount = r5;
        r1 = 0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:206:0x02e1, code lost:
    
        if (r1 < 16) goto L209;
     */
    /* JADX WARN: Code restructure failed: missing block: B:207:0x02e3, code lost:
    
        r5 = r20;
        r0 = generateSamples(r39.dataSource, r39.dataOffset, r10, r5);
        r39.samples = r0;
        r0 = new long[r0.size()];
        r39.sampleDurations = r0;
        java.util.Arrays.fill(r0, r39.samplesPerFrame);
     */
    /* JADX WARN: Code restructure failed: missing block: B:208:0x0311, code lost:
    
        return true;
     */
    /* JADX WARN: Code restructure failed: missing block: B:209:0x0312, code lost:
    
        r35 = r0;
        r32 = r2;
        r28 = r3;
        r27 = r9;
        r34 = r26;
        r33 = r29;
        r29 = r17;
        r0 = r39.channelMask;
     */
    /* JADX WARN: Code restructure failed: missing block: B:20:0x0074, code lost:
    
        if (r1 == 2048) goto L24;
     */
    /* JADX WARN: Code restructure failed: missing block: B:210:0x0325, code lost:
    
        if (((r0 >> r1) & 1) != 1) goto L393;
     */
    /* JADX WARN: Code restructure failed: missing block: B:211:0x0327, code lost:
    
        if (r1 == 0) goto L225;
     */
    /* JADX WARN: Code restructure failed: missing block: B:213:0x032b, code lost:
    
        if (r1 == 12) goto L225;
     */
    /* JADX WARN: Code restructure failed: missing block: B:215:0x032f, code lost:
    
        if (r1 == 14) goto L225;
     */
    /* JADX WARN: Code restructure failed: missing block: B:217:0x0332, code lost:
    
        if (r1 == 3) goto L225;
     */
    /* JADX WARN: Code restructure failed: missing block: B:219:0x0335, code lost:
    
        if (r1 == 4) goto L225;
     */
    /* JADX WARN: Code restructure failed: missing block: B:21:0x0076, code lost:
    
        if (r1 == 4096) goto L23;
     */
    /* JADX WARN: Code restructure failed: missing block: B:221:0x0338, code lost:
    
        if (r1 == 7) goto L225;
     */
    /* JADX WARN: Code restructure failed: missing block: B:223:0x033c, code lost:
    
        if (r1 == 8) goto L225;
     */
    /* JADX WARN: Code restructure failed: missing block: B:224:0x033e, code lost:
    
        r39.channelCount += 2;
     */
    /* JADX WARN: Code restructure failed: missing block: B:225:0x0345, code lost:
    
        r39.channelCount++;
     */
    /* JADX WARN: Code restructure failed: missing block: B:226:0x034a, code lost:
    
        r1 = r1 + 1;
        r9 = r27;
        r3 = r28;
        r17 = r29;
        r2 = r32;
        r29 = r33;
        r26 = r34;
        r0 = r35;
     */
    /* JADX WARN: Code restructure failed: missing block: B:227:0x035b, code lost:
    
        r35 = r0;
        r32 = r2;
        r33 = r3;
        r34 = r4;
        r29 = r5;
        r30 = r9;
        r31 = r12;
        r12 = r21;
        r21 = r8;
        r8 = r22;
        r22 = r7;
        r7 = r20;
        r20 = r15;
        r0 = r22.position();
        r1 = r22.getInt();
     */
    /* JADX WARN: Code restructure failed: missing block: B:228:0x0381, code lost:
    
        if (r1 != 2147385345) goto L376;
     */
    /* JADX WARN: Code restructure failed: missing block: B:22:0x0078, code lost:
    
        r3 = -1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:230:0x0385, code lost:
    
        if (r20 != 1) goto L377;
     */
    /* JADX WARN: Code restructure failed: missing block: B:231:0x0387, code lost:
    
        r19 = true;
        r15 = r20;
        r20 = r7;
        r7 = r22;
        r5 = r29;
        r9 = r30;
        r2 = r32;
        r3 = r33;
        r4 = r34;
        r0 = r35;
        r22 = r8;
        r8 = r21;
        r21 = r12;
        r12 = r31;
     */
    /* JADX WARN: Code restructure failed: missing block: B:232:0x03a4, code lost:
    
        r15 = 1;
        r2 = new com.googlecode.mp4parser.boxes.mp4.objectdescriptors.BitReaderBuffer(r22);
        r3 = r2.readBits(1);
        r27 = r10;
        r10 = r2.readBits(5);
        r11 = r2.readBits(1);
     */
    /* JADX WARN: Code restructure failed: missing block: B:233:0x03bb, code lost:
    
        if (r3 != 1) goto L381;
     */
    /* JADX WARN: Code restructure failed: missing block: B:235:0x03bf, code lost:
    
        if (r10 != 31) goto L382;
     */
    /* JADX WARN: Code restructure failed: missing block: B:236:0x03c1, code lost:
    
        if (r11 == 0) goto L238;
     */
    /* JADX WARN: Code restructure failed: missing block: B:238:0x03cb, code lost:
    
        r22 = r2.readBits(7);
        r39.samplesPerFrame = (r22 + 1) * 32;
        r9 = r2.readBits(14);
        r39.frameSize += r9 + 1;
        r23 = r2.readBits(6);
        r3 = r2.readBits(4);
        r39.samplerate = getSampleRate(r3);
        r3 = r2.readBits(5);
        r39.bitrate = getBitRate(r3);
        r36 = r2.readBits(1);
     */
    /* JADX WARN: Code restructure failed: missing block: B:239:0x0408, code lost:
    
        if (r36 == 0) goto L242;
     */
    /* JADX WARN: Code restructure failed: missing block: B:23:0x007b, code lost:
    
        r3 = 3;
     */
    /* JADX WARN: Code restructure failed: missing block: B:240:0x040a, code lost:
    
        return false;
     */
    /* JADX WARN: Code restructure failed: missing block: B:242:0x040c, code lost:
    
        r2.readBits(1);
        r2.readBits(1);
        r2.readBits(1);
        r2.readBits(1);
        r13 = r2.readBits(3);
        r14 = r2.readBits(1);
        r2.readBits(1);
        r2.readBits(2);
        r2.readBits(1);
     */
    /* JADX WARN: Code restructure failed: missing block: B:243:0x042e, code lost:
    
        if (r11 != 1) goto L245;
     */
    /* JADX WARN: Code restructure failed: missing block: B:244:0x0430, code lost:
    
        r2.readBits(16);
     */
    /* JADX WARN: Code restructure failed: missing block: B:245:0x0435, code lost:
    
        r2.readBits(1);
        r3 = r2.readBits(4);
        r2.readBits(2);
        r10 = r2.readBits(3);
     */
    /* JADX WARN: Code restructure failed: missing block: B:246:0x044b, code lost:
    
        if (r10 == 0) goto L261;
     */
    /* JADX WARN: Code restructure failed: missing block: B:248:0x044e, code lost:
    
        if (r10 == 1) goto L261;
     */
    /* JADX WARN: Code restructure failed: missing block: B:24:0x0080, code lost:
    
        r3 = 2;
     */
    /* JADX WARN: Code restructure failed: missing block: B:250:0x0451, code lost:
    
        if (r10 == 2) goto L260;
     */
    /* JADX WARN: Code restructure failed: missing block: B:252:0x0454, code lost:
    
        if (r10 == 3) goto L260;
     */
    /* JADX WARN: Code restructure failed: missing block: B:254:0x0457, code lost:
    
        if (r10 == 5) goto L259;
     */
    /* JADX WARN: Code restructure failed: missing block: B:256:0x045a, code lost:
    
        if (r10 == 6) goto L259;
     */
    /* JADX WARN: Code restructure failed: missing block: B:257:0x045c, code lost:
    
        return false;
     */
    /* JADX WARN: Code restructure failed: missing block: B:259:0x045e, code lost:
    
        r39.sampleSize = 24;
     */
    /* JADX WARN: Code restructure failed: missing block: B:25:0x0085, code lost:
    
        r3 = 1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:260:0x0463, code lost:
    
        r39.sampleSize = 20;
     */
    /* JADX WARN: Code restructure failed: missing block: B:261:0x0468, code lost:
    
        r39.sampleSize = 16;
     */
    /* JADX WARN: Code restructure failed: missing block: B:262:0x046d, code lost:
    
        r2.readBits(1);
        r2.readBits(1);
     */
    /* JADX WARN: Code restructure failed: missing block: B:263:0x0479, code lost:
    
        if (r3 == 6) goto L268;
     */
    /* JADX WARN: Code restructure failed: missing block: B:265:0x047c, code lost:
    
        if (r3 == 7) goto L267;
     */
    /* JADX WARN: Code restructure failed: missing block: B:266:0x047e, code lost:
    
        r2.readBits(4);
     */
    /* JADX WARN: Code restructure failed: missing block: B:267:0x0485, code lost:
    
        r2.readBits(4);
     */
    /* JADX WARN: Code restructure failed: missing block: B:268:0x048c, code lost:
    
        r2.readBits(4);
     */
    /* JADX WARN: Code restructure failed: missing block: B:269:0x0493, code lost:
    
        r22.position((r0 + r9) + 1);
        r20 = r7;
        r22 = r8;
        r8 = r21;
        r10 = r27;
        r9 = r30;
        r2 = r32;
        r3 = r33;
        r4 = r34;
        r0 = r35;
        r7 = r22;
        r21 = r12;
        r12 = r23;
        r5 = r29;
     */
    /* JADX WARN: Code restructure failed: missing block: B:26:0x008a, code lost:
    
        r3 = 0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:271:0x04bf, code lost:
    
        return false;
     */
    /* JADX WARN: Code restructure failed: missing block: B:273:0x04c1, code lost:
    
        r27 = r10;
     */
    /* JADX WARN: Code restructure failed: missing block: B:274:0x04ca, code lost:
    
        if (r1 != 1683496997) goto L385;
     */
    /* JADX WARN: Code restructure failed: missing block: B:276:0x04cd, code lost:
    
        if (r20 != (-1)) goto L278;
     */
    /* JADX WARN: Code restructure failed: missing block: B:277:0x04cf, code lost:
    
        r39.samplesPerFrame = r39.samplesPerFrameAtMaxFs;
        r15 = 0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:278:0x04d6, code lost:
    
        r15 = r20;
     */
    /* JADX WARN: Code restructure failed: missing block: B:279:0x04d7, code lost:
    
        r3 = new com.googlecode.mp4parser.boxes.mp4.objectdescriptors.BitReaderBuffer(r22);
        r3.readBits(8);
        r3.readBits(2);
        r9 = r3.readBits(1);
        r4 = 12;
        r10 = 20;
     */
    /* JADX WARN: Code restructure failed: missing block: B:280:0x04ef, code lost:
    
        if (r9 != 0) goto L282;
     */
    /* JADX WARN: Code restructure failed: missing block: B:281:0x04f1, code lost:
    
        r4 = 8;
        r10 = 16;
     */
    /* JADX WARN: Code restructure failed: missing block: B:282:0x04f5, code lost:
    
        r11 = r3.readBits(r4) + 1;
        r18 = r3.readBits(r10) + 1;
        r22.position(r0 + r11);
        r1 = r22.getInt();
     */
    /* JADX WARN: Code restructure failed: missing block: B:283:0x0511, code lost:
    
        if (r1 != 1515870810) goto L288;
     */
    /* JADX WARN: Code restructure failed: missing block: B:285:0x0518, code lost:
    
        if (r33 != 1) goto L287;
     */
    /* JADX WARN: Code restructure failed: missing block: B:286:0x051a, code lost:
    
        r19 = true;
     */
    /* JADX WARN: Code restructure failed: missing block: B:287:0x051c, code lost:
    
        r33 = 1;
        r20 = r7;
        r2 = r32;
        r3 = r35;
     */
    /* JADX WARN: Code restructure failed: missing block: B:289:0x052e, code lost:
    
        if (r1 != 1191201283) goto L294;
     */
    /* JADX WARN: Code restructure failed: missing block: B:28:0x008f, code lost:
    
        if (r3 != (-1)) goto L31;
     */
    /* JADX WARN: Code restructure failed: missing block: B:290:0x0530, code lost:
    
        r33 = r33;
     */
    /* JADX WARN: Code restructure failed: missing block: B:291:0x0535, code lost:
    
        if (r34 != 1) goto L293;
     */
    /* JADX WARN: Code restructure failed: missing block: B:292:0x0537, code lost:
    
        r19 = true;
     */
    /* JADX WARN: Code restructure failed: missing block: B:293:0x0539, code lost:
    
        r34 = 1;
        r20 = r7;
        r2 = r32;
        r3 = r35;
     */
    /* JADX WARN: Code restructure failed: missing block: B:294:0x0544, code lost:
    
        r33 = r33;
     */
    /* JADX WARN: Code restructure failed: missing block: B:295:0x054b, code lost:
    
        if (r1 != 496366178) goto L300;
     */
    /* JADX WARN: Code restructure failed: missing block: B:296:0x054d, code lost:
    
        r34 = r34;
     */
    /* JADX WARN: Code restructure failed: missing block: B:297:0x0552, code lost:
    
        if (r32 != 1) goto L299;
     */
    /* JADX WARN: Code restructure failed: missing block: B:298:0x0554, code lost:
    
        r19 = true;
     */
    /* JADX WARN: Code restructure failed: missing block: B:299:0x0556, code lost:
    
        r2 = 1;
        r20 = r7;
        r3 = r35;
     */
    /* JADX WARN: Code restructure failed: missing block: B:29:0x0091, code lost:
    
        return false;
     */
    /* JADX WARN: Code restructure failed: missing block: B:300:0x055c, code lost:
    
        r34 = r34;
     */
    /* JADX WARN: Code restructure failed: missing block: B:301:0x0563, code lost:
    
        if (r1 != 1700671838) goto L306;
     */
    /* JADX WARN: Code restructure failed: missing block: B:303:0x056a, code lost:
    
        if (r35 != 1) goto L305;
     */
    /* JADX WARN: Code restructure failed: missing block: B:304:0x056c, code lost:
    
        r19 = true;
     */
    /* JADX WARN: Code restructure failed: missing block: B:305:0x056e, code lost:
    
        r3 = 1;
        r20 = r7;
        r2 = r32;
     */
    /* JADX WARN: Code restructure failed: missing block: B:306:0x0575, code lost:
    
        r3 = r35;
     */
    /* JADX WARN: Code restructure failed: missing block: B:307:0x057c, code lost:
    
        if (r1 != 176167201) goto L312;
     */
    /* JADX WARN: Code restructure failed: missing block: B:309:0x057f, code lost:
    
        if (r7 != 1) goto L311;
     */
    /* JADX WARN: Code restructure failed: missing block: B:310:0x0581, code lost:
    
        r19 = true;
     */
    /* JADX WARN: Code restructure failed: missing block: B:311:0x0583, code lost:
    
        r20 = 1;
        r2 = r32;
     */
    /* JADX WARN: Code restructure failed: missing block: B:313:0x058c, code lost:
    
        if (r1 != 1101174087) goto L318;
     */
    /* JADX WARN: Code restructure failed: missing block: B:315:0x058f, code lost:
    
        if (r12 != 1) goto L317;
     */
    /* JADX WARN: Code restructure failed: missing block: B:316:0x0591, code lost:
    
        r19 = true;
     */
    /* JADX WARN: Code restructure failed: missing block: B:317:0x0593, code lost:
    
        r12 = 1;
        r20 = r7;
        r2 = r32;
     */
    /* JADX WARN: Code restructure failed: missing block: B:319:0x059d, code lost:
    
        if (r1 != 45126241) goto L324;
     */
    /* JADX WARN: Code restructure failed: missing block: B:321:0x05a0, code lost:
    
        if (r8 != 1) goto L323;
     */
    /* JADX WARN: Code restructure failed: missing block: B:322:0x05a2, code lost:
    
        r19 = true;
     */
    /* JADX WARN: Code restructure failed: missing block: B:323:0x05a4, code lost:
    
        r8 = 1;
        r20 = r7;
        r2 = r32;
     */
    /* JADX WARN: Code restructure failed: missing block: B:324:0x05ab, code lost:
    
        r20 = r7;
        r2 = r32;
     */
    /* JADX WARN: Code restructure failed: missing block: B:325:0x05af, code lost:
    
        if (r19 != false) goto L327;
     */
    /* JADX WARN: Code restructure failed: missing block: B:326:0x05b1, code lost:
    
        r39.frameSize += r18;
     */
    /* JADX WARN: Code restructure failed: missing block: B:327:0x05b7, code lost:
    
        r22.position(r0 + r18);
        r0 = r3;
        r7 = r22;
        r5 = 1;
        r10 = r27;
        r9 = r30;
        r3 = r33;
        r4 = r34;
        r22 = r8;
        r8 = r21;
        r21 = r12;
        r12 = r31;
     */
    /* JADX WARN: Code restructure failed: missing block: B:329:0x05eb, code lost:
    
        throw new java.io.IOException("No DTS_SYNCWORD_* found at " + r22.position());
     */
    /* JADX WARN: Code restructure failed: missing block: B:32:0x0095, code lost:
    
        if (r12 == 0) goto L37;
     */
    /* JADX WARN: Code restructure failed: missing block: B:34:0x0098, code lost:
    
        if (r12 == 2) goto L37;
     */
    /* JADX WARN: Code restructure failed: missing block: B:35:0x009a, code lost:
    
        switch(r12) {
            case 4: goto L37;
            case 5: goto L37;
            case 6: goto L37;
            case 7: goto L37;
            case 8: goto L37;
            case 9: goto L37;
            default: goto L36;
        };
     */
    /* JADX WARN: Code restructure failed: missing block: B:36:0x009d, code lost:
    
        r9 = 31;
     */
    /* JADX WARN: Code restructure failed: missing block: B:37:0x009f, code lost:
    
        r1 = r12;
        r9 = r1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:395:?, code lost:
    
        return false;
     */
    /* JADX WARN: Code restructure failed: missing block: B:39:0x00a6, code lost:
    
        if (r15 != 0) goto L65;
     */
    /* JADX WARN: Code restructure failed: missing block: B:40:0x00a8, code lost:
    
        r12 = r21;
     */
    /* JADX WARN: Code restructure failed: missing block: B:41:0x00af, code lost:
    
        if (r12 != 1) goto L46;
     */
    /* JADX WARN: Code restructure failed: missing block: B:42:0x00b1, code lost:
    
        r8 = r22;
     */
    /* JADX WARN: Code restructure failed: missing block: B:43:0x00b3, code lost:
    
        if (r8 != 0) goto L45;
     */
    /* JADX WARN: Code restructure failed: missing block: B:44:0x00b5, code lost:
    
        r39.type = com.coremedia.iso.boxes.sampleentry.AudioSampleEntry.TYPE11;
        r1 = 17;
        r20 = r15;
     */
    /* JADX WARN: Code restructure failed: missing block: B:45:0x00c6, code lost:
    
        r39.type = com.coremedia.iso.boxes.sampleentry.AudioSampleEntry.TYPE12;
        r1 = 21;
        r20 = r15;
     */
    /* JADX WARN: Code restructure failed: missing block: B:46:0x00d3, code lost:
    
        r8 = r22;
        r7 = r20;
        r20 = r15;
     */
    /* JADX WARN: Code restructure failed: missing block: B:47:0x00dc, code lost:
    
        if (r7 != 1) goto L49;
     */
    /* JADX WARN: Code restructure failed: missing block: B:48:0x00de, code lost:
    
        r1 = 18;
        r39.type = com.coremedia.iso.boxes.sampleentry.AudioSampleEntry.TYPE13;
     */
    /* JADX WARN: Code restructure failed: missing block: B:50:0x00e6, code lost:
    
        if (r8 != 1) goto L63;
     */
    /* JADX WARN: Code restructure failed: missing block: B:51:0x00e8, code lost:
    
        r39.type = com.coremedia.iso.boxes.sampleentry.AudioSampleEntry.TYPE12;
     */
    /* JADX WARN: Code restructure failed: missing block: B:52:0x00ea, code lost:
    
        if (r4 != 0) goto L55;
     */
    /* JADX WARN: Code restructure failed: missing block: B:53:0x00ec, code lost:
    
        if (r12 != 0) goto L55;
     */
    /* JADX WARN: Code restructure failed: missing block: B:54:0x00ee, code lost:
    
        r1 = 19;
     */
    /* JADX WARN: Code restructure failed: missing block: B:56:0x00f2, code lost:
    
        if (r4 != 1) goto L59;
     */
    /* JADX WARN: Code restructure failed: missing block: B:57:0x00f4, code lost:
    
        if (r12 != 0) goto L59;
     */
    /* JADX WARN: Code restructure failed: missing block: B:58:0x00f6, code lost:
    
        r1 = 20;
     */
    /* JADX WARN: Code restructure failed: missing block: B:59:0x00f9, code lost:
    
        if (r4 != 0) goto L63;
     */
    /* JADX WARN: Code restructure failed: missing block: B:61:0x00fc, code lost:
    
        if (r12 != 1) goto L63;
     */
    /* JADX WARN: Code restructure failed: missing block: B:62:0x00fe, code lost:
    
        r1 = 21;
     */
    /* JADX WARN: Code restructure failed: missing block: B:63:0x0101, code lost:
    
        r1 = 0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:64:0x0103, code lost:
    
        r39.samplerate = r39.maxSampleRate;
        r39.sampleSize = 24;
        r15 = r1;
        r17 = r5;
     */
    /* JADX WARN: Code restructure failed: missing block: B:65:0x0110, code lost:
    
        r12 = r21;
        r8 = r22;
        r7 = r20;
        r20 = r15;
     */
    /* JADX WARN: Code restructure failed: missing block: B:66:0x011f, code lost:
    
        if (r5 >= 1) goto L79;
     */
    /* JADX WARN: Code restructure failed: missing block: B:68:0x0123, code lost:
    
        if (r14 <= 0) goto L78;
     */
    /* JADX WARN: Code restructure failed: missing block: B:69:0x0125, code lost:
    
        if (r13 == 0) goto L77;
     */
    /* JADX WARN: Code restructure failed: missing block: B:70:0x0127, code lost:
    
        r17 = r5;
     */
    /* JADX WARN: Code restructure failed: missing block: B:71:0x012a, code lost:
    
        if (r13 == 2) goto L76;
     */
    /* JADX WARN: Code restructure failed: missing block: B:73:0x012d, code lost:
    
        if (r13 == 6) goto L75;
     */
    /* JADX WARN: Code restructure failed: missing block: B:74:0x012f, code lost:
    
        r39.type = com.coremedia.iso.boxes.sampleentry.AudioSampleEntry.TYPE12;
        r15 = 0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:75:0x0135, code lost:
    
        r39.type = com.coremedia.iso.boxes.sampleentry.AudioSampleEntry.TYPE12;
        r15 = 3;
     */
    /* JADX WARN: Code restructure failed: missing block: B:76:0x013b, code lost:
    
        r39.type = "dtsc";
        r15 = 4;
     */
    /* JADX WARN: Code restructure failed: missing block: B:77:0x0141, code lost:
    
        r17 = r5;
        r39.type = "dtsc";
        r15 = 2;
     */
    /* JADX WARN: Code restructure failed: missing block: B:78:0x0149, code lost:
    
        r17 = r5;
        r39.type = "dtsc";
        r15 = 1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:79:0x0151, code lost:
    
        r17 = r5;
        r39.type = com.coremedia.iso.boxes.sampleentry.AudioSampleEntry.TYPE12;
     */
    /* JADX WARN: Code restructure failed: missing block: B:80:0x0155, code lost:
    
        if (r14 != 0) goto L129;
     */
    /* JADX WARN: Code restructure failed: missing block: B:81:0x0157, code lost:
    
        if (r8 != 0) goto L89;
     */
    /* JADX WARN: Code restructure failed: missing block: B:83:0x015a, code lost:
    
        if (r4 != 1) goto L89;
     */
    /* JADX WARN: Code restructure failed: missing block: B:84:0x015c, code lost:
    
        if (r2 != 0) goto L89;
     */
    /* JADX WARN: Code restructure failed: missing block: B:85:0x015e, code lost:
    
        if (r0 != 0) goto L89;
     */
    /* JADX WARN: Code restructure failed: missing block: B:86:0x0160, code lost:
    
        if (r12 != 0) goto L89;
     */
    /* JADX WARN: Code restructure failed: missing block: B:87:0x0162, code lost:
    
        if (r7 != 0) goto L89;
     */
    /* JADX WARN: Code restructure failed: missing block: B:88:0x0164, code lost:
    
        r15 = 5;
     */
    /* JADX WARN: Code restructure failed: missing block: B:89:0x0168, code lost:
    
        if (r8 != 0) goto L97;
     */
    /* JADX WARN: Code restructure failed: missing block: B:90:0x016a, code lost:
    
        if (r4 != 0) goto L97;
     */
    /* JADX WARN: Code restructure failed: missing block: B:91:0x016c, code lost:
    
        if (r2 != 0) goto L97;
     */
    /* JADX WARN: Code restructure failed: missing block: B:93:0x016f, code lost:
    
        if (r0 != 1) goto L97;
     */
    /* JADX WARN: Code restructure failed: missing block: B:94:0x0171, code lost:
    
        if (r12 != 0) goto L97;
     */
    /* JADX WARN: Code restructure failed: missing block: B:95:0x0173, code lost:
    
        if (r7 != 0) goto L97;
     */
    /* JADX WARN: Code restructure failed: missing block: B:96:0x0175, code lost:
    
        r15 = 6;
     */
    /* JADX WARN: Code restructure failed: missing block: B:97:0x0179, code lost:
    
        if (r8 != 0) goto L105;
     */
    /* JADX WARN: Code restructure failed: missing block: B:99:0x017c, code lost:
    
        if (r4 != 1) goto L105;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private boolean readVariables() throws java.io.IOException {
        /*
            Method dump skipped, instruction units count: 1640
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.googlecode.mp4parser.authoring.tracks.DTSTrackImpl.readVariables():boolean");
    }

    private List<Sample> generateSamples(DataSource dataSource, int dataOffset, long dataSize, int corePresent) throws IOException {
        LookAhead la = new LookAhead(dataSource, dataOffset, dataSize, corePresent);
        List<Sample> mySamples = new ArrayList<>();
        while (true) {
            final ByteBuffer sample = la.findNextStart();
            if (sample != null) {
                mySamples.add(new Sample() { // from class: com.googlecode.mp4parser.authoring.tracks.DTSTrackImpl.1
                    @Override // com.googlecode.mp4parser.authoring.Sample
                    public void writeTo(WritableByteChannel channel) throws IOException {
                        channel.write((ByteBuffer) sample.rewind());
                    }

                    @Override // com.googlecode.mp4parser.authoring.Sample
                    public long getSize() {
                        return sample.rewind().remaining();
                    }

                    @Override // com.googlecode.mp4parser.authoring.Sample
                    public ByteBuffer asByteBuffer() {
                        return sample;
                    }
                });
            } else {
                System.err.println("all samples found");
                return mySamples;
            }
        }
    }

    private int getBitRate(int rate) throws IOException {
        switch (rate) {
            case 0:
                return 32;
            case 1:
                return 56;
            case 2:
                return 64;
            case 3:
                return 96;
            case 4:
                return 112;
            case 5:
                return 128;
            case 6:
                return PsExtractor.AUDIO_STREAM;
            case 7:
                return 224;
            case 8:
                return 256;
            case 9:
                return 320;
            case 10:
                return 384;
            case 11:
                return 448;
            case 12:
                return 512;
            case 13:
                return 576;
            case 14:
                return 640;
            case 15:
                return 768;
            case 16:
                return 960;
            case 17:
                return 1024;
            case 18:
                return 1152;
            case 19:
                return 1280;
            case 20:
                return 1344;
            case 21:
                return 1408;
            case 22:
                return 1411;
            case 23:
                return 1472;
            case 24:
                return 1536;
            case 25:
                return -1;
            default:
                throw new IOException("Unknown bitrate value");
        }
    }

    private int getSampleRate(int sfreq) throws IOException {
        switch (sfreq) {
            case 1:
                return 8000;
            case 2:
                return AudioEditConstant.ExportSampleRate;
            case 3:
                return 32000;
            case 4:
            case 5:
            case 9:
            case 10:
            default:
                throw new IOException("Unknown Sample Rate");
            case 6:
                return 11025;
            case 7:
                return 22050;
            case 8:
                return 44100;
            case 11:
                return 12000;
            case 12:
                return 24000;
            case 13:
                return 48000;
        }
    }

    class LookAhead {
        ByteBuffer buffer;
        long bufferStartPos;
        private final int corePresent;
        long dataEnd;
        DataSource dataSource;
        int inBufferPos = 0;
        long start;

        LookAhead(DataSource dataSource, long bufferStartPos, long dataSize, int corePresent) throws IOException {
            this.dataSource = dataSource;
            this.bufferStartPos = bufferStartPos;
            this.dataEnd = dataSize + bufferStartPos;
            this.corePresent = corePresent;
            fillBuffer();
        }

        public ByteBuffer findNextStart() throws IOException {
            while (true) {
                try {
                    if (this.corePresent == 1) {
                        if (nextFourEquals0x7FFE8001()) {
                            break;
                        }
                        discardByte();
                    } else {
                        if (nextFourEquals0x64582025()) {
                            break;
                        }
                        discardByte();
                    }
                } catch (EOFException e) {
                    return null;
                }
            }
            discardNext4AndMarkStart();
            while (true) {
                if (this.corePresent == 1) {
                    if (nextFourEquals0x7FFE8001orEof()) {
                        break;
                    }
                    discardQWord();
                } else {
                    if (nextFourEquals0x64582025orEof()) {
                        break;
                    }
                    discardQWord();
                }
            }
            return getSample();
        }

        private void fillBuffer() throws IOException {
            System.err.println("Fill Buffer");
            DataSource dataSource = this.dataSource;
            long j = this.bufferStartPos;
            this.buffer = dataSource.map(j, Math.min(this.dataEnd - j, 67108864L));
        }

        private boolean nextFourEquals0x64582025() throws IOException {
            return nextFourEquals((byte) 100, (byte) 88, (byte) 32, (byte) 37);
        }

        private boolean nextFourEquals0x7FFE8001() throws IOException {
            return nextFourEquals(ByteCompanionObject.MAX_VALUE, (byte) -2, ByteCompanionObject.MIN_VALUE, (byte) 1);
        }

        private boolean nextFourEquals(byte a, byte b, byte c, byte d) throws IOException {
            int iLimit = this.buffer.limit();
            int i = this.inBufferPos;
            if (iLimit - i >= 4) {
                return this.buffer.get(i) == a && this.buffer.get(this.inBufferPos + 1) == b && this.buffer.get(this.inBufferPos + 2) == c && this.buffer.get(this.inBufferPos + 3) == d;
            }
            if (this.bufferStartPos + ((long) i) + 4 < this.dataSource.size()) {
                return false;
            }
            throw new EOFException();
        }

        private boolean nextFourEquals0x64582025orEof() throws IOException {
            return nextFourEqualsOrEof((byte) 100, (byte) 88, (byte) 32, (byte) 37);
        }

        private boolean nextFourEquals0x7FFE8001orEof() throws IOException {
            return nextFourEqualsOrEof(ByteCompanionObject.MAX_VALUE, (byte) -2, ByteCompanionObject.MIN_VALUE, (byte) 1);
        }

        private boolean nextFourEqualsOrEof(byte a, byte b, byte c, byte d) throws IOException {
            int iLimit = this.buffer.limit();
            int i = this.inBufferPos;
            if (iLimit - i >= 4) {
                if ((this.bufferStartPos + ((long) i)) % 1048576 == 0) {
                    PrintStream printStream = System.err;
                    StringBuilder sb = new StringBuilder();
                    sb.append(((this.bufferStartPos + ((long) this.inBufferPos)) / 1024) / 1024);
                    printStream.println(sb.toString());
                }
                return this.buffer.get(this.inBufferPos) == a && this.buffer.get(this.inBufferPos + 1) == b && this.buffer.get(this.inBufferPos + 2) == c && this.buffer.get(this.inBufferPos + 3) == d;
            }
            long j = this.bufferStartPos;
            long j2 = ((long) i) + j + 4;
            long j3 = this.dataEnd;
            if (j2 > j3) {
                return j + ((long) i) == j3;
            }
            this.bufferStartPos = this.start;
            this.inBufferPos = 0;
            fillBuffer();
            return nextFourEquals0x7FFE8001();
        }

        private void discardByte() {
            this.inBufferPos++;
        }

        private void discardQWord() {
            this.inBufferPos += 4;
        }

        private void discardNext4AndMarkStart() {
            long j = this.bufferStartPos;
            int i = this.inBufferPos;
            this.start = j + ((long) i);
            this.inBufferPos = i + 4;
        }

        private ByteBuffer getSample() {
            long j = this.start;
            long j2 = this.bufferStartPos;
            if (j >= j2) {
                this.buffer.position((int) (j - j2));
                Buffer sample = this.buffer.slice();
                sample.limit((int) (((long) this.inBufferPos) - (this.start - this.bufferStartPos)));
                return (ByteBuffer) sample;
            }
            throw new RuntimeException("damn! NAL exceeds buffer");
        }
    }
}
