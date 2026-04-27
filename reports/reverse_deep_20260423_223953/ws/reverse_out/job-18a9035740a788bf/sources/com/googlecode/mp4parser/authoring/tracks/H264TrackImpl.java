package com.googlecode.mp4parser.authoring.tracks;

import com.coremedia.iso.boxes.CompositionTimeToSample;
import com.coremedia.iso.boxes.SampleDependencyTypeBox;
import com.coremedia.iso.boxes.SampleDescriptionBox;
import com.coremedia.iso.boxes.sampleentry.VisualSampleEntry;
import com.googlecode.mp4parser.DataSource;
import com.googlecode.mp4parser.authoring.Sample;
import com.googlecode.mp4parser.authoring.tracks.AbstractH26XTrack;
import com.googlecode.mp4parser.h264.model.PictureParameterSet;
import com.googlecode.mp4parser.h264.model.SeqParameterSet;
import com.googlecode.mp4parser.h264.read.CAVLCReader;
import com.googlecode.mp4parser.util.RangeStartMap;
import com.mp4parser.iso14496.part15.AvcConfigurationBox;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;
import kotlin.UByte;

/* JADX INFO: loaded from: classes.dex */
public class H264TrackImpl extends AbstractH26XTrack {
    private static final Logger LOG = Logger.getLogger(H264TrackImpl.class.getName());
    PictureParameterSet currentPictureParameterSet;
    SeqParameterSet currentSeqParameterSet;
    private boolean determineFrameRate;
    PictureParameterSet firstPictureParameterSet;
    SeqParameterSet firstSeqParameterSet;
    int frameNrInGop;
    private int frametick;
    private int height;
    private String lang;
    RangeStartMap<Integer, byte[]> pictureParameterRangeMap;
    Map<Integer, PictureParameterSet> ppsIdToPps;
    Map<Integer, byte[]> ppsIdToPpsBytes;
    SampleDescriptionBox sampleDescriptionBox;
    private List<Sample> samples;
    private SEIMessage seiMessage;
    RangeStartMap<Integer, byte[]> seqParameterRangeMap;
    Map<Integer, SeqParameterSet> spsIdToSps;
    Map<Integer, byte[]> spsIdToSpsBytes;
    private long timescale;
    private int width;

    public H264TrackImpl(DataSource dataSource, String lang, long timescale, int frametick) throws IOException {
        super(dataSource);
        this.spsIdToSpsBytes = new HashMap();
        this.spsIdToSps = new HashMap();
        this.ppsIdToPpsBytes = new HashMap();
        this.ppsIdToPps = new HashMap();
        this.firstSeqParameterSet = null;
        this.firstPictureParameterSet = null;
        this.currentSeqParameterSet = null;
        this.currentPictureParameterSet = null;
        this.seqParameterRangeMap = new RangeStartMap<>();
        this.pictureParameterRangeMap = new RangeStartMap<>();
        this.frameNrInGop = 0;
        this.determineFrameRate = true;
        this.lang = "eng";
        this.lang = lang;
        this.timescale = timescale;
        this.frametick = frametick;
        if (timescale > 0 && frametick > 0) {
            this.determineFrameRate = false;
        }
        parse(new AbstractH26XTrack.LookAhead(dataSource));
    }

    public H264TrackImpl(DataSource dataSource, String lang) throws IOException {
        this(dataSource, lang, -1L, -1);
    }

    public H264TrackImpl(DataSource dataSource) throws IOException {
        this(dataSource, "eng");
    }

    private void parse(AbstractH26XTrack.LookAhead la) throws IOException {
        this.samples = new LinkedList();
        if (!readSamples(la)) {
            throw new IOException();
        }
        if (!readVariables()) {
            throw new IOException();
        }
        this.sampleDescriptionBox = new SampleDescriptionBox();
        VisualSampleEntry visualSampleEntry = new VisualSampleEntry(VisualSampleEntry.TYPE3);
        visualSampleEntry.setDataReferenceIndex(1);
        visualSampleEntry.setDepth(24);
        visualSampleEntry.setFrameCount(1);
        visualSampleEntry.setHorizresolution(72.0d);
        visualSampleEntry.setVertresolution(72.0d);
        visualSampleEntry.setWidth(this.width);
        visualSampleEntry.setHeight(this.height);
        visualSampleEntry.setCompressorname("AVC Coding");
        AvcConfigurationBox avcConfigurationBox = new AvcConfigurationBox();
        avcConfigurationBox.setSequenceParameterSets(new ArrayList(this.spsIdToSpsBytes.values()));
        avcConfigurationBox.setPictureParameterSets(new ArrayList(this.ppsIdToPpsBytes.values()));
        avcConfigurationBox.setAvcLevelIndication(this.firstSeqParameterSet.level_idc);
        avcConfigurationBox.setAvcProfileIndication(this.firstSeqParameterSet.profile_idc);
        avcConfigurationBox.setBitDepthLumaMinus8(this.firstSeqParameterSet.bit_depth_luma_minus8);
        avcConfigurationBox.setBitDepthChromaMinus8(this.firstSeqParameterSet.bit_depth_chroma_minus8);
        avcConfigurationBox.setChromaFormat(this.firstSeqParameterSet.chroma_format_idc.getId());
        avcConfigurationBox.setConfigurationVersion(1);
        avcConfigurationBox.setLengthSizeMinusOne(3);
        avcConfigurationBox.setProfileCompatibility((this.firstSeqParameterSet.constraint_set_0_flag ? 128 : 0) + (this.firstSeqParameterSet.constraint_set_1_flag ? 64 : 0) + (this.firstSeqParameterSet.constraint_set_2_flag ? 32 : 0) + (this.firstSeqParameterSet.constraint_set_3_flag ? 16 : 0) + (this.firstSeqParameterSet.constraint_set_4_flag ? 8 : 0) + ((int) (this.firstSeqParameterSet.reserved_zero_2bits & 3)));
        visualSampleEntry.addBox(avcConfigurationBox);
        this.sampleDescriptionBox.addBox(visualSampleEntry);
        this.trackMetaData.setCreationTime(new Date());
        this.trackMetaData.setModificationTime(new Date());
        this.trackMetaData.setLanguage(this.lang);
        this.trackMetaData.setTimescale(this.timescale);
        this.trackMetaData.setWidth(this.width);
        this.trackMetaData.setHeight(this.height);
    }

    @Override // com.googlecode.mp4parser.authoring.Track
    public SampleDescriptionBox getSampleDescriptionBox() {
        return this.sampleDescriptionBox;
    }

    @Override // com.googlecode.mp4parser.authoring.Track
    public String getHandler() {
        return "vide";
    }

    @Override // com.googlecode.mp4parser.authoring.Track
    public List<Sample> getSamples() {
        return this.samples;
    }

    private boolean readVariables() {
        this.width = (this.firstSeqParameterSet.pic_width_in_mbs_minus1 + 1) * 16;
        int mult = 2;
        if (this.firstSeqParameterSet.frame_mbs_only_flag) {
            mult = 1;
        }
        this.height = (this.firstSeqParameterSet.pic_height_in_map_units_minus1 + 1) * 16 * mult;
        if (this.firstSeqParameterSet.frame_cropping_flag) {
            int chromaArrayType = 0;
            if (!this.firstSeqParameterSet.residual_color_transform_flag) {
                chromaArrayType = this.firstSeqParameterSet.chroma_format_idc.getId();
            }
            int cropUnitX = 1;
            int cropUnitY = mult;
            if (chromaArrayType != 0) {
                cropUnitX = this.firstSeqParameterSet.chroma_format_idc.getSubWidth();
                cropUnitY = this.firstSeqParameterSet.chroma_format_idc.getSubHeight() * mult;
            }
            this.width -= (this.firstSeqParameterSet.frame_crop_left_offset + this.firstSeqParameterSet.frame_crop_right_offset) * cropUnitX;
            this.height -= (this.firstSeqParameterSet.frame_crop_top_offset + this.firstSeqParameterSet.frame_crop_bottom_offset) * cropUnitY;
        }
        return true;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r1v0 */
    /* JADX WARN: Type inference failed for: r1v1, types: [com.googlecode.mp4parser.authoring.tracks.H264TrackImpl$1FirstVclNalDetector] */
    /* JADX WARN: Type inference failed for: r1v10 */
    /* JADX WARN: Type inference failed for: r1v11 */
    /* JADX WARN: Type inference failed for: r1v12 */
    /* JADX WARN: Type inference failed for: r1v13 */
    /* JADX WARN: Type inference failed for: r1v14 */
    /* JADX WARN: Type inference failed for: r1v15 */
    /* JADX WARN: Type inference failed for: r1v3 */
    /* JADX WARN: Type inference failed for: r1v4 */
    /* JADX WARN: Type inference failed for: r1v5 */
    /* JADX WARN: Type inference failed for: r1v6 */
    /* JADX WARN: Type inference failed for: r1v7 */
    /* JADX WARN: Type inference failed for: r1v8 */
    /* JADX WARN: Type inference failed for: r1v9 */
    /* JADX WARN: Type inference failed for: r6v1, types: [com.googlecode.mp4parser.authoring.tracks.H264TrackImpl$1FirstVclNalDetector] */
    private boolean readSamples(AbstractH26XTrack.LookAhead lookAhead) throws IOException {
        ArrayList arrayList = new ArrayList();
        ?? r1 = 0;
        while (true) {
            ByteBuffer byteBufferFindNextNal = findNextNal(lookAhead);
            if (byteBufferFindNextNal != null) {
                byte b = byteBufferFindNextNal.get(0);
                int i = (b >> 5) & 3;
                int i2 = b & 31;
                switch (i2) {
                    case 1:
                    case 2:
                    case 3:
                    case 4:
                    case 5:
                        ?? r6 = new Object(byteBufferFindNextNal, i, i2) { // from class: com.googlecode.mp4parser.authoring.tracks.H264TrackImpl.1FirstVclNalDetector
                            boolean bottom_field_flag;
                            int delta_pic_order_cnt_0;
                            int delta_pic_order_cnt_1;
                            int delta_pic_order_cnt_bottom;
                            boolean field_pic_flag;
                            int frame_num;
                            boolean idrPicFlag;
                            int idr_pic_id;
                            int nal_ref_idc;
                            int pic_order_cnt_lsb;
                            int pic_order_cnt_type;
                            int pic_parameter_set_id;

                            {
                                InputStream bs = H264TrackImpl.cleanBuffer(H264TrackImpl.this.new ByteBufferBackedInputStream(byteBufferFindNextNal));
                                SliceHeader sh = new SliceHeader(bs, H264TrackImpl.this.spsIdToSps, H264TrackImpl.this.ppsIdToPps, i2 == 5);
                                this.frame_num = sh.frame_num;
                                this.pic_parameter_set_id = sh.pic_parameter_set_id;
                                this.field_pic_flag = sh.field_pic_flag;
                                this.bottom_field_flag = sh.bottom_field_flag;
                                this.nal_ref_idc = i;
                                this.pic_order_cnt_type = H264TrackImpl.this.spsIdToSps.get(Integer.valueOf(H264TrackImpl.this.ppsIdToPps.get(Integer.valueOf(sh.pic_parameter_set_id)).seq_parameter_set_id)).pic_order_cnt_type;
                                this.delta_pic_order_cnt_bottom = sh.delta_pic_order_cnt_bottom;
                                this.pic_order_cnt_lsb = sh.pic_order_cnt_lsb;
                                this.delta_pic_order_cnt_0 = sh.delta_pic_order_cnt_0;
                                this.delta_pic_order_cnt_1 = sh.delta_pic_order_cnt_1;
                                this.idr_pic_id = sh.idr_pic_id;
                            }

                            boolean isFirstInNew(C1FirstVclNalDetector nu) {
                                boolean z;
                                boolean z2;
                                boolean z3;
                                if (nu.frame_num != this.frame_num || nu.pic_parameter_set_id != this.pic_parameter_set_id || (z = nu.field_pic_flag) != this.field_pic_flag) {
                                    return true;
                                }
                                if ((z && nu.bottom_field_flag != this.bottom_field_flag) || nu.nal_ref_idc != this.nal_ref_idc) {
                                    return true;
                                }
                                if (nu.pic_order_cnt_type == 0 && this.pic_order_cnt_type == 0 && (nu.pic_order_cnt_lsb != this.pic_order_cnt_lsb || nu.delta_pic_order_cnt_bottom != this.delta_pic_order_cnt_bottom)) {
                                    return true;
                                }
                                if (!(nu.pic_order_cnt_type == 1 && this.pic_order_cnt_type == 1 && (nu.delta_pic_order_cnt_0 != this.delta_pic_order_cnt_0 || nu.delta_pic_order_cnt_1 != this.delta_pic_order_cnt_1)) && (z2 = nu.idrPicFlag) == (z3 = this.idrPicFlag)) {
                                    return z2 && z3 && nu.idr_pic_id != this.idr_pic_id;
                                }
                                return true;
                            }
                        };
                        if (r1 == 0) {
                            r1 = r6;
                        } else {
                            boolean zIsFirstInNew = r1.isFirstInNew(r6);
                            r1 = r1;
                            if (zIsFirstInNew) {
                                createSample(arrayList);
                                r1 = r6;
                            }
                        }
                        arrayList.add((ByteBuffer) byteBufferFindNextNal.rewind());
                        continue;
                    case 6:
                        if (r1 != 0) {
                            createSample(arrayList);
                            r1 = 0;
                        }
                        this.seiMessage = new SEIMessage(cleanBuffer(new ByteBufferBackedInputStream(byteBufferFindNextNal)), this.currentSeqParameterSet);
                        arrayList.add(byteBufferFindNextNal);
                        continue;
                    case 7:
                        if (r1 != 0) {
                            createSample(arrayList);
                            r1 = 0;
                        }
                        handleSPS((ByteBuffer) byteBufferFindNextNal.rewind());
                        continue;
                    case 8:
                        if (r1 != 0) {
                            createSample(arrayList);
                            r1 = 0;
                        }
                        handlePPS((ByteBuffer) byteBufferFindNextNal.rewind());
                        continue;
                    case 9:
                        if (r1 != 0) {
                            createSample(arrayList);
                            r1 = 0;
                        }
                        arrayList.add(byteBufferFindNextNal);
                        continue;
                    case 10:
                    case 11:
                        break;
                    case 12:
                    default:
                        System.err.println("Unknown NAL unit type: " + i2);
                        continue;
                    case 13:
                        throw new RuntimeException("Sequence parameter set extension is not yet handled. Needs TLC.");
                }
            }
        }
        createSample(arrayList);
        this.decodingTimes = new long[this.samples.size()];
        Arrays.fill(this.decodingTimes, this.frametick);
        return true;
    }

    private void createSample(List<ByteBuffer> buffered) throws IOException {
        int stdpValue = 22;
        boolean IdrPicFlag = false;
        for (ByteBuffer nal : buffered) {
            int type = nal.get(0);
            int nal_unit_type = type & 31;
            if (nal_unit_type == 5) {
                IdrPicFlag = true;
            }
        }
        if (IdrPicFlag) {
            stdpValue = 22 + 16;
        }
        InputStream bs = cleanBuffer(new ByteBufferBackedInputStream(buffered.get(buffered.size() - 1)));
        SliceHeader sh = new SliceHeader(bs, this.spsIdToSps, this.ppsIdToPps, IdrPicFlag);
        if (sh.slice_type == SliceHeader.SliceType.B) {
            stdpValue += 4;
        }
        Sample bb = createSampleObject(buffered);
        buffered.clear();
        SEIMessage sEIMessage = this.seiMessage;
        if (sEIMessage == null || sEIMessage.n_frames == 0) {
            this.frameNrInGop = 0;
        }
        int offset = 0;
        SEIMessage sEIMessage2 = this.seiMessage;
        if (sEIMessage2 == null || !sEIMessage2.clock_timestamp_flag) {
            SEIMessage sEIMessage3 = this.seiMessage;
            if (sEIMessage3 != null && sEIMessage3.removal_delay_flag) {
                offset = this.seiMessage.dpb_removal_delay / 2;
            }
        } else {
            offset = this.seiMessage.n_frames - this.frameNrInGop;
        }
        this.ctts.add(new CompositionTimeToSample.Entry(1, this.frametick * offset));
        this.sdtp.add(new SampleDependencyTypeBox.Entry(stdpValue));
        this.frameNrInGop++;
        this.samples.add(bb);
        if (IdrPicFlag) {
            this.stss.add(Integer.valueOf(this.samples.size()));
        }
    }

    private void handlePPS(ByteBuffer data) throws IOException {
        InputStream is = new ByteBufferBackedInputStream(data);
        is.read();
        PictureParameterSet _pictureParameterSet = PictureParameterSet.read(is);
        if (this.firstPictureParameterSet == null) {
            this.firstPictureParameterSet = _pictureParameterSet;
        }
        this.currentPictureParameterSet = _pictureParameterSet;
        byte[] ppsBytes = toArray((ByteBuffer) data.rewind());
        byte[] oldPpsSameId = this.ppsIdToPpsBytes.get(Integer.valueOf(_pictureParameterSet.pic_parameter_set_id));
        if (oldPpsSameId != null && !Arrays.equals(oldPpsSameId, ppsBytes)) {
            throw new RuntimeException("OMG - I got two SPS with same ID but different settings! (AVC3 is the solution)");
        }
        if (oldPpsSameId == null) {
            this.pictureParameterRangeMap.put(Integer.valueOf(this.samples.size()), ppsBytes);
        }
        this.ppsIdToPpsBytes.put(Integer.valueOf(_pictureParameterSet.pic_parameter_set_id), ppsBytes);
        this.ppsIdToPps.put(Integer.valueOf(_pictureParameterSet.pic_parameter_set_id), _pictureParameterSet);
    }

    private void handleSPS(ByteBuffer data) throws IOException {
        InputStream spsInputStream = cleanBuffer(new ByteBufferBackedInputStream(data));
        spsInputStream.read();
        SeqParameterSet _seqParameterSet = SeqParameterSet.read(spsInputStream);
        if (this.firstSeqParameterSet == null) {
            this.firstSeqParameterSet = _seqParameterSet;
            configureFramerate();
        }
        this.currentSeqParameterSet = _seqParameterSet;
        byte[] spsBytes = toArray((ByteBuffer) data.rewind());
        byte[] oldSpsSameId = this.spsIdToSpsBytes.get(Integer.valueOf(_seqParameterSet.seq_parameter_set_id));
        if (oldSpsSameId != null && !Arrays.equals(oldSpsSameId, spsBytes)) {
            throw new RuntimeException("OMG - I got two SPS with same ID but different settings!");
        }
        if (oldSpsSameId != null) {
            this.seqParameterRangeMap.put(Integer.valueOf(this.samples.size()), spsBytes);
        }
        this.spsIdToSpsBytes.put(Integer.valueOf(_seqParameterSet.seq_parameter_set_id), spsBytes);
        this.spsIdToSps.put(Integer.valueOf(_seqParameterSet.seq_parameter_set_id), _seqParameterSet);
    }

    private void configureFramerate() {
        if (this.determineFrameRate) {
            if (this.firstSeqParameterSet.vuiParams != null) {
                this.timescale = this.firstSeqParameterSet.vuiParams.time_scale >> 1;
                int i = this.firstSeqParameterSet.vuiParams.num_units_in_tick;
                this.frametick = i;
                if (this.timescale == 0 || i == 0) {
                    System.err.println("Warning: vuiParams contain invalid values: time_scale: " + this.timescale + " and frame_tick: " + this.frametick + ". Setting frame rate to 25fps");
                    this.timescale = 90000L;
                    this.frametick = 3600;
                    return;
                }
                return;
            }
            System.err.println("Warning: Can't determine frame rate. Guessing 25 fps");
            this.timescale = 90000L;
            this.frametick = 3600;
        }
    }

    public static class SliceHeader {
        public boolean bottom_field_flag;
        public int colour_plane_id;
        public int delta_pic_order_cnt_0;
        public int delta_pic_order_cnt_1;
        public int delta_pic_order_cnt_bottom;
        public boolean field_pic_flag;
        public int first_mb_in_slice;
        public int frame_num;
        public int idr_pic_id;
        public int pic_order_cnt_lsb;
        public int pic_parameter_set_id;
        public SliceType slice_type;

        public enum SliceType {
            P,
            B,
            I,
            SP,
            SI;

            /* JADX INFO: renamed from: values, reason: to resolve conflict with enum method */
            public static SliceType[] valuesCustom() {
                SliceType[] sliceTypeArrValuesCustom = values();
                int length = sliceTypeArrValuesCustom.length;
                SliceType[] sliceTypeArr = new SliceType[length];
                System.arraycopy(sliceTypeArrValuesCustom, 0, sliceTypeArr, 0, length);
                return sliceTypeArr;
            }
        }

        public SliceHeader(InputStream is, Map<Integer, SeqParameterSet> spss, Map<Integer, PictureParameterSet> ppss, boolean IdrPicFlag) {
            this.field_pic_flag = false;
            this.bottom_field_flag = false;
            try {
                is.read();
                CAVLCReader reader = new CAVLCReader(is);
                this.first_mb_in_slice = reader.readUE("SliceHeader: first_mb_in_slice");
                int sliceTypeInt = reader.readUE("SliceHeader: slice_type");
                switch (sliceTypeInt) {
                    case 0:
                    case 5:
                        this.slice_type = SliceType.P;
                        break;
                    case 1:
                    case 6:
                        this.slice_type = SliceType.B;
                        break;
                    case 2:
                    case 7:
                        this.slice_type = SliceType.I;
                        break;
                    case 3:
                    case 8:
                        this.slice_type = SliceType.SP;
                        break;
                    case 4:
                    case 9:
                        this.slice_type = SliceType.SI;
                        break;
                }
                int ue = reader.readUE("SliceHeader: pic_parameter_set_id");
                this.pic_parameter_set_id = ue;
                PictureParameterSet pps = ppss.get(Integer.valueOf(ue));
                SeqParameterSet sps = spss.get(Integer.valueOf(pps.seq_parameter_set_id));
                if (sps.residual_color_transform_flag) {
                    this.colour_plane_id = reader.readU(2, "SliceHeader: colour_plane_id");
                }
                this.frame_num = reader.readU(sps.log2_max_frame_num_minus4 + 4, "SliceHeader: frame_num");
                if (!sps.frame_mbs_only_flag) {
                    boolean bool = reader.readBool("SliceHeader: field_pic_flag");
                    this.field_pic_flag = bool;
                    if (bool) {
                        this.bottom_field_flag = reader.readBool("SliceHeader: bottom_field_flag");
                    }
                }
                if (IdrPicFlag) {
                    this.idr_pic_id = reader.readUE("SliceHeader: idr_pic_id");
                }
                if (sps.pic_order_cnt_type == 0) {
                    this.pic_order_cnt_lsb = reader.readU(sps.log2_max_pic_order_cnt_lsb_minus4 + 4, "SliceHeader: pic_order_cnt_lsb");
                    if (pps.bottom_field_pic_order_in_frame_present_flag && !this.field_pic_flag) {
                        this.delta_pic_order_cnt_bottom = reader.readSE("SliceHeader: delta_pic_order_cnt_bottom");
                    }
                }
                if (sps.pic_order_cnt_type == 1 && !sps.delta_pic_order_always_zero_flag) {
                    this.delta_pic_order_cnt_0 = reader.readSE("delta_pic_order_cnt_0");
                    if (pps.bottom_field_pic_order_in_frame_present_flag && !this.field_pic_flag) {
                        this.delta_pic_order_cnt_1 = reader.readSE("delta_pic_order_cnt_1");
                    }
                }
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }

        public String toString() {
            return "SliceHeader{first_mb_in_slice=" + this.first_mb_in_slice + ", slice_type=" + this.slice_type + ", pic_parameter_set_id=" + this.pic_parameter_set_id + ", colour_plane_id=" + this.colour_plane_id + ", frame_num=" + this.frame_num + ", field_pic_flag=" + this.field_pic_flag + ", bottom_field_flag=" + this.bottom_field_flag + ", idr_pic_id=" + this.idr_pic_id + ", pic_order_cnt_lsb=" + this.pic_order_cnt_lsb + ", delta_pic_order_cnt_bottom=" + this.delta_pic_order_cnt_bottom + '}';
        }
    }

    public class ByteBufferBackedInputStream extends InputStream {
        private final ByteBuffer buf;

        public ByteBufferBackedInputStream(ByteBuffer buf) {
            this.buf = buf.duplicate();
        }

        @Override // java.io.InputStream
        public int read() throws IOException {
            if (!this.buf.hasRemaining()) {
                return -1;
            }
            return this.buf.get() & UByte.MAX_VALUE;
        }

        @Override // java.io.InputStream
        public int read(byte[] bytes, int off, int len) throws IOException {
            if (!this.buf.hasRemaining()) {
                return -1;
            }
            int len2 = Math.min(len, this.buf.remaining());
            this.buf.get(bytes, off, len2);
            return len2;
        }
    }

    public class SEIMessage {
        boolean clock_timestamp_flag;
        int cnt_dropped_flag;
        int counting_type;
        int cpb_removal_delay;
        int ct_type;
        int discontinuity_flag;
        int dpb_removal_delay;
        int full_timestamp_flag;
        int hours_value;
        int minutes_value;
        int n_frames;
        int nuit_field_based_flag;
        int payloadSize;
        int payloadType;
        int pic_struct;
        boolean removal_delay_flag;
        int seconds_value;
        SeqParameterSet sps;
        int time_offset;
        int time_offset_length;

        public SEIMessage(InputStream inputStream, SeqParameterSet seqParameterSet) throws IOException {
            int i;
            int i2;
            int i3;
            boolean z = false;
            this.payloadType = 0;
            this.payloadSize = 0;
            this.sps = seqParameterSet;
            inputStream.read();
            int iAvailable = inputStream.available();
            int i4 = 0;
            while (i4 < iAvailable) {
                this.payloadType = z ? 1 : 0;
                this.payloadSize = z ? 1 : 0;
                int i5 = inputStream.read();
                int i6 = i4 + 1;
                while (i5 == 255) {
                    this.payloadType += i5;
                    i5 = inputStream.read();
                    i6++;
                    z = false;
                }
                this.payloadType += i5;
                int i7 = inputStream.read();
                i4 = i6 + 1;
                while (i7 == 255) {
                    this.payloadSize += i7;
                    i7 = inputStream.read();
                    i4++;
                    z = false;
                }
                int i8 = this.payloadSize + i7;
                this.payloadSize = i8;
                if (iAvailable - i4 < i8) {
                    i4 = iAvailable;
                } else if (this.payloadType != 1) {
                    for (int i9 = 0; i9 < this.payloadSize; i9++) {
                        inputStream.read();
                        i4++;
                    }
                } else if (seqParameterSet.vuiParams != null && (seqParameterSet.vuiParams.nalHRDParams != null || seqParameterSet.vuiParams.vclHRDParams != null || seqParameterSet.vuiParams.pic_struct_present_flag)) {
                    byte[] bArr = new byte[this.payloadSize];
                    inputStream.read(bArr);
                    int i10 = i4 + this.payloadSize;
                    CAVLCReader cAVLCReader = new CAVLCReader(new ByteArrayInputStream(bArr));
                    if (seqParameterSet.vuiParams.nalHRDParams != null || seqParameterSet.vuiParams.vclHRDParams != null) {
                        this.removal_delay_flag = true;
                        this.cpb_removal_delay = cAVLCReader.readU(seqParameterSet.vuiParams.nalHRDParams.cpb_removal_delay_length_minus1 + 1, "SEI: cpb_removal_delay");
                        this.dpb_removal_delay = cAVLCReader.readU(seqParameterSet.vuiParams.nalHRDParams.dpb_output_delay_length_minus1 + 1, "SEI: dpb_removal_delay");
                    } else {
                        this.removal_delay_flag = z;
                    }
                    if (!seqParameterSet.vuiParams.pic_struct_present_flag) {
                        i = i10;
                    } else {
                        int u = cAVLCReader.readU(4, "SEI: pic_struct");
                        this.pic_struct = u;
                        switch (u) {
                            case 3:
                            case 4:
                            case 7:
                                i2 = 2;
                                break;
                            case 5:
                            case 6:
                            case 8:
                                i2 = 3;
                                break;
                            default:
                                i2 = 1;
                                break;
                        }
                        int i11 = 0;
                        while (i11 < i2) {
                            boolean bool = cAVLCReader.readBool("pic_timing SEI: clock_timestamp_flag[" + i11 + "]");
                            this.clock_timestamp_flag = bool;
                            if (bool) {
                                this.ct_type = cAVLCReader.readU(2, "pic_timing SEI: ct_type");
                                this.nuit_field_based_flag = cAVLCReader.readU(1, "pic_timing SEI: nuit_field_based_flag");
                                this.counting_type = cAVLCReader.readU(5, "pic_timing SEI: counting_type");
                                this.full_timestamp_flag = cAVLCReader.readU(1, "pic_timing SEI: full_timestamp_flag");
                                this.discontinuity_flag = cAVLCReader.readU(1, "pic_timing SEI: discontinuity_flag");
                                this.cnt_dropped_flag = cAVLCReader.readU(1, "pic_timing SEI: cnt_dropped_flag");
                                this.n_frames = cAVLCReader.readU(8, "pic_timing SEI: n_frames");
                                i3 = i10;
                                if (this.full_timestamp_flag == 1) {
                                    this.seconds_value = cAVLCReader.readU(6, "pic_timing SEI: seconds_value");
                                    this.minutes_value = cAVLCReader.readU(6, "pic_timing SEI: minutes_value");
                                    this.hours_value = cAVLCReader.readU(5, "pic_timing SEI: hours_value");
                                } else if (cAVLCReader.readBool("pic_timing SEI: seconds_flag")) {
                                    this.seconds_value = cAVLCReader.readU(6, "pic_timing SEI: seconds_value");
                                    if (cAVLCReader.readBool("pic_timing SEI: minutes_flag")) {
                                        this.minutes_value = cAVLCReader.readU(6, "pic_timing SEI: minutes_value");
                                        if (cAVLCReader.readBool("pic_timing SEI: hours_flag")) {
                                            this.hours_value = cAVLCReader.readU(5, "pic_timing SEI: hours_value");
                                        }
                                    }
                                }
                                if (seqParameterSet.vuiParams.nalHRDParams != null) {
                                    this.time_offset_length = seqParameterSet.vuiParams.nalHRDParams.time_offset_length;
                                } else if (seqParameterSet.vuiParams.vclHRDParams != null) {
                                    this.time_offset_length = seqParameterSet.vuiParams.vclHRDParams.time_offset_length;
                                } else {
                                    this.time_offset_length = 24;
                                }
                                this.time_offset = cAVLCReader.readU(24, "pic_timing SEI: time_offset");
                            } else {
                                i3 = i10;
                            }
                            i11++;
                            i10 = i3;
                        }
                        i = i10;
                    }
                    i4 = i;
                } else {
                    for (int i12 = 0; i12 < this.payloadSize; i12++) {
                        inputStream.read();
                        i4++;
                    }
                }
                H264TrackImpl.LOG.fine(toString());
                z = false;
            }
        }

        public String toString() {
            String out = "SEIMessage{payloadType=" + this.payloadType + ", payloadSize=" + this.payloadSize;
            if (this.payloadType == 1) {
                if (this.sps.vuiParams.nalHRDParams != null || this.sps.vuiParams.vclHRDParams != null) {
                    out = String.valueOf(out) + ", cpb_removal_delay=" + this.cpb_removal_delay + ", dpb_removal_delay=" + this.dpb_removal_delay;
                }
                if (this.sps.vuiParams.pic_struct_present_flag) {
                    out = String.valueOf(out) + ", pic_struct=" + this.pic_struct;
                    if (this.clock_timestamp_flag) {
                        out = String.valueOf(out) + ", ct_type=" + this.ct_type + ", nuit_field_based_flag=" + this.nuit_field_based_flag + ", counting_type=" + this.counting_type + ", full_timestamp_flag=" + this.full_timestamp_flag + ", discontinuity_flag=" + this.discontinuity_flag + ", cnt_dropped_flag=" + this.cnt_dropped_flag + ", n_frames=" + this.n_frames + ", seconds_value=" + this.seconds_value + ", minutes_value=" + this.minutes_value + ", hours_value=" + this.hours_value + ", time_offset_length=" + this.time_offset_length + ", time_offset=" + this.time_offset;
                    }
                }
            }
            return String.valueOf(out) + '}';
        }
    }
}
