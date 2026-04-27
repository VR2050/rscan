package com.google.android.exoplayer2.util;

import android.text.TextUtils;
import com.coremedia.iso.boxes.sampleentry.AudioSampleEntry;
import com.coremedia.iso.boxes.sampleentry.VisualSampleEntry;
import com.googlecode.mp4parser.boxes.AC3SpecificBox;
import com.googlecode.mp4parser.boxes.EC3SpecificBox;
import java.util.ArrayList;

/* JADX INFO: loaded from: classes2.dex */
public final class MimeTypes {
    public static final String APPLICATION_CAMERA_MOTION = "application/x-camera-motion";
    public static final String APPLICATION_CEA608 = "application/cea-608";
    public static final String APPLICATION_CEA708 = "application/cea-708";
    public static final String APPLICATION_DVBSUBS = "application/dvbsubs";
    public static final String APPLICATION_EMSG = "application/x-emsg";
    public static final String APPLICATION_EXIF = "application/x-exif";
    public static final String APPLICATION_ICY = "application/x-icy";
    public static final String APPLICATION_ID3 = "application/id3";
    public static final String APPLICATION_M3U8 = "application/x-mpegURL";
    public static final String APPLICATION_MP4 = "application/mp4";
    public static final String APPLICATION_MP4CEA608 = "application/x-mp4-cea-608";
    public static final String APPLICATION_MP4VTT = "application/x-mp4-vtt";
    public static final String APPLICATION_MPD = "application/dash+xml";
    public static final String APPLICATION_PGS = "application/pgs";
    public static final String APPLICATION_RAWCC = "application/x-rawcc";
    public static final String APPLICATION_SCTE35 = "application/x-scte35";
    public static final String APPLICATION_SS = "application/vnd.ms-sstr+xml";
    public static final String APPLICATION_SUBRIP = "application/x-subrip";
    public static final String APPLICATION_TTML = "application/ttml+xml";
    public static final String APPLICATION_TX3G = "application/x-quicktime-tx3g";
    public static final String APPLICATION_VOBSUB = "application/vobsub";
    public static final String APPLICATION_WEBM = "application/webm";
    public static final String AUDIO_AAC = "audio/mp4a-latm";
    public static final String AUDIO_AC3 = "audio/ac3";
    public static final String AUDIO_ALAC = "audio/alac";
    public static final String AUDIO_ALAW = "audio/g711-alaw";
    public static final String AUDIO_AMR_NB = "audio/3gpp";
    public static final String AUDIO_AMR_WB = "audio/amr-wb";
    public static final String AUDIO_DTS = "audio/vnd.dts";
    public static final String AUDIO_DTS_EXPRESS = "audio/vnd.dts.hd;profile=lbr";
    public static final String AUDIO_DTS_HD = "audio/vnd.dts.hd";
    public static final String AUDIO_E_AC3 = "audio/eac3";
    public static final String AUDIO_E_AC3_JOC = "audio/eac3-joc";
    public static final String AUDIO_FLAC = "audio/flac";
    public static final String AUDIO_MLAW = "audio/g711-mlaw";
    public static final String AUDIO_MP4 = "audio/mp4";
    public static final String AUDIO_MPEG = "audio/mpeg";
    public static final String AUDIO_MPEG_L1 = "audio/mpeg-L1";
    public static final String AUDIO_MPEG_L2 = "audio/mpeg-L2";
    public static final String AUDIO_MSGSM = "audio/gsm";
    public static final String AUDIO_OPUS = "audio/opus";
    public static final String AUDIO_RAW = "audio/raw";
    public static final String AUDIO_TRUEHD = "audio/true-hd";
    public static final String AUDIO_UNKNOWN = "audio/x-unknown";
    public static final String AUDIO_VORBIS = "audio/vorbis";
    public static final String AUDIO_WEBM = "audio/webm";
    public static final String BASE_TYPE_APPLICATION = "application";
    public static final String BASE_TYPE_AUDIO = "audio";
    public static final String BASE_TYPE_TEXT = "text";
    public static final String BASE_TYPE_VIDEO = "video";
    public static final String TEXT_SSA = "text/x-ssa";
    public static final String TEXT_VTT = "text/vtt";
    public static final String VIDEO_H263 = "video/3gpp";
    public static final String VIDEO_H264 = "video/avc";
    public static final String VIDEO_H265 = "video/hevc";
    public static final String VIDEO_MP4 = "video/mp4";
    public static final String VIDEO_MP4V = "video/mp4v-es";
    public static final String VIDEO_MPEG = "video/mpeg";
    public static final String VIDEO_MPEG2 = "video/mpeg2";
    public static final String VIDEO_UNKNOWN = "video/x-unknown";
    public static final String VIDEO_VC1 = "video/wvc1";
    public static final String VIDEO_VP8 = "video/x-vnd.on2.vp8";
    public static final String VIDEO_VP9 = "video/x-vnd.on2.vp9";
    public static final String VIDEO_WEBM = "video/webm";
    private static final ArrayList<CustomMimeType> customMimeTypes = new ArrayList<>();

    public static void registerCustomMimeType(String mimeType, String codecPrefix, int trackType) {
        CustomMimeType customMimeType = new CustomMimeType(mimeType, codecPrefix, trackType);
        int customMimeTypeCount = customMimeTypes.size();
        int i = 0;
        while (true) {
            if (i >= customMimeTypeCount) {
                break;
            }
            if (!mimeType.equals(customMimeTypes.get(i).mimeType)) {
                i++;
            } else {
                customMimeTypes.remove(i);
                break;
            }
        }
        customMimeTypes.add(customMimeType);
    }

    public static boolean isAudio(String mimeType) {
        return "audio".equals(getTopLevelType(mimeType));
    }

    public static boolean isVideo(String mimeType) {
        return "video".equals(getTopLevelType(mimeType));
    }

    public static boolean isText(String mimeType) {
        return "text".equals(getTopLevelType(mimeType));
    }

    public static boolean isApplication(String mimeType) {
        return BASE_TYPE_APPLICATION.equals(getTopLevelType(mimeType));
    }

    public static String getVideoMediaMimeType(String codecs) {
        if (codecs == null) {
            return null;
        }
        String[] codecList = Util.splitCodecs(codecs);
        for (String codec : codecList) {
            String mimeType = getMediaMimeType(codec);
            if (mimeType != null && isVideo(mimeType)) {
                return mimeType;
            }
        }
        return null;
    }

    public static String getAudioMediaMimeType(String codecs) {
        if (codecs == null) {
            return null;
        }
        String[] codecList = Util.splitCodecs(codecs);
        for (String codec : codecList) {
            String mimeType = getMediaMimeType(codec);
            if (mimeType != null && isAudio(mimeType)) {
                return mimeType;
            }
        }
        return null;
    }

    public static String getMediaMimeType(String codec) {
        if (codec == null) {
            return null;
        }
        String codec2 = Util.toLowerInvariant(codec.trim());
        if (codec2.startsWith(VisualSampleEntry.TYPE3) || codec2.startsWith(VisualSampleEntry.TYPE4)) {
            return "video/avc";
        }
        if (codec2.startsWith(VisualSampleEntry.TYPE7) || codec2.startsWith(VisualSampleEntry.TYPE6)) {
            return VIDEO_H265;
        }
        if (codec2.startsWith("vp9") || codec2.startsWith("vp09")) {
            return VIDEO_VP9;
        }
        if (codec2.startsWith("vp8") || codec2.startsWith("vp08")) {
            return VIDEO_VP8;
        }
        if (codec2.startsWith(AudioSampleEntry.TYPE3)) {
            String mimeType = null;
            if (codec2.startsWith("mp4a.")) {
                String objectTypeString = codec2.substring(5);
                if (objectTypeString.length() >= 2) {
                    try {
                        String objectTypeHexString = Util.toUpperInvariant(objectTypeString.substring(0, 2));
                        int objectTypeInt = Integer.parseInt(objectTypeHexString, 16);
                        mimeType = getMimeTypeFromMp4ObjectType(objectTypeInt);
                    } catch (NumberFormatException e) {
                    }
                }
            }
            return mimeType == null ? AUDIO_AAC : mimeType;
        }
        if (codec2.startsWith(AudioSampleEntry.TYPE8) || codec2.startsWith(AC3SpecificBox.TYPE)) {
            return AUDIO_AC3;
        }
        if (codec2.startsWith(AudioSampleEntry.TYPE9) || codec2.startsWith(EC3SpecificBox.TYPE)) {
            return AUDIO_E_AC3;
        }
        if (codec2.startsWith("ec+3")) {
            return AUDIO_E_AC3_JOC;
        }
        if (codec2.startsWith("dtsc") || codec2.startsWith(AudioSampleEntry.TYPE13)) {
            return AUDIO_DTS;
        }
        if (codec2.startsWith(AudioSampleEntry.TYPE12) || codec2.startsWith(AudioSampleEntry.TYPE11)) {
            return AUDIO_DTS_HD;
        }
        if (codec2.startsWith("opus")) {
            return AUDIO_OPUS;
        }
        if (codec2.startsWith("vorbis")) {
            return AUDIO_VORBIS;
        }
        if (codec2.startsWith("flac")) {
            return AUDIO_FLAC;
        }
        return getCustomMimeTypeForCodec(codec2);
    }

    public static String getMimeTypeFromMp4ObjectType(int objectType) {
        if (objectType == 32) {
            return VIDEO_MP4V;
        }
        if (objectType == 33) {
            return "video/avc";
        }
        if (objectType == 35) {
            return VIDEO_H265;
        }
        if (objectType == 64) {
            return AUDIO_AAC;
        }
        if (objectType == 163) {
            return VIDEO_VC1;
        }
        if (objectType == 177) {
            return VIDEO_VP9;
        }
        if (objectType == 165) {
            return AUDIO_AC3;
        }
        if (objectType != 166) {
            switch (objectType) {
                case 96:
                case 97:
                case 98:
                case 99:
                case 100:
                case 101:
                    return VIDEO_MPEG2;
                case 102:
                case 103:
                case 104:
                    return AUDIO_AAC;
                case 105:
                case 107:
                    return AUDIO_MPEG;
                case 106:
                    return VIDEO_MPEG;
                default:
                    switch (objectType) {
                        case 169:
                        case 172:
                            return AUDIO_DTS;
                        case 170:
                        case 171:
                            return AUDIO_DTS_HD;
                        case 173:
                            return AUDIO_OPUS;
                        default:
                            return null;
                    }
            }
        }
        return AUDIO_E_AC3;
    }

    public static int getTrackType(String mimeType) {
        if (TextUtils.isEmpty(mimeType)) {
            return -1;
        }
        if (isAudio(mimeType)) {
            return 1;
        }
        if (isVideo(mimeType)) {
            return 2;
        }
        if (isText(mimeType) || APPLICATION_CEA608.equals(mimeType) || APPLICATION_CEA708.equals(mimeType) || APPLICATION_MP4CEA608.equals(mimeType) || APPLICATION_SUBRIP.equals(mimeType) || APPLICATION_TTML.equals(mimeType) || APPLICATION_TX3G.equals(mimeType) || APPLICATION_MP4VTT.equals(mimeType) || APPLICATION_RAWCC.equals(mimeType) || APPLICATION_VOBSUB.equals(mimeType) || APPLICATION_PGS.equals(mimeType) || APPLICATION_DVBSUBS.equals(mimeType)) {
            return 3;
        }
        if (APPLICATION_ID3.equals(mimeType) || APPLICATION_EMSG.equals(mimeType) || APPLICATION_SCTE35.equals(mimeType)) {
            return 4;
        }
        if (APPLICATION_CAMERA_MOTION.equals(mimeType)) {
            return 5;
        }
        return getTrackTypeForCustomMimeType(mimeType);
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Failed to restore switch over string. Please report as a decompilation issue */
    /* JADX WARN: Removed duplicated region for block: B:23:0x004a  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static int getEncoding(java.lang.String r7) {
        /*
            int r0 = r7.hashCode()
            r1 = 0
            r2 = 4
            r3 = 3
            r4 = 2
            r5 = 1
            r6 = 5
            switch(r0) {
                case -2123537834: goto L40;
                case -1095064472: goto L36;
                case 187078296: goto L2c;
                case 1504578661: goto L22;
                case 1505942594: goto L18;
                case 1556697186: goto Le;
                default: goto Ld;
            }
        Ld:
            goto L4a
        Le:
            java.lang.String r0 = "audio/true-hd"
            boolean r0 = r7.equals(r0)
            if (r0 == 0) goto Ld
            r0 = 5
            goto L4b
        L18:
            java.lang.String r0 = "audio/vnd.dts.hd"
            boolean r0 = r7.equals(r0)
            if (r0 == 0) goto Ld
            r0 = 4
            goto L4b
        L22:
            java.lang.String r0 = "audio/eac3"
            boolean r0 = r7.equals(r0)
            if (r0 == 0) goto Ld
            r0 = 1
            goto L4b
        L2c:
            java.lang.String r0 = "audio/ac3"
            boolean r0 = r7.equals(r0)
            if (r0 == 0) goto Ld
            r0 = 0
            goto L4b
        L36:
            java.lang.String r0 = "audio/vnd.dts"
            boolean r0 = r7.equals(r0)
            if (r0 == 0) goto Ld
            r0 = 3
            goto L4b
        L40:
            java.lang.String r0 = "audio/eac3-joc"
            boolean r0 = r7.equals(r0)
            if (r0 == 0) goto Ld
            r0 = 2
            goto L4b
        L4a:
            r0 = -1
        L4b:
            if (r0 == 0) goto L62
            if (r0 == r5) goto L60
            if (r0 == r4) goto L60
            if (r0 == r3) goto L5e
            if (r0 == r2) goto L5b
            if (r0 == r6) goto L58
            return r1
        L58:
            r0 = 14
            return r0
        L5b:
            r0 = 8
            return r0
        L5e:
            r0 = 7
            return r0
        L60:
            r0 = 6
            return r0
        L62:
            return r6
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.exoplayer2.util.MimeTypes.getEncoding(java.lang.String):int");
    }

    public static int getTrackTypeOfCodec(String codec) {
        return getTrackType(getMediaMimeType(codec));
    }

    private static String getTopLevelType(String mimeType) {
        if (mimeType == null) {
            return null;
        }
        int indexOfSlash = mimeType.indexOf(47);
        if (indexOfSlash == -1) {
            throw new IllegalArgumentException("Invalid mime type: " + mimeType);
        }
        return mimeType.substring(0, indexOfSlash);
    }

    private static String getCustomMimeTypeForCodec(String codec) {
        int customMimeTypeCount = customMimeTypes.size();
        for (int i = 0; i < customMimeTypeCount; i++) {
            CustomMimeType customMimeType = customMimeTypes.get(i);
            if (codec.startsWith(customMimeType.codecPrefix)) {
                return customMimeType.mimeType;
            }
        }
        return null;
    }

    private static int getTrackTypeForCustomMimeType(String mimeType) {
        int customMimeTypeCount = customMimeTypes.size();
        for (int i = 0; i < customMimeTypeCount; i++) {
            CustomMimeType customMimeType = customMimeTypes.get(i);
            if (mimeType.equals(customMimeType.mimeType)) {
                return customMimeType.trackType;
            }
        }
        return -1;
    }

    private MimeTypes() {
    }

    private static final class CustomMimeType {
        public final String codecPrefix;
        public final String mimeType;
        public final int trackType;

        public CustomMimeType(String mimeType, String codecPrefix, int trackType) {
            this.mimeType = mimeType;
            this.codecPrefix = codecPrefix;
            this.trackType = trackType;
        }
    }
}
