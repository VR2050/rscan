package org.webrtc.mozi.owtbase;

/* JADX INFO: loaded from: classes3.dex */
public final class MediaCodecs {

    public enum VideoCodec {
        VP8("VP8"),
        VP9("VP9"),
        H264("H264"),
        H265("H265"),
        AV1("AV1"),
        INVALID("");

        final String name;

        VideoCodec(String codecName) {
            this.name = codecName;
        }

        /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
        /* JADX WARN: Failed to restore switch over string. Please report as a decompilation issue */
        /* JADX WARN: Removed duplicated region for block: B:20:0x0042  */
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        public static org.webrtc.mozi.owtbase.MediaCodecs.VideoCodec get(java.lang.String r6) {
            /*
                java.lang.String r0 = r6.toUpperCase()
                int r1 = r0.hashCode()
                r2 = 4
                r3 = 3
                r4 = 2
                r5 = 1
                switch(r1) {
                    case 65180: goto L38;
                    case 85182: goto L2e;
                    case 85183: goto L24;
                    case 2194728: goto L1a;
                    case 2194729: goto L10;
                    default: goto Lf;
                }
            Lf:
                goto L42
            L10:
                java.lang.String r1 = "H265"
                boolean r0 = r0.equals(r1)
                if (r0 == 0) goto Lf
                r0 = 3
                goto L43
            L1a:
                java.lang.String r1 = "H264"
                boolean r0 = r0.equals(r1)
                if (r0 == 0) goto Lf
                r0 = 2
                goto L43
            L24:
                java.lang.String r1 = "VP9"
                boolean r0 = r0.equals(r1)
                if (r0 == 0) goto Lf
                r0 = 1
                goto L43
            L2e:
                java.lang.String r1 = "VP8"
                boolean r0 = r0.equals(r1)
                if (r0 == 0) goto Lf
                r0 = 0
                goto L43
            L38:
                java.lang.String r1 = "AV1"
                boolean r0 = r0.equals(r1)
                if (r0 == 0) goto Lf
                r0 = 4
                goto L43
            L42:
                r0 = -1
            L43:
                if (r0 == 0) goto L5c
                if (r0 == r5) goto L59
                if (r0 == r4) goto L56
                if (r0 == r3) goto L53
                if (r0 == r2) goto L50
                org.webrtc.mozi.owtbase.MediaCodecs$VideoCodec r0 = org.webrtc.mozi.owtbase.MediaCodecs.VideoCodec.INVALID
                return r0
            L50:
                org.webrtc.mozi.owtbase.MediaCodecs$VideoCodec r0 = org.webrtc.mozi.owtbase.MediaCodecs.VideoCodec.AV1
                return r0
            L53:
                org.webrtc.mozi.owtbase.MediaCodecs$VideoCodec r0 = org.webrtc.mozi.owtbase.MediaCodecs.VideoCodec.H265
                return r0
            L56:
                org.webrtc.mozi.owtbase.MediaCodecs$VideoCodec r0 = org.webrtc.mozi.owtbase.MediaCodecs.VideoCodec.H264
                return r0
            L59:
                org.webrtc.mozi.owtbase.MediaCodecs$VideoCodec r0 = org.webrtc.mozi.owtbase.MediaCodecs.VideoCodec.VP9
                return r0
            L5c:
                org.webrtc.mozi.owtbase.MediaCodecs$VideoCodec r0 = org.webrtc.mozi.owtbase.MediaCodecs.VideoCodec.VP8
                return r0
            */
            throw new UnsupportedOperationException("Method not decompiled: org.webrtc.mozi.owtbase.MediaCodecs.VideoCodec.get(java.lang.String):org.webrtc.mozi.owtbase.MediaCodecs$VideoCodec");
        }
    }

    public enum H264Profile {
        CONSTRAINED_BASELINE("constrained_baseline"),
        BASELINE("baseline"),
        MAIN("main"),
        HIGH("high");

        final String profile;

        H264Profile(String profile) {
            this.profile = profile;
        }

        /* JADX WARN: Failed to restore switch over string. Please report as a decompilation issue */
        public static H264Profile get(String profileName) {
            if (profileName == null) {
                return null;
            }
            String lowerCase = profileName.toLowerCase();
            byte b = -1;
            switch (lowerCase.hashCode()) {
                case -1720785339:
                    if (lowerCase.equals("baseline")) {
                        b = 1;
                    }
                    break;
                case 3202466:
                    if (lowerCase.equals("high")) {
                        b = 3;
                    }
                    break;
                case 3343801:
                    if (lowerCase.equals("main")) {
                        b = 2;
                    }
                    break;
                case 773649422:
                    if (lowerCase.equals("constrained_baseline")) {
                        b = 0;
                    }
                    break;
            }
            if (b == 0) {
                return CONSTRAINED_BASELINE;
            }
            if (b == 1) {
                return BASELINE;
            }
            if (b == 2) {
                return MAIN;
            }
            if (b != 3) {
                return null;
            }
            return HIGH;
        }
    }

    public enum AudioCodec {
        PCMU("PCMU"),
        PCMA("PCMA"),
        OPUS("opus"),
        G722("G722"),
        ISAC("ISAC"),
        ILBC("ILBC"),
        AAC("AAC"),
        AC3("AC3"),
        ASAO("ASAO"),
        RED("red"),
        INVALID("");

        final String name;

        AudioCodec(String codecName) {
            this.name = codecName;
        }

        /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
        /* JADX WARN: Removed duplicated region for block: B:35:0x0073  */
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        public static org.webrtc.mozi.owtbase.MediaCodecs.AudioCodec get(java.lang.String r2) {
            /*
                Method dump skipped, instruction units count: 218
                To view this dump add '--comments-level debug' option
            */
            throw new UnsupportedOperationException("Method not decompiled: org.webrtc.mozi.owtbase.MediaCodecs.AudioCodec.get(java.lang.String):org.webrtc.mozi.owtbase.MediaCodecs$AudioCodec");
        }
    }
}
