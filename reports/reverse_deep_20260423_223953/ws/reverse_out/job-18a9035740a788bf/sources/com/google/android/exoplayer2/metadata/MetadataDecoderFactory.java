package com.google.android.exoplayer2.metadata;

import com.google.android.exoplayer2.Format;
import com.google.android.exoplayer2.util.MimeTypes;

/* JADX INFO: loaded from: classes2.dex */
public interface MetadataDecoderFactory {
    public static final MetadataDecoderFactory DEFAULT = new MetadataDecoderFactory() { // from class: com.google.android.exoplayer2.metadata.MetadataDecoderFactory.1
        @Override // com.google.android.exoplayer2.metadata.MetadataDecoderFactory
        public boolean supportsFormat(Format format) {
            String mimeType = format.sampleMimeType;
            return MimeTypes.APPLICATION_ID3.equals(mimeType) || MimeTypes.APPLICATION_EMSG.equals(mimeType) || MimeTypes.APPLICATION_SCTE35.equals(mimeType) || MimeTypes.APPLICATION_ICY.equals(mimeType);
        }

        /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
        /* JADX WARN: Failed to restore switch over string. Please report as a decompilation issue */
        /* JADX WARN: Removed duplicated region for block: B:17:0x0035  */
        @Override // com.google.android.exoplayer2.metadata.MetadataDecoderFactory
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        public com.google.android.exoplayer2.metadata.MetadataDecoder createDecoder(com.google.android.exoplayer2.Format r6) {
            /*
                r5 = this;
                java.lang.String r0 = r6.sampleMimeType
                int r1 = r0.hashCode()
                r2 = 3
                r3 = 2
                r4 = 1
                switch(r1) {
                    case -1348231605: goto L2b;
                    case -1248341703: goto L21;
                    case 1154383568: goto L17;
                    case 1652648887: goto Ld;
                    default: goto Lc;
                }
            Lc:
                goto L35
            Ld:
                java.lang.String r1 = "application/x-scte35"
                boolean r0 = r0.equals(r1)
                if (r0 == 0) goto Lc
                r0 = 2
                goto L36
            L17:
                java.lang.String r1 = "application/x-emsg"
                boolean r0 = r0.equals(r1)
                if (r0 == 0) goto Lc
                r0 = 1
                goto L36
            L21:
                java.lang.String r1 = "application/id3"
                boolean r0 = r0.equals(r1)
                if (r0 == 0) goto Lc
                r0 = 0
                goto L36
            L2b:
                java.lang.String r1 = "application/x-icy"
                boolean r0 = r0.equals(r1)
                if (r0 == 0) goto Lc
                r0 = 3
                goto L36
            L35:
                r0 = -1
            L36:
                if (r0 == 0) goto L58
                if (r0 == r4) goto L52
                if (r0 == r3) goto L4c
                if (r0 != r2) goto L44
                com.google.android.exoplayer2.metadata.icy.IcyDecoder r0 = new com.google.android.exoplayer2.metadata.icy.IcyDecoder
                r0.<init>()
                return r0
            L44:
                java.lang.IllegalArgumentException r0 = new java.lang.IllegalArgumentException
                java.lang.String r1 = "Attempted to create decoder for unsupported format"
                r0.<init>(r1)
                throw r0
            L4c:
                com.google.android.exoplayer2.metadata.scte35.SpliceInfoDecoder r0 = new com.google.android.exoplayer2.metadata.scte35.SpliceInfoDecoder
                r0.<init>()
                return r0
            L52:
                com.google.android.exoplayer2.metadata.emsg.EventMessageDecoder r0 = new com.google.android.exoplayer2.metadata.emsg.EventMessageDecoder
                r0.<init>()
                return r0
            L58:
                com.google.android.exoplayer2.metadata.id3.Id3Decoder r0 = new com.google.android.exoplayer2.metadata.id3.Id3Decoder
                r0.<init>()
                return r0
            */
            throw new UnsupportedOperationException("Method not decompiled: com.google.android.exoplayer2.metadata.MetadataDecoderFactory.AnonymousClass1.createDecoder(com.google.android.exoplayer2.Format):com.google.android.exoplayer2.metadata.MetadataDecoder");
        }
    };

    MetadataDecoder createDecoder(Format format);

    boolean supportsFormat(Format format);
}
