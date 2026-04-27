package com.google.android.exoplayer2.metadata.icy;

import com.google.android.exoplayer2.metadata.Metadata;
import com.google.android.exoplayer2.metadata.MetadataDecoder;
import com.google.android.exoplayer2.metadata.MetadataInputBuffer;
import com.google.android.exoplayer2.util.Util;
import java.nio.ByteBuffer;
import java.util.regex.Pattern;

/* JADX INFO: loaded from: classes2.dex */
public final class IcyDecoder implements MetadataDecoder {
    private static final Pattern METADATA_ELEMENT = Pattern.compile("(.+?)='(.+?)';");
    private static final String STREAM_KEY_NAME = "streamtitle";
    private static final String STREAM_KEY_URL = "streamurl";
    private static final String TAG = "IcyDecoder";

    @Override // com.google.android.exoplayer2.metadata.MetadataDecoder
    public Metadata decode(MetadataInputBuffer inputBuffer) {
        ByteBuffer buffer = inputBuffer.data;
        byte[] data = buffer.array();
        int length = buffer.limit();
        return decode(Util.fromUtf8Bytes(data, 0, length));
    }

    /* JADX WARN: Removed duplicated region for block: B:16:0x0041  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    com.google.android.exoplayer2.metadata.Metadata decode(java.lang.String r12) {
        /*
            r11 = this;
            r0 = 0
            r1 = 0
            r2 = 0
            java.util.regex.Pattern r3 = com.google.android.exoplayer2.metadata.icy.IcyDecoder.METADATA_ELEMENT
            java.util.regex.Matcher r3 = r3.matcher(r12)
        L9:
            boolean r4 = r3.find(r2)
            r5 = 0
            r6 = 1
            if (r4 == 0) goto L66
            java.lang.String r4 = r3.group(r6)
            java.lang.String r4 = com.google.android.exoplayer2.util.Util.toLowerInvariant(r4)
            r7 = 2
            java.lang.String r7 = r3.group(r7)
            r8 = -1
            int r9 = r4.hashCode()
            r10 = -315603473(0xffffffffed3045ef, float:-3.409619E27)
            if (r9 == r10) goto L37
            r10 = 1646559960(0x622482d8, float:7.586736E20)
            if (r9 == r10) goto L2e
        L2d:
            goto L41
        L2e:
            java.lang.String r9 = "streamtitle"
            boolean r9 = r4.equals(r9)
            if (r9 == 0) goto L2d
            goto L42
        L37:
            java.lang.String r5 = "streamurl"
            boolean r5 = r4.equals(r5)
            if (r5 == 0) goto L2d
            r5 = 1
            goto L42
        L41:
            r5 = -1
        L42:
            if (r5 == 0) goto L5f
            if (r5 == r6) goto L5d
            java.lang.StringBuilder r5 = new java.lang.StringBuilder
            r5.<init>()
            java.lang.String r6 = "Unrecognized ICY tag: "
            r5.append(r6)
            r5.append(r0)
            java.lang.String r5 = r5.toString()
            java.lang.String r6 = "IcyDecoder"
            com.google.android.exoplayer2.util.Log.w(r6, r5)
            goto L61
        L5d:
            r1 = r7
            goto L61
        L5f:
            r0 = r7
        L61:
            int r2 = r3.end()
            goto L9
        L66:
            if (r0 != 0) goto L6d
            if (r1 == 0) goto L6b
            goto L6d
        L6b:
            r4 = 0
            goto L7b
        L6d:
            com.google.android.exoplayer2.metadata.Metadata r4 = new com.google.android.exoplayer2.metadata.Metadata
            com.google.android.exoplayer2.metadata.Metadata$Entry[] r6 = new com.google.android.exoplayer2.metadata.Metadata.Entry[r6]
            com.google.android.exoplayer2.metadata.icy.IcyInfo r7 = new com.google.android.exoplayer2.metadata.icy.IcyInfo
            r7.<init>(r0, r1)
            r6[r5] = r7
            r4.<init>(r6)
        L7b:
            return r4
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.exoplayer2.metadata.icy.IcyDecoder.decode(java.lang.String):com.google.android.exoplayer2.metadata.Metadata");
    }
}
