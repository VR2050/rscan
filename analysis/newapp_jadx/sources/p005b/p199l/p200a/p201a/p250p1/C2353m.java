package p005b.p199l.p200a.p201a.p250p1;

import androidx.annotation.Nullable;
import com.google.android.exoplayer2.Format;
import com.google.android.exoplayer2.metadata.Metadata;
import com.google.android.exoplayer2.metadata.flac.PictureFrame;
import com.google.android.exoplayer2.metadata.flac.VorbisComment;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import kotlin.jvm.internal.ByteCompanionObject;

/* renamed from: b.l.a.a.p1.m */
/* loaded from: classes.dex */
public final class C2353m {

    /* renamed from: a */
    public final int f6073a;

    /* renamed from: b */
    public final int f6074b;

    /* renamed from: c */
    public final int f6075c;

    /* renamed from: d */
    public final int f6076d;

    /* renamed from: e */
    public final int f6077e;

    /* renamed from: f */
    public final int f6078f;

    /* renamed from: g */
    public final int f6079g;

    /* renamed from: h */
    public final int f6080h;

    /* renamed from: i */
    public final int f6081i;

    /* renamed from: j */
    public final long f6082j;

    /* renamed from: k */
    @Nullable
    public final a f6083k;

    /* renamed from: l */
    @Nullable
    public final Metadata f6084l;

    /* renamed from: b.l.a.a.p1.m$a */
    public static class a {

        /* renamed from: a */
        public final long[] f6085a;

        /* renamed from: b */
        public final long[] f6086b;

        public a(long[] jArr, long[] jArr2) {
            this.f6085a = jArr;
            this.f6086b = jArr2;
        }
    }

    public C2353m(byte[] bArr, int i2) {
        C2359s c2359s = new C2359s(bArr);
        c2359s.m2562j(i2 * 8);
        this.f6073a = c2359s.m2558f(16);
        this.f6074b = c2359s.m2558f(16);
        this.f6075c = c2359s.m2558f(24);
        this.f6076d = c2359s.m2558f(24);
        int m2558f = c2359s.m2558f(20);
        this.f6077e = m2558f;
        this.f6078f = m2368h(m2558f);
        this.f6079g = c2359s.m2558f(3) + 1;
        int m2558f2 = c2359s.m2558f(5) + 1;
        this.f6080h = m2558f2;
        this.f6081i = m2367c(m2558f2);
        this.f6082j = (C2344d0.m2321M(c2359s.m2558f(4)) << 32) | C2344d0.m2321M(c2359s.m2558f(32));
        this.f6083k = null;
        this.f6084l = null;
    }

    @Nullable
    /* renamed from: a */
    public static Metadata m2366a(List<String> list, List<PictureFrame> list2) {
        if (list.isEmpty() && list2.isEmpty()) {
            return null;
        }
        ArrayList arrayList = new ArrayList();
        for (int i2 = 0; i2 < list.size(); i2++) {
            String[] m2317I = C2344d0.m2317I(list.get(i2), "=");
            if (m2317I.length == 2) {
                arrayList.add(new VorbisComment(m2317I[0], m2317I[1]));
            }
        }
        arrayList.addAll(list2);
        if (arrayList.isEmpty()) {
            return null;
        }
        return new Metadata(arrayList);
    }

    /* renamed from: c */
    public static int m2367c(int i2) {
        if (i2 == 8) {
            return 1;
        }
        if (i2 == 12) {
            return 2;
        }
        if (i2 == 16) {
            return 4;
        }
        if (i2 != 20) {
            return i2 != 24 ? -1 : 6;
        }
        return 5;
    }

    /* renamed from: h */
    public static int m2368h(int i2) {
        switch (i2) {
            case 8000:
                return 4;
            case 16000:
                return 5;
            case 22050:
                return 6;
            case 24000:
                return 7;
            case 32000:
                return 8;
            case 44100:
                return 9;
            case 48000:
                return 10;
            case 88200:
                return 1;
            case 96000:
                return 11;
            case 176400:
                return 2;
            case 192000:
                return 3;
            default:
                return -1;
        }
    }

    /* renamed from: b */
    public C2353m m2369b(@Nullable a aVar) {
        return new C2353m(this.f6073a, this.f6074b, this.f6075c, this.f6076d, this.f6077e, this.f6079g, this.f6080h, this.f6082j, aVar, this.f6084l);
    }

    /* renamed from: d */
    public long m2370d() {
        long j2 = this.f6082j;
        if (j2 == 0) {
            return -9223372036854775807L;
        }
        return (j2 * 1000000) / this.f6077e;
    }

    /* renamed from: e */
    public Format m2371e(byte[] bArr, @Nullable Metadata metadata) {
        bArr[4] = ByteCompanionObject.MIN_VALUE;
        int i2 = this.f6076d;
        int i3 = i2 > 0 ? i2 : -1;
        Metadata metadata2 = this.f6084l;
        Metadata m4054e = metadata2 == null ? metadata : metadata2.m4054e(metadata);
        int i4 = this.f6080h;
        int i5 = this.f6077e;
        int i6 = this.f6079g;
        return Format.m4038y(null, "audio/flac", null, i4 * i5 * i6, i3, i6, i5, -1, 0, 0, Collections.singletonList(bArr), null, 0, null, m4054e);
    }

    @Nullable
    /* renamed from: f */
    public Metadata m2372f(@Nullable Metadata metadata) {
        Metadata metadata2 = this.f6084l;
        return metadata2 == null ? metadata : metadata2.m4054e(metadata);
    }

    /* renamed from: g */
    public long m2373g(long j2) {
        return C2344d0.m2330h((j2 * this.f6077e) / 1000000, 0L, this.f6082j - 1);
    }

    public C2353m(int i2, int i3, int i4, int i5, int i6, int i7, int i8, long j2, @Nullable a aVar, @Nullable Metadata metadata) {
        this.f6073a = i2;
        this.f6074b = i3;
        this.f6075c = i4;
        this.f6076d = i5;
        this.f6077e = i6;
        this.f6078f = m2368h(i6);
        this.f6079g = i7;
        this.f6080h = i8;
        this.f6081i = m2367c(i8);
        this.f6082j = j2;
        this.f6083k = aVar;
        this.f6084l = metadata;
    }
}
