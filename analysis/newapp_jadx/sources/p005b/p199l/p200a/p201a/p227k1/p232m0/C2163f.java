package p005b.p199l.p200a.p201a.p227k1.p232m0;

import android.text.TextUtils;
import androidx.annotation.Nullable;
import com.google.android.exoplayer2.Format;
import com.google.android.exoplayer2.metadata.Metadata;
import com.google.android.exoplayer2.source.hls.HlsTrackMetadataEntry;
import java.io.EOFException;
import java.util.Collections;
import java.util.List;
import p005b.p199l.p200a.p201a.p208f1.C2003e;
import p005b.p199l.p200a.p201a.p208f1.InterfaceC2041h;
import p005b.p199l.p200a.p201a.p208f1.p210b0.C1976d;
import p005b.p199l.p200a.p201a.p208f1.p211c0.C1984d;
import p005b.p199l.p200a.p201a.p208f1.p214f0.C2006a;
import p005b.p199l.p200a.p201a.p208f1.p214f0.C2009b0;
import p005b.p199l.p200a.p201a.p208f1.p214f0.C2010c;
import p005b.p199l.p200a.p201a.p208f1.p214f0.C2014e;
import p005b.p199l.p200a.p201a.p208f1.p214f0.C2016g;
import p005b.p199l.p200a.p201a.p227k1.p232m0.InterfaceC2167j;
import p005b.p199l.p200a.p201a.p250p1.C2342c0;
import p005b.p199l.p200a.p201a.p250p1.C2357q;

/* renamed from: b.l.a.a.k1.m0.f */
/* loaded from: classes.dex */
public final class C2163f implements InterfaceC2167j {
    /* renamed from: a */
    public static InterfaceC2167j.a m1934a(InterfaceC2041h interfaceC2041h) {
        boolean z = true;
        boolean z2 = (interfaceC2041h instanceof C2014e) || (interfaceC2041h instanceof C2006a) || (interfaceC2041h instanceof C2010c) || (interfaceC2041h instanceof C1976d);
        if (!(interfaceC2041h instanceof C2009b0) && !(interfaceC2041h instanceof C1984d)) {
            z = false;
        }
        return new InterfaceC2167j.a(interfaceC2041h, z2, z);
    }

    /* renamed from: b */
    public static C1984d m1935b(C2342c0 c2342c0, Format format, @Nullable List<Format> list) {
        boolean z;
        Metadata metadata = format.f9243j;
        if (metadata != null) {
            int i2 = 0;
            while (true) {
                Metadata.Entry[] entryArr = metadata.f9273c;
                if (i2 >= entryArr.length) {
                    break;
                }
                Metadata.Entry entry = entryArr[i2];
                if (entry instanceof HlsTrackMetadataEntry) {
                    z = !((HlsTrackMetadataEntry) entry).f9478f.isEmpty();
                    break;
                }
                i2++;
            }
        }
        z = false;
        int i3 = z ? 4 : 0;
        if (list == null) {
            list = Collections.emptyList();
        }
        return new C1984d(i3, c2342c0, null, list);
    }

    /* renamed from: c */
    public static C2009b0 m1936c(int i2, boolean z, Format format, @Nullable List<Format> list, C2342c0 c2342c0) {
        int i3 = i2 | 16;
        if (list != null) {
            i3 |= 32;
        } else {
            list = z ? Collections.singletonList(Format.m4031H(null, "application/cea-608", 0, null, null)) : Collections.emptyList();
        }
        String str = format.f9242i;
        if (!TextUtils.isEmpty(str)) {
            if (!"audio/mp4a-latm".equals(C2357q.m2538a(str))) {
                i3 |= 2;
            }
            if (!"video/avc".equals(C2357q.m2544g(str))) {
                i3 |= 4;
            }
        }
        return new C2009b0(2, c2342c0, new C2016g(i3, list));
    }

    /* renamed from: d */
    public static boolean m1937d(InterfaceC2041h interfaceC2041h, C2003e c2003e) {
        try {
            return interfaceC2041h.mo1483h(c2003e);
        } catch (EOFException unused) {
            return false;
        } finally {
            c2003e.f3791f = 0;
        }
    }
}
