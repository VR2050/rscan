package p005b.p199l.p200a.p201a.p227k1.p232m0;

import android.text.TextUtils;
import androidx.annotation.Nullable;
import com.google.android.exoplayer2.Format;
import java.util.Arrays;
import java.util.Collections;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.checkerframework.checker.nullness.qual.RequiresNonNull;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.C2205l0;
import p005b.p199l.p200a.p201a.p208f1.C2003e;
import p005b.p199l.p200a.p201a.p208f1.C2049p;
import p005b.p199l.p200a.p201a.p208f1.InterfaceC2041h;
import p005b.p199l.p200a.p201a.p208f1.InterfaceC2042i;
import p005b.p199l.p200a.p201a.p208f1.InterfaceC2050q;
import p005b.p199l.p200a.p201a.p208f1.InterfaceC2052s;
import p005b.p199l.p200a.p201a.p236l1.p244t.C2246f;
import p005b.p199l.p200a.p201a.p236l1.p244t.C2248h;
import p005b.p199l.p200a.p201a.p250p1.C2342c0;
import p005b.p199l.p200a.p201a.p250p1.C2360t;

/* renamed from: b.l.a.a.k1.m0.r */
/* loaded from: classes.dex */
public final class C2175r implements InterfaceC2041h {

    /* renamed from: a */
    public static final Pattern f5002a = Pattern.compile("LOCAL:([^,]+)");

    /* renamed from: b */
    public static final Pattern f5003b = Pattern.compile("MPEGTS:(\\d+)");

    /* renamed from: c */
    @Nullable
    public final String f5004c;

    /* renamed from: d */
    public final C2342c0 f5005d;

    /* renamed from: f */
    public InterfaceC2042i f5007f;

    /* renamed from: h */
    public int f5009h;

    /* renamed from: e */
    public final C2360t f5006e = new C2360t();

    /* renamed from: g */
    public byte[] f5008g = new byte[1024];

    public C2175r(@Nullable String str, C2342c0 c2342c0) {
        this.f5004c = str;
        this.f5005d = c2342c0;
    }

    @RequiresNonNull({"output"})
    /* renamed from: a */
    public final InterfaceC2052s m1967a(long j2) {
        InterfaceC2052s mo1625t = this.f5007f.mo1625t(0, 3);
        mo1625t.mo1615d(Format.m4032I(null, "text/vtt", null, -1, 0, this.f5004c, -1, null, j2, Collections.emptyList()));
        this.f5007f.mo1624o();
        return mo1625t;
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2041h
    /* renamed from: d */
    public int mo1479d(C2003e c2003e, C2049p c2049p) {
        Matcher matcher;
        String m2574f;
        Objects.requireNonNull(this.f5007f);
        int i2 = (int) c2003e.f3788c;
        int i3 = this.f5009h;
        byte[] bArr = this.f5008g;
        if (i3 == bArr.length) {
            this.f5008g = Arrays.copyOf(bArr, ((i2 != -1 ? i2 : bArr.length) * 3) / 2);
        }
        byte[] bArr2 = this.f5008g;
        int i4 = this.f5009h;
        int m1566f = c2003e.m1566f(bArr2, i4, bArr2.length - i4);
        if (m1566f != -1) {
            int i5 = this.f5009h + m1566f;
            this.f5009h = i5;
            if (i2 == -1 || i5 != i2) {
                return 0;
            }
        }
        C2360t c2360t = new C2360t(this.f5008g);
        C2248h.m2138d(c2360t);
        long j2 = 0;
        long j3 = 0;
        for (String m2574f2 = c2360t.m2574f(); !TextUtils.isEmpty(m2574f2); m2574f2 = c2360t.m2574f()) {
            if (m2574f2.startsWith("X-TIMESTAMP-MAP")) {
                Matcher matcher2 = f5002a.matcher(m2574f2);
                if (!matcher2.find()) {
                    throw new C2205l0(C1499a.m637w("X-TIMESTAMP-MAP doesn't contain local timestamp: ", m2574f2));
                }
                Matcher matcher3 = f5003b.matcher(m2574f2);
                if (!matcher3.find()) {
                    throw new C2205l0(C1499a.m637w("X-TIMESTAMP-MAP doesn't contain media timestamp: ", m2574f2));
                }
                j3 = C2248h.m2137c(matcher2.group(1));
                j2 = (Long.parseLong(matcher3.group(1)) * 1000000) / 90000;
            }
        }
        while (true) {
            String m2574f3 = c2360t.m2574f();
            if (m2574f3 == null) {
                matcher = null;
                break;
            }
            if (!C2248h.f5602a.matcher(m2574f3).matches()) {
                matcher = C2246f.f5587a.matcher(m2574f3);
                if (matcher.matches()) {
                    break;
                }
            } else {
                do {
                    m2574f = c2360t.m2574f();
                    if (m2574f != null) {
                    }
                } while (!m2574f.isEmpty());
            }
        }
        if (matcher == null) {
            m1967a(0L);
        } else {
            long m2137c = C2248h.m2137c(matcher.group(1));
            long m2306b = this.f5005d.m2306b((((j2 + m2137c) - j3) * 90000) / 1000000);
            InterfaceC2052s m1967a = m1967a(m2306b - m2137c);
            this.f5006e.m2565A(this.f5008g, this.f5009h);
            m1967a.mo1613b(this.f5006e, this.f5009h);
            m1967a.mo1614c(m2306b, 1, this.f5009h, 0, null);
        }
        return -1;
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2041h
    /* renamed from: e */
    public void mo1480e(InterfaceC2042i interfaceC2042i) {
        this.f5007f = interfaceC2042i;
        interfaceC2042i.mo1623a(new InterfaceC2050q.b(-9223372036854775807L, 0L));
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2041h
    /* renamed from: f */
    public void mo1481f(long j2, long j3) {
        throw new IllegalStateException();
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2041h
    /* renamed from: h */
    public boolean mo1483h(C2003e c2003e) {
        c2003e.m1565e(this.f5008g, 0, 6, false);
        this.f5006e.m2565A(this.f5008g, 6);
        if (C2248h.m2135a(this.f5006e)) {
            return true;
        }
        c2003e.m1565e(this.f5008g, 6, 3, false);
        this.f5006e.m2565A(this.f5008g, 9);
        return C2248h.m2135a(this.f5006e);
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2041h
    public void release() {
    }
}
