package p005b.p199l.p200a.p201a.p220h1.p224j;

import com.google.android.exoplayer2.metadata.Metadata;
import com.google.android.exoplayer2.metadata.scte35.PrivateCommand;
import com.google.android.exoplayer2.metadata.scte35.SpliceInsertCommand;
import com.google.android.exoplayer2.metadata.scte35.SpliceNullCommand;
import com.google.android.exoplayer2.metadata.scte35.SpliceScheduleCommand;
import com.google.android.exoplayer2.metadata.scte35.TimeSignalCommand;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import p005b.p199l.p200a.p201a.p220h1.C2081d;
import p005b.p199l.p200a.p201a.p220h1.InterfaceC2079b;
import p005b.p199l.p200a.p201a.p250p1.C2342c0;
import p005b.p199l.p200a.p201a.p250p1.C2359s;
import p005b.p199l.p200a.p201a.p250p1.C2360t;

/* renamed from: b.l.a.a.h1.j.a */
/* loaded from: classes.dex */
public final class C2089a implements InterfaceC2079b {

    /* renamed from: a */
    public final C2360t f4394a = new C2360t();

    /* renamed from: b */
    public final C2359s f4395b = new C2359s();

    /* renamed from: c */
    public C2342c0 f4396c;

    @Override // p005b.p199l.p200a.p201a.p220h1.InterfaceC2079b
    /* renamed from: a */
    public Metadata mo1705a(C2081d c2081d) {
        int i2;
        long j2;
        ArrayList arrayList;
        boolean z;
        boolean z2;
        long j3;
        boolean z3;
        long j4;
        int i3;
        int i4;
        int i5;
        boolean z4;
        long j5;
        List list;
        long j6;
        boolean z5;
        boolean z6;
        boolean z7;
        boolean z8;
        long j7;
        int i6;
        int i7;
        int i8;
        boolean z9;
        long j8;
        ByteBuffer byteBuffer = c2081d.f3306e;
        Objects.requireNonNull(byteBuffer);
        C2342c0 c2342c0 = this.f4396c;
        if (c2342c0 == null || c2081d.f4371i != c2342c0.m2307c()) {
            C2342c0 c2342c02 = new C2342c0(c2081d.f3307f);
            this.f4396c = c2342c02;
            c2342c02.m2305a(c2081d.f3307f - c2081d.f4371i);
        }
        byte[] array = byteBuffer.array();
        int limit = byteBuffer.limit();
        this.f4394a.m2565A(array, limit);
        this.f4395b.m2561i(array, limit);
        this.f4395b.m2564l(39);
        long m2558f = (this.f4395b.m2558f(1) << 32) | this.f4395b.m2558f(32);
        this.f4395b.m2564l(20);
        int m2558f2 = this.f4395b.m2558f(12);
        int m2558f3 = this.f4395b.m2558f(8);
        this.f4394a.m2568D(14);
        Metadata.Entry entry = null;
        if (m2558f3 == 0) {
            entry = new SpliceNullCommand();
        } else if (m2558f3 != 255) {
            long j9 = 128;
            if (m2558f3 == 4) {
                C2360t c2360t = this.f4394a;
                int m2585q = c2360t.m2585q();
                ArrayList arrayList2 = new ArrayList(m2585q);
                int i9 = 0;
                while (i9 < m2585q) {
                    long m2586r = c2360t.m2586r();
                    boolean z10 = (c2360t.m2585q() & 128) != 0;
                    ArrayList arrayList3 = new ArrayList();
                    if (z10) {
                        i2 = m2585q;
                        j2 = j9;
                        arrayList = arrayList3;
                        z = false;
                        z2 = false;
                        j3 = -9223372036854775807L;
                        z3 = false;
                        j4 = -9223372036854775807L;
                        i3 = 0;
                        i4 = 0;
                        i5 = 0;
                    } else {
                        int m2585q2 = c2360t.m2585q();
                        boolean z11 = (m2585q2 & 128) != 0;
                        boolean z12 = (m2585q2 & 64) != 0;
                        boolean z13 = (m2585q2 & 32) != 0;
                        long m2586r2 = z12 ? c2360t.m2586r() : -9223372036854775807L;
                        if (z12) {
                            i2 = m2585q;
                        } else {
                            int m2585q3 = c2360t.m2585q();
                            ArrayList arrayList4 = new ArrayList(m2585q3);
                            int i10 = 0;
                            while (i10 < m2585q3) {
                                arrayList4.add(new SpliceScheduleCommand.C3285b(c2360t.m2585q(), c2360t.m2586r(), null));
                                i10++;
                                m2585q3 = m2585q3;
                                m2585q = m2585q;
                            }
                            i2 = m2585q;
                            arrayList3 = arrayList4;
                        }
                        if (z13) {
                            long m2585q4 = c2360t.m2585q();
                            j2 = 128;
                            z4 = (m2585q4 & 128) != 0;
                            j5 = ((((m2585q4 & 1) << 32) | c2360t.m2586r()) * 1000) / 90;
                        } else {
                            j2 = 128;
                            z4 = false;
                            j5 = -9223372036854775807L;
                        }
                        z3 = z4;
                        j4 = j5;
                        arrayList = arrayList3;
                        i3 = c2360t.m2590v();
                        z = z11;
                        z2 = z12;
                        j3 = m2586r2;
                        i4 = c2360t.m2585q();
                        i5 = c2360t.m2585q();
                    }
                    arrayList2.add(new SpliceScheduleCommand.C3286c(m2586r, z10, z, z2, arrayList, j3, z3, j4, i3, i4, i5));
                    i9++;
                    j9 = j2;
                    m2585q = i2;
                }
                entry = new SpliceScheduleCommand(arrayList2);
            } else if (m2558f3 == 5) {
                C2360t c2360t2 = this.f4394a;
                C2342c0 c2342c03 = this.f4396c;
                long m2586r3 = c2360t2.m2586r();
                boolean z14 = (c2360t2.m2585q() & 128) != 0;
                List emptyList = Collections.emptyList();
                if (z14) {
                    list = emptyList;
                    j6 = -9223372036854775807L;
                    z5 = false;
                    z6 = false;
                    z7 = false;
                    z8 = false;
                    j7 = -9223372036854775807L;
                    i6 = 0;
                    i7 = 0;
                    i8 = 0;
                } else {
                    int m2585q5 = c2360t2.m2585q();
                    boolean z15 = (m2585q5 & 128) != 0;
                    boolean z16 = (m2585q5 & 64) != 0;
                    boolean z17 = (m2585q5 & 32) != 0;
                    boolean z18 = (m2585q5 & 16) != 0;
                    long m4056b = (!z16 || z18) ? -9223372036854775807L : TimeSignalCommand.m4056b(c2360t2, m2558f);
                    if (!z16) {
                        int m2585q6 = c2360t2.m2585q();
                        ArrayList arrayList5 = new ArrayList(m2585q6);
                        for (int i11 = 0; i11 < m2585q6; i11++) {
                            int m2585q7 = c2360t2.m2585q();
                            long m4056b2 = !z18 ? TimeSignalCommand.m4056b(c2360t2, m2558f) : -9223372036854775807L;
                            arrayList5.add(new SpliceInsertCommand.C3282b(m2585q7, m4056b2, c2342c03.m2306b(m4056b2), null));
                        }
                        emptyList = arrayList5;
                    }
                    if (z17) {
                        long m2585q8 = c2360t2.m2585q();
                        z9 = (m2585q8 & 128) != 0;
                        j8 = ((((m2585q8 & 1) << 32) | c2360t2.m2586r()) * 1000) / 90;
                    } else {
                        z9 = false;
                        j8 = -9223372036854775807L;
                    }
                    int m2590v = c2360t2.m2590v();
                    int m2585q9 = c2360t2.m2585q();
                    i6 = m2590v;
                    z8 = z9;
                    i8 = c2360t2.m2585q();
                    list = emptyList;
                    j7 = j8;
                    i7 = m2585q9;
                    z7 = z18;
                    z5 = z15;
                    z6 = z16;
                    j6 = m4056b;
                }
                entry = new SpliceInsertCommand(m2586r3, z14, z5, z6, z7, j6, c2342c03.m2306b(j6), list, z8, j7, i6, i7, i8);
            } else if (m2558f3 == 6) {
                C2360t c2360t3 = this.f4394a;
                C2342c0 c2342c04 = this.f4396c;
                long m4056b3 = TimeSignalCommand.m4056b(c2360t3, m2558f);
                entry = new TimeSignalCommand(m4056b3, c2342c04.m2306b(m4056b3));
            }
        } else {
            C2360t c2360t4 = this.f4394a;
            long m2586r4 = c2360t4.m2586r();
            int i12 = m2558f2 - 4;
            byte[] bArr = new byte[i12];
            System.arraycopy(c2360t4.f6133a, c2360t4.f6134b, bArr, 0, i12);
            c2360t4.f6134b += i12;
            entry = new PrivateCommand(m2586r4, bArr, m2558f);
        }
        return entry == null ? new Metadata(new Metadata.Entry[0]) : new Metadata(entry);
    }
}
