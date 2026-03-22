package p005b.p199l.p200a.p201a.p220h1;

import android.os.Handler;
import android.os.Looper;
import android.os.Message;
import androidx.annotation.Nullable;
import com.google.android.exoplayer2.Format;
import com.google.android.exoplayer2.metadata.Metadata;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import p005b.p199l.p200a.p201a.AbstractC2397u;
import p005b.p199l.p200a.p201a.C1964f0;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;

/* renamed from: b.l.a.a.h1.f */
/* loaded from: classes.dex */
public final class C2083f extends AbstractC2397u implements Handler.Callback {

    /* renamed from: o */
    public final InterfaceC2080c f4372o;

    /* renamed from: p */
    public final InterfaceC2082e f4373p;

    /* renamed from: q */
    @Nullable
    public final Handler f4374q;

    /* renamed from: r */
    public final C2081d f4375r;

    /* renamed from: s */
    public final Metadata[] f4376s;

    /* renamed from: t */
    public final long[] f4377t;

    /* renamed from: u */
    public int f4378u;

    /* renamed from: v */
    public int f4379v;

    /* renamed from: w */
    @Nullable
    public InterfaceC2079b f4380w;

    /* renamed from: x */
    public boolean f4381x;

    /* renamed from: y */
    public long f4382y;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C2083f(InterfaceC2082e interfaceC2082e, @Nullable Looper looper) {
        super(4);
        Handler handler;
        InterfaceC2080c interfaceC2080c = InterfaceC2080c.f4370a;
        Objects.requireNonNull(interfaceC2082e);
        this.f4373p = interfaceC2082e;
        if (looper == null) {
            handler = null;
        } else {
            int i2 = C2344d0.f6035a;
            handler = new Handler(looper, this);
        }
        this.f4374q = handler;
        this.f4372o = interfaceC2080c;
        this.f4375r = new C2081d();
        this.f4376s = new Metadata[5];
        this.f4377t = new long[5];
    }

    @Override // p005b.p199l.p200a.p201a.AbstractC2397u
    /* renamed from: C */
    public void mo1303C(Format[] formatArr, long j2) {
        this.f4380w = this.f4372o.mo1707b(formatArr[0]);
    }

    @Override // p005b.p199l.p200a.p201a.AbstractC2397u
    /* renamed from: E */
    public int mo1661E(Format format) {
        if (this.f4372o.mo1706a(format)) {
            return (AbstractC2397u.m2664F(null, format.f9248o) ? 4 : 2) | 0 | 0;
        }
        return 0;
    }

    /* renamed from: H */
    public final void m1708H(Metadata metadata, List<Metadata.Entry> list) {
        int i2 = 0;
        while (true) {
            Metadata.Entry[] entryArr = metadata.f9273c;
            if (i2 >= entryArr.length) {
                return;
            }
            Format mo4051d = entryArr[i2].mo4051d();
            if (mo4051d == null || !this.f4372o.mo1706a(mo4051d)) {
                list.add(metadata.f9273c[i2]);
            } else {
                InterfaceC2079b mo1707b = this.f4372o.mo1707b(mo4051d);
                byte[] mo4052u = metadata.f9273c[i2].mo4052u();
                Objects.requireNonNull(mo4052u);
                this.f4375r.clear();
                this.f4375r.m1381f(mo4052u.length);
                ByteBuffer byteBuffer = this.f4375r.f3306e;
                int i3 = C2344d0.f6035a;
                byteBuffer.put(mo4052u);
                this.f4375r.m1382g();
                Metadata mo1705a = mo1707b.mo1705a(this.f4375r);
                if (mo1705a != null) {
                    m1708H(mo1705a, list);
                }
            }
            i2++;
        }
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2396t0
    /* renamed from: c */
    public boolean mo1314c() {
        return this.f4381x;
    }

    @Override // android.os.Handler.Callback
    public boolean handleMessage(Message message) {
        if (message.what != 0) {
            throw new IllegalStateException();
        }
        this.f4373p.onMetadata((Metadata) message.obj);
        return true;
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2396t0
    public boolean isReady() {
        return true;
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2396t0
    /* renamed from: j */
    public void mo1680j(long j2, long j3) {
        if (!this.f4381x && this.f4379v < 5) {
            this.f4375r.clear();
            C1964f0 m2667v = m2667v();
            int m2665D = m2665D(m2667v, this.f4375r, false);
            if (m2665D == -4) {
                if (this.f4375r.isEndOfStream()) {
                    this.f4381x = true;
                } else if (!this.f4375r.isDecodeOnly()) {
                    C2081d c2081d = this.f4375r;
                    c2081d.f4371i = this.f4382y;
                    c2081d.m1382g();
                    InterfaceC2079b interfaceC2079b = this.f4380w;
                    int i2 = C2344d0.f6035a;
                    Metadata mo1705a = interfaceC2079b.mo1705a(this.f4375r);
                    if (mo1705a != null) {
                        ArrayList arrayList = new ArrayList(mo1705a.f9273c.length);
                        m1708H(mo1705a, arrayList);
                        if (!arrayList.isEmpty()) {
                            Metadata metadata = new Metadata(arrayList);
                            int i3 = this.f4378u;
                            int i4 = this.f4379v;
                            int i5 = (i3 + i4) % 5;
                            this.f4376s[i5] = metadata;
                            this.f4377t[i5] = this.f4375r.f3307f;
                            this.f4379v = i4 + 1;
                        }
                    }
                }
            } else if (m2665D == -5) {
                Format format = m2667v.f3394c;
                Objects.requireNonNull(format);
                this.f4382y = format.f9249p;
            }
        }
        if (this.f4379v > 0) {
            long[] jArr = this.f4377t;
            int i6 = this.f4378u;
            if (jArr[i6] <= j2) {
                Metadata metadata2 = this.f4376s[i6];
                int i7 = C2344d0.f6035a;
                Handler handler = this.f4374q;
                if (handler != null) {
                    handler.obtainMessage(0, metadata2).sendToTarget();
                } else {
                    this.f4373p.onMetadata(metadata2);
                }
                Metadata[] metadataArr = this.f4376s;
                int i8 = this.f4378u;
                metadataArr[i8] = null;
                this.f4378u = (i8 + 1) % 5;
                this.f4379v--;
            }
        }
    }

    @Override // p005b.p199l.p200a.p201a.AbstractC2397u
    /* renamed from: w */
    public void mo1325w() {
        Arrays.fill(this.f4376s, (Object) null);
        this.f4378u = 0;
        this.f4379v = 0;
        this.f4380w = null;
    }

    @Override // p005b.p199l.p200a.p201a.AbstractC2397u
    /* renamed from: y */
    public void mo1327y(long j2, boolean z) {
        Arrays.fill(this.f4376s, (Object) null);
        this.f4378u = 0;
        this.f4379v = 0;
        this.f4381x = false;
    }
}
