package p005b.p199l.p200a.p201a.p227k1.p229k0;

import androidx.annotation.Nullable;
import com.google.android.exoplayer2.Format;
import java.io.IOException;
import java.util.Arrays;
import p005b.p199l.p200a.p201a.p227k1.p232m0.C2165h;
import p005b.p199l.p200a.p201a.p248o1.C2287d0;
import p005b.p199l.p200a.p201a.p248o1.C2324p;
import p005b.p199l.p200a.p201a.p248o1.InterfaceC2321m;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;

/* renamed from: b.l.a.a.k1.k0.j */
/* loaded from: classes.dex */
public abstract class AbstractC2128j extends AbstractC2122d {

    /* renamed from: i */
    public byte[] f4683i;

    /* renamed from: j */
    public volatile boolean f4684j;

    public AbstractC2128j(InterfaceC2321m interfaceC2321m, C2324p c2324p, int i2, Format format, int i3, @Nullable Object obj, byte[] bArr) {
        super(interfaceC2321m, c2324p, i2, format, i3, obj, -9223372036854775807L, -9223372036854775807L);
        this.f4683i = bArr;
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.C2281a0.e
    /* renamed from: a */
    public final void mo1782a() {
        try {
            this.f4630h.open(this.f4623a);
            int i2 = 0;
            int i3 = 0;
            while (i2 != -1 && !this.f4684j) {
                byte[] bArr = this.f4683i;
                if (bArr == null) {
                    this.f4683i = new byte[16384];
                } else if (bArr.length < i3 + 16384) {
                    this.f4683i = Arrays.copyOf(bArr, bArr.length + 16384);
                }
                i2 = this.f4630h.read(this.f4683i, i3, 16384);
                if (i2 != -1) {
                    i3 += i2;
                }
            }
            if (!this.f4684j) {
                ((C2165h.a) this).f4884k = Arrays.copyOf(this.f4683i, i3);
            }
            if (r0 != null) {
                try {
                    this.f4630h.close();
                } catch (IOException unused) {
                }
            }
        } finally {
            C2287d0 c2287d0 = this.f4630h;
            int i4 = C2344d0.f6035a;
            if (c2287d0 != null) {
                try {
                    c2287d0.close();
                } catch (IOException unused2) {
                }
            }
        }
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.C2281a0.e
    /* renamed from: b */
    public final void mo1783b() {
        this.f4684j = true;
    }
}
