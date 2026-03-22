package p476m.p477a.p485b.p488j0.p491j;

import java.net.Socket;
import java.util.ArrayList;
import java.util.List;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p476m.p477a.p485b.InterfaceC4891n;
import p476m.p477a.p485b.p486h0.C4805a;
import p476m.p477a.p485b.p492k0.InterfaceC4850d;
import p476m.p477a.p485b.p493l0.C4861i;
import p476m.p477a.p485b.p493l0.InterfaceC4870r;
import p476m.p477a.p485b.p495n0.C4893b;

/* renamed from: m.a.b.j0.j.a */
/* loaded from: classes3.dex */
public abstract class AbstractC4830a<T extends InterfaceC4891n> {

    /* renamed from: a */
    public final InterfaceC4850d f12367a;

    /* renamed from: b */
    public final C4805a f12368b;

    /* renamed from: c */
    public final List<C4893b> f12369c;

    /* renamed from: d */
    public final InterfaceC4870r f12370d;

    /* renamed from: e */
    public int f12371e;

    /* renamed from: f */
    public T f12372f;

    public AbstractC4830a(InterfaceC4850d interfaceC4850d, InterfaceC4870r interfaceC4870r, C4805a c4805a) {
        C2354n.m2470e1(interfaceC4850d, "Session input buffer");
        this.f12367a = interfaceC4850d;
        this.f12370d = interfaceC4870r == null ? C4861i.f12450a : interfaceC4870r;
        this.f12368b = c4805a == null ? C4805a.f12283c : c4805a;
        this.f12369c = new ArrayList();
        this.f12371e = 0;
    }

    /* JADX WARN: Code restructure failed: missing block: B:65:0x00bf, code lost:
    
        r8 = new p476m.p477a.p485b.InterfaceC4800f[r12.size()];
     */
    /* JADX WARN: Code restructure failed: missing block: B:67:0x00c9, code lost:
    
        if (r2 >= r12.size()) goto L85;
     */
    /* JADX WARN: Code restructure failed: missing block: B:70:0x00d1, code lost:
    
        r8[r2] = new p476m.p477a.p485b.p493l0.C4867o(r12.get(r2));
     */
    /* JADX WARN: Code restructure failed: missing block: B:71:0x00d8, code lost:
    
        r2 = r2 + 1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:73:0x00db, code lost:
    
        r8 = move-exception;
     */
    /* JADX WARN: Code restructure failed: missing block: B:75:0x00e5, code lost:
    
        throw new p476m.p477a.p485b.C4793b0(r8.getMessage());
     */
    /* JADX WARN: Code restructure failed: missing block: B:77:0x00e6, code lost:
    
        return r8;
     */
    /* renamed from: b */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static p476m.p477a.p485b.InterfaceC4800f[] m5491b(p476m.p477a.p485b.p492k0.InterfaceC4850d r8, int r9, int r10, p476m.p477a.p485b.p493l0.InterfaceC4870r r11, java.util.List<p476m.p477a.p485b.p495n0.C4893b> r12) {
        /*
            Method dump skipped, instructions count: 231
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p476m.p477a.p485b.p488j0.p491j.AbstractC4830a.m5491b(m.a.b.k0.d, int, int, m.a.b.l0.r, java.util.List):m.a.b.f[]");
    }

    /* renamed from: a */
    public abstract T mo5492a(Socket socket, InterfaceC4850d interfaceC4850d);
}
