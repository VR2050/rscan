package p005b.p199l.p200a.p201a.p208f1;

import java.lang.reflect.Constructor;
import java.util.Collections;
import p005b.p199l.p200a.p201a.p208f1.p209a0.C1969d;
import p005b.p199l.p200a.p201a.p208f1.p210b0.C1976d;
import p005b.p199l.p200a.p201a.p208f1.p211c0.C1984d;
import p005b.p199l.p200a.p201a.p208f1.p211c0.C1986f;
import p005b.p199l.p200a.p201a.p208f1.p212d0.C1996c;
import p005b.p199l.p200a.p201a.p208f1.p214f0.C2006a;
import p005b.p199l.p200a.p201a.p208f1.p214f0.C2009b0;
import p005b.p199l.p200a.p201a.p208f1.p214f0.C2010c;
import p005b.p199l.p200a.p201a.p208f1.p214f0.C2014e;
import p005b.p199l.p200a.p201a.p208f1.p214f0.C2016g;
import p005b.p199l.p200a.p201a.p208f1.p214f0.C2030u;
import p005b.p199l.p200a.p201a.p208f1.p215g0.C2037a;
import p005b.p199l.p200a.p201a.p208f1.p216x.C2057a;
import p005b.p199l.p200a.p201a.p208f1.p217y.C2060c;
import p005b.p199l.p200a.p201a.p208f1.p218z.C2062b;
import p005b.p199l.p200a.p201a.p250p1.C2342c0;

/* renamed from: b.l.a.a.f1.f */
/* loaded from: classes.dex */
public final class C2005f implements InterfaceC2043j {

    /* renamed from: a */
    public static final Constructor<? extends InterfaceC2041h> f3801a;

    static {
        Constructor<? extends InterfaceC2041h> constructor = null;
        try {
            if (Boolean.TRUE.equals(Class.forName("com.google.android.exoplayer2.ext.flac.FlacLibrary").getMethod("isAvailable", new Class[0]).invoke(null, new Object[0]))) {
                constructor = Class.forName("com.google.android.exoplayer2.ext.flac.FlacExtractor").asSubclass(InterfaceC2041h.class).getConstructor(new Class[0]);
            }
        } catch (ClassNotFoundException unused) {
        } catch (Exception e2) {
            throw new RuntimeException("Error instantiating FLAC extension", e2);
        }
        f3801a = constructor;
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2043j
    /* renamed from: a */
    public synchronized InterfaceC2041h[] mo1571a() {
        InterfaceC2041h[] interfaceC2041hArr;
        interfaceC2041hArr = new InterfaceC2041h[14];
        interfaceC2041hArr[0] = new C1969d(0);
        interfaceC2041hArr[1] = new C1984d(0, null, null, Collections.emptyList());
        interfaceC2041hArr[2] = new C1986f(0);
        interfaceC2041hArr[3] = new C1976d(0, -9223372036854775807L);
        interfaceC2041hArr[4] = new C2014e(0);
        interfaceC2041hArr[5] = new C2006a();
        interfaceC2041hArr[6] = new C2009b0(1, new C2342c0(0L), new C2016g(0));
        interfaceC2041hArr[7] = new C2062b();
        interfaceC2041hArr[8] = new C1996c();
        interfaceC2041hArr[9] = new C2030u();
        interfaceC2041hArr[10] = new C2037a();
        interfaceC2041hArr[11] = new C2057a(0);
        interfaceC2041hArr[12] = new C2010c();
        Constructor<? extends InterfaceC2041h> constructor = f3801a;
        if (constructor != null) {
            try {
                interfaceC2041hArr[13] = constructor.newInstance(new Object[0]);
            } catch (Exception e2) {
                throw new IllegalStateException("Unexpected error creating FLAC extractor", e2);
            }
        } else {
            interfaceC2041hArr[13] = new C2060c();
        }
        return interfaceC2041hArr;
    }
}
