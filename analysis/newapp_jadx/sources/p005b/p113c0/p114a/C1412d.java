package p005b.p113c0.p114a;

import android.content.Context;
import java.io.File;
import java.util.LinkedList;
import java.util.List;
import p005b.p113c0.p114a.p116h.C1430f;
import p005b.p113c0.p114a.p116h.InterfaceC1426b;
import p005b.p113c0.p114a.p116h.InterfaceC1427c;
import p005b.p113c0.p114a.p116h.p118h.C1434b;
import p005b.p113c0.p114a.p116h.p120j.InterfaceC1437a;
import p005b.p113c0.p114a.p116h.p122l.C1450d;
import p005b.p113c0.p114a.p124i.C1464j;
import p005b.p113c0.p114a.p124i.C1465k;
import p005b.p113c0.p114a.p124i.C1466l;
import p005b.p113c0.p114a.p124i.InterfaceC1457c;
import p005b.p113c0.p114a.p124i.p126o.C1477g;
import p005b.p113c0.p114a.p124i.p126o.InterfaceC1474d;
import p005b.p113c0.p114a.p124i.p127p.C1481d;
import p005b.p113c0.p114a.p128j.InterfaceC1484b;
import p476m.p477a.p485b.InterfaceC4895o;
import p476m.p477a.p485b.InterfaceC4898r;
import p476m.p477a.p485b.p494m0.InterfaceC4877d;
import p476m.p477a.p485b.p494m0.InterfaceC4882i;

/* renamed from: b.c0.a.d */
/* loaded from: classes2.dex */
public class C1412d implements InterfaceC4882i, InterfaceC1484b {

    /* renamed from: a */
    public final Context f1366a;

    /* renamed from: b */
    public C1481d f1367b;

    /* renamed from: e */
    public C1434b f1370e;

    /* renamed from: f */
    public List<InterfaceC1437a> f1371f = new LinkedList();

    /* renamed from: g */
    public List<InterfaceC1427c> f1372g = new LinkedList();

    /* renamed from: c */
    public C1450d f1368c = new C1450d();

    /* renamed from: d */
    public InterfaceC1426b f1369d = new InterfaceC1426b.b(InterfaceC1426b.f1376a);

    public C1412d(Context context) {
        this.f1366a = context;
        this.f1367b = new C1481d(context);
        this.f1372g.add(new C1430f());
    }

    @Override // p476m.p477a.p485b.p494m0.InterfaceC4882i
    /* renamed from: a */
    public void mo485a(InterfaceC4895o interfaceC4895o, InterfaceC4898r interfaceC4898r, InterfaceC4877d interfaceC4877d) {
        m488d(new C1465k(interfaceC4895o, new C1464j(interfaceC4877d), this, this.f1367b), new C1466l(interfaceC4898r));
    }

    /* renamed from: b */
    public final void m486b(InterfaceC1474d interfaceC1474d) {
        C1434b c1434b = this.f1370e;
        if (c1434b != null) {
            long j2 = c1434b.f1382a;
            if (j2 == -1 || j2 > 0) {
                ((C1477g) interfaceC1474d).f1466b.f12182a = j2;
            }
            long j3 = c1434b.f1383b;
            if (j3 == -1 || j3 > 0) {
                ((C1477g) interfaceC1474d).f1466b.f12183b = j3;
            }
            int i2 = c1434b.f1384c;
            if (i2 > 0) {
                ((C1477g) interfaceC1474d).f1465a.f12248b = i2;
            }
            File file = c1434b.f1385d;
            if (file != null) {
                C1477g c1477g = (C1477g) interfaceC1474d;
                if (file.exists() || file.mkdirs()) {
                    c1477g.f1465a.f12247a = file;
                    return;
                }
                throw new IllegalArgumentException("Given uploadTempDir [" + file + "] could not be created.");
            }
        }
    }

    /* renamed from: c */
    public final InterfaceC1437a m487c(InterfaceC1457c interfaceC1457c) {
        for (InterfaceC1437a interfaceC1437a : this.f1371f) {
            if (interfaceC1437a.mo499b(interfaceC1457c)) {
                return interfaceC1437a;
            }
        }
        return null;
    }

    /* JADX WARN: Removed duplicated region for block: B:11:0x0051 A[Catch: all -> 0x003f, TryCatch #2 {all -> 0x003f, blocks: (B:3:0x0006, B:8:0x0044, B:9:0x004b, B:11:0x0051, B:13:0x0057, B:14:0x005d, B:16:0x0063, B:26:0x007d, B:35:0x009a, B:36:0x00a3, B:37:0x00a4, B:38:0x00ad, B:39:0x0013, B:41:0x0019, B:49:0x002a, B:52:0x0023), top: B:2:0x0006 }] */
    /* JADX WARN: Removed duplicated region for block: B:37:0x00a4 A[Catch: all -> 0x003f, TryCatch #2 {all -> 0x003f, blocks: (B:3:0x0006, B:8:0x0044, B:9:0x004b, B:11:0x0051, B:13:0x0057, B:14:0x005d, B:16:0x0063, B:26:0x007d, B:35:0x009a, B:36:0x00a3, B:37:0x00a4, B:38:0x00ad, B:39:0x0013, B:41:0x0019, B:49:0x002a, B:52:0x0023), top: B:2:0x0006 }] */
    /* JADX WARN: Removed duplicated region for block: B:48:0x003d  */
    /* JADX WARN: Removed duplicated region for block: B:8:0x0044 A[Catch: all -> 0x003f, TryCatch #2 {all -> 0x003f, blocks: (B:3:0x0006, B:8:0x0044, B:9:0x004b, B:11:0x0051, B:13:0x0057, B:14:0x005d, B:16:0x0063, B:26:0x007d, B:35:0x009a, B:36:0x00a3, B:37:0x00a4, B:38:0x00ad, B:39:0x0013, B:41:0x0019, B:49:0x002a, B:52:0x0023), top: B:2:0x0006 }] */
    /* renamed from: d */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void m488d(p005b.p113c0.p114a.p124i.InterfaceC1457c r8, p005b.p113c0.p114a.p124i.InterfaceC1458d r9) {
        /*
            Method dump skipped, instructions count: 245
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p113c0.p114a.C1412d.m488d(b.c0.a.i.c, b.c0.a.i.d):void");
    }

    /* JADX WARN: Removed duplicated region for block: B:17:0x0069  */
    /* renamed from: e */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void m489e(p005b.p113c0.p114a.p124i.InterfaceC1457c r12, p005b.p113c0.p114a.p124i.InterfaceC1458d r13) {
        /*
            Method dump skipped, instructions count: 227
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p113c0.p114a.C1412d.m489e(b.c0.a.i.c, b.c0.a.i.d):void");
    }
}
