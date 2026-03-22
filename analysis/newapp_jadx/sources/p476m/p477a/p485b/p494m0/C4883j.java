package p476m.p477a.p485b.p494m0;

import com.yalantis.ucrop.view.CropImageView;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p476m.p477a.p485b.C4793b0;
import p476m.p477a.p485b.C4794c;
import p476m.p477a.p485b.C4873m;
import p476m.p477a.p485b.C4905y;
import p476m.p477a.p485b.InterfaceC4792b;
import p476m.p477a.p485b.InterfaceC4898r;
import p476m.p477a.p485b.InterfaceC4899s;
import p476m.p477a.p485b.p487i0.C4810c;
import p476m.p477a.p485b.p488j0.C4817e;
import p476m.p477a.p485b.p493l0.C4854b;
import p476m.p477a.p485b.p493l0.C4859g;

/* renamed from: m.a.b.m0.j */
/* loaded from: classes3.dex */
public class C4883j {

    /* renamed from: a */
    public volatile InterfaceC4881h f12484a;

    /* renamed from: b */
    public volatile C4889p f12485b;

    /* renamed from: c */
    public volatile InterfaceC4792b f12486c;

    /* renamed from: d */
    public volatile InterfaceC4899s f12487d;

    /* renamed from: e */
    public volatile InterfaceC4880g f12488e;

    public C4883j(InterfaceC4881h interfaceC4881h, InterfaceC4792b interfaceC4792b, InterfaceC4899s interfaceC4899s, C4889p c4889p, InterfaceC4880g interfaceC4880g) {
        this.f12484a = null;
        this.f12485b = null;
        this.f12486c = null;
        this.f12487d = null;
        this.f12488e = null;
        C2354n.m2470e1(interfaceC4881h, "HTTP processor");
        this.f12484a = interfaceC4881h;
        this.f12486c = interfaceC4792b;
        this.f12487d = interfaceC4899s == null ? C4817e.f12316a : interfaceC4899s;
        this.f12485b = c4889p;
        this.f12488e = null;
    }

    /* JADX WARN: Code restructure failed: missing block: B:18:0x008f, code lost:
    
        if (r1 == null) goto L53;
     */
    /* JADX WARN: Code restructure failed: missing block: B:20:0x0099, code lost:
    
        if (r1.length() < r6.length()) goto L54;
     */
    /* JADX WARN: Code restructure failed: missing block: B:22:0x00a3, code lost:
    
        if (r1.length() != r6.length()) goto L58;
     */
    /* JADX WARN: Code restructure failed: missing block: B:25:0x00ab, code lost:
    
        if (r6.endsWith("*") == false) goto L59;
     */
    /* JADX WARN: Code restructure failed: missing block: B:27:0x00ad, code lost:
    
        r3 = r0.f12494a.get(r6);
     */
    /* JADX WARN: Code restructure failed: missing block: B:28:0x00b3, code lost:
    
        r1 = r6;
     */
    /* renamed from: a */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void m5551a(p476m.p477a.p485b.InterfaceC4895o r11, p476m.p477a.p485b.InterfaceC4898r r12, p476m.p477a.p485b.p494m0.InterfaceC4877d r13) {
        /*
            r10 = this;
            m.a.b.m0.p r0 = r10.f12485b
            r1 = 0
            if (r0 == 0) goto Lbd
            m.a.b.m0.p r0 = r10.f12485b
            java.util.Objects.requireNonNull(r0)
            java.lang.String r2 = "HTTP request"
            p005b.p199l.p200a.p201a.p250p1.C2354n.m2470e1(r11, r2)
            m.a.b.m0.q<m.a.b.m0.i> r0 = r0.f12493a
            m.a.b.e0 r2 = r11.mo5525k()
            java.lang.String r2 = r2.getUri()
            r3 = 63
            int r3 = r2.indexOf(r3)
            r4 = -1
            r5 = 0
            if (r3 == r4) goto L28
            java.lang.String r2 = r2.substring(r5, r3)
            goto L34
        L28:
            r3 = 35
            int r3 = r2.indexOf(r3)
            if (r3 == r4) goto L34
            java.lang.String r2 = r2.substring(r5, r3)
        L34:
            monitor-enter(r0)
            java.lang.String r3 = "Request path"
            p005b.p199l.p200a.p201a.p250p1.C2354n.m2470e1(r2, r3)     // Catch: java.lang.Throwable -> Lba
            java.util.Map<java.lang.String, T> r3 = r0.f12494a     // Catch: java.lang.Throwable -> Lba
            java.lang.Object r3 = r3.get(r2)     // Catch: java.lang.Throwable -> Lba
            if (r3 != 0) goto Lb5
            java.util.Map<java.lang.String, T> r4 = r0.f12494a     // Catch: java.lang.Throwable -> Lba
            java.util.Set r4 = r4.keySet()     // Catch: java.lang.Throwable -> Lba
            java.util.Iterator r4 = r4.iterator()     // Catch: java.lang.Throwable -> Lba
        L4c:
            boolean r6 = r4.hasNext()     // Catch: java.lang.Throwable -> Lba
            if (r6 == 0) goto Lb5
            java.lang.Object r6 = r4.next()     // Catch: java.lang.Throwable -> Lba
            java.lang.String r6 = (java.lang.String) r6     // Catch: java.lang.Throwable -> Lba
            java.lang.String r7 = "*"
            boolean r8 = r6.equals(r7)     // Catch: java.lang.Throwable -> Lba
            r9 = 1
            if (r8 == 0) goto L62
            goto L8d
        L62:
            boolean r8 = r6.endsWith(r7)     // Catch: java.lang.Throwable -> Lba
            if (r8 == 0) goto L77
            int r8 = r6.length()     // Catch: java.lang.Throwable -> Lba
            int r8 = r8 - r9
            java.lang.String r8 = r6.substring(r5, r8)     // Catch: java.lang.Throwable -> Lba
            boolean r8 = r2.startsWith(r8)     // Catch: java.lang.Throwable -> Lba
            if (r8 != 0) goto L8d
        L77:
            boolean r7 = r6.startsWith(r7)     // Catch: java.lang.Throwable -> Lba
            if (r7 == 0) goto L8c
            int r7 = r6.length()     // Catch: java.lang.Throwable -> Lba
            java.lang.String r7 = r6.substring(r9, r7)     // Catch: java.lang.Throwable -> Lba
            boolean r7 = r2.endsWith(r7)     // Catch: java.lang.Throwable -> Lba
            if (r7 == 0) goto L8c
            goto L8d
        L8c:
            r9 = 0
        L8d:
            if (r9 == 0) goto L4c
            if (r1 == 0) goto Lad
            int r7 = r1.length()     // Catch: java.lang.Throwable -> Lba
            int r8 = r6.length()     // Catch: java.lang.Throwable -> Lba
            if (r7 < r8) goto Lad
            int r7 = r1.length()     // Catch: java.lang.Throwable -> Lba
            int r8 = r6.length()     // Catch: java.lang.Throwable -> Lba
            if (r7 != r8) goto L4c
            java.lang.String r7 = "*"
            boolean r7 = r6.endsWith(r7)     // Catch: java.lang.Throwable -> Lba
            if (r7 == 0) goto L4c
        Lad:
            java.util.Map<java.lang.String, T> r1 = r0.f12494a     // Catch: java.lang.Throwable -> Lba
            java.lang.Object r3 = r1.get(r6)     // Catch: java.lang.Throwable -> Lba
            r1 = r6
            goto L4c
        Lb5:
            monitor-exit(r0)
            r1 = r3
            m.a.b.m0.i r1 = (p476m.p477a.p485b.p494m0.InterfaceC4882i) r1
            goto Lbd
        Lba:
            r11 = move-exception
            monitor-exit(r0)
            throw r11
        Lbd:
            if (r1 == 0) goto Lc3
            r1.mo485a(r11, r12, r13)
            goto Lca
        Lc3:
            r11 = 501(0x1f5, float:7.02E-43)
            m.a.b.l0.g r12 = (p476m.p477a.p485b.p493l0.C4859g) r12
            r12.mo5529i(r11)
        Lca:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: p476m.p477a.p485b.p494m0.C4883j.m5551a(m.a.b.o, m.a.b.r, m.a.b.m0.d):void");
    }

    /* renamed from: b */
    public void m5552b(C4873m c4873m, InterfaceC4898r interfaceC4898r) {
        if (c4873m instanceof C4905y) {
            ((C4859g) interfaceC4898r).mo5529i(501);
        } else if (c4873m instanceof C4793b0) {
            ((C4859g) interfaceC4898r).mo5529i(400);
        } else {
            ((C4859g) interfaceC4898r).mo5529i(CropImageView.DEFAULT_IMAGE_TO_CROP_BOUNDS_ANIM_DURATION);
        }
        String message = c4873m.getMessage();
        if (message == null) {
            message = c4873m.toString();
        }
        C2354n.m2470e1(message, "Input");
        C4810c c4810c = new C4810c(message.getBytes(C4794c.f12277b));
        c4810c.f12295c = new C4854b("Content-Type", "text/plain; charset=US-ASCII");
        ((C4859g) interfaceC4898r).f12446f = c4810c;
    }

    /* JADX WARN: Code restructure failed: missing block: B:101:0x01c5, code lost:
    
        if (java.lang.Long.parseLong(r0[0].getValue()) < 0) goto L111;
     */
    /* JADX WARN: Code restructure failed: missing block: B:48:0x013c, code lost:
    
        if (r9.mo5519n("Transfer-Encoding") != null) goto L61;
     */
    /* JADX WARN: Code restructure failed: missing block: B:58:0x0134, code lost:
    
        if (java.lang.Integer.parseInt(r16.getValue()) > 0) goto L61;
     */
    /* JADX WARN: Code restructure failed: missing block: B:66:0x0183, code lost:
    
        if ("chunked".equalsIgnoreCase(r13.getValue()) == false) goto L61;
     */
    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:110:0x014f A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:42:0x00fb  */
    /* JADX WARN: Removed duplicated region for block: B:45:0x0123  */
    /* JADX WARN: Removed duplicated region for block: B:52:0x021a  */
    /* JADX WARN: Removed duplicated region for block: B:55:? A[RETURN, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:65:0x0179  */
    /* JADX WARN: Removed duplicated region for block: B:70:0x01d7  */
    /* JADX WARN: Removed duplicated region for block: B:73:0x01e8  */
    /* JADX WARN: Removed duplicated region for block: B:90:0x0188  */
    /* JADX WARN: Type inference failed for: r0v3, types: [m.a.b.m0.d] */
    /* JADX WARN: Type inference failed for: r0v4, types: [m.a.b.m0.h, m.a.b.t] */
    /* JADX WARN: Type inference failed for: r18v0, types: [java.lang.Object, m.a.b.i, m.a.b.u] */
    /* JADX WARN: Type inference failed for: r7v18 */
    /* JADX WARN: Type inference failed for: r7v19 */
    /* JADX WARN: Type inference failed for: r7v2 */
    /* JADX WARN: Type inference failed for: r7v20 */
    /* JADX WARN: Type inference failed for: r7v21 */
    /* JADX WARN: Type inference failed for: r7v22 */
    /* JADX WARN: Type inference failed for: r7v3, types: [java.lang.Object, m.a.b.r] */
    /* renamed from: c */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void m5553c(p476m.p477a.p485b.InterfaceC4901u r18, p476m.p477a.p485b.p494m0.InterfaceC4877d r19) {
        /*
            Method dump skipped, instructions count: 542
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p476m.p477a.p485b.p494m0.C4883j.m5553c(m.a.b.u, m.a.b.m0.d):void");
    }
}
