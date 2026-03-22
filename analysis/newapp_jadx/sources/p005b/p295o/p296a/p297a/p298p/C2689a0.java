package p005b.p295o.p296a.p297a.p298p;

import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Stack;

/* renamed from: b.o.a.a.p.a0 */
/* loaded from: classes2.dex */
public class C2689a0 {

    /* renamed from: a */
    public static Hashtable f7356a = new Hashtable();

    /* renamed from: b */
    public Stack f7357b;

    /* renamed from: c */
    public boolean f7358c;

    /* renamed from: d */
    public String f7359d;

    public C2689a0(boolean z, C2707r[] c2707rArr) {
        this.f7357b = new Stack();
        for (C2707r c2707r : c2707rArr) {
            this.f7357b.addElement(c2707r);
        }
        this.f7358c = z;
        this.f7359d = null;
    }

    /* renamed from: a */
    public static C2689a0 m3230a(String str) {
        C2689a0 c2689a0;
        synchronized (f7356a) {
            c2689a0 = (C2689a0) f7356a.get(str);
            if (c2689a0 == null) {
                c2689a0 = new C2689a0(str);
                f7356a.put(str, c2689a0);
            }
        }
        return c2689a0;
    }

    public Object clone() {
        int size = this.f7357b.size();
        C2707r[] c2707rArr = new C2707r[size];
        Enumeration elements = this.f7357b.elements();
        for (int i2 = 0; i2 < size; i2++) {
            c2707rArr[i2] = (C2707r) elements.nextElement();
        }
        return new C2689a0(this.f7358c, c2707rArr);
    }

    public String toString() {
        if (this.f7359d == null) {
            StringBuffer stringBuffer = new StringBuffer();
            Enumeration elements = this.f7357b.elements();
            boolean z = true;
            while (elements.hasMoreElements()) {
                C2707r c2707r = (C2707r) elements.nextElement();
                if (!z || this.f7358c) {
                    stringBuffer.append('/');
                    if (c2707r.f7379c) {
                        stringBuffer.append('/');
                    }
                }
                stringBuffer.append(c2707r.toString());
                z = false;
            }
            this.f7359d = stringBuffer.toString();
        }
        return this.f7359d;
    }

    /* JADX WARN: Removed duplicated region for block: B:20:0x006c A[Catch: IOException -> 0x0091, TryCatch #0 {IOException -> 0x0091, blocks: (B:3:0x0018, B:6:0x0030, B:10:0x003e, B:12:0x0046, B:14:0x004e, B:16:0x0056, B:17:0x005e, B:18:0x0068, B:20:0x006c, B:22:0x0072, B:24:0x0078, B:32:0x0087, B:33:0x0090, B:36:0x005b), top: B:2:0x0018 }] */
    /* JADX WARN: Removed duplicated region for block: B:27:0x0083 A[EDGE_INSN: B:27:0x0083->B:28:0x0083 BREAK  A[LOOP:2: B:18:0x0068->B:24:0x0078], SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:30:0x0086 A[RETURN] */
    /* JADX WARN: Removed duplicated region for block: B:32:0x0087 A[Catch: IOException -> 0x0091, TryCatch #0 {IOException -> 0x0091, blocks: (B:3:0x0018, B:6:0x0030, B:10:0x003e, B:12:0x0046, B:14:0x004e, B:16:0x0056, B:17:0x005e, B:18:0x0068, B:20:0x006c, B:22:0x0072, B:24:0x0078, B:32:0x0087, B:33:0x0090, B:36:0x005b), top: B:2:0x0018 }] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public C2689a0(java.lang.String r7) {
        /*
            r6 = this;
            java.io.InputStreamReader r0 = new java.io.InputStreamReader
            java.io.ByteArrayInputStream r1 = new java.io.ByteArrayInputStream
            byte[] r2 = r7.getBytes()
            r1.<init>(r2)
            r0.<init>(r1)
            r6.<init>()
            java.util.Stack r1 = new java.util.Stack
            r1.<init>()
            r6.f7357b = r1
            r6.f7359d = r7     // Catch: java.io.IOException -> L91
            b.o.a.a.p.q r7 = new b.o.a.a.p.q     // Catch: java.io.IOException -> L91
            r7.<init>(r0)     // Catch: java.io.IOException -> L91
            int[] r0 = r7.f7374g     // Catch: java.io.IOException -> L91
            r1 = 47
            r0[r1] = r1     // Catch: java.io.IOException -> L91
            r2 = 46
            r0[r2] = r2     // Catch: java.io.IOException -> L91
            r0 = 58
            r2 = 58
        L2d:
            r3 = -3
            if (r2 > r0) goto L38
            int[] r4 = r7.f7374g     // Catch: java.io.IOException -> L91
            r4[r2] = r3     // Catch: java.io.IOException -> L91
            int r2 = r2 + 1
            char r2 = (char) r2     // Catch: java.io.IOException -> L91
            goto L2d
        L38:
            r0 = 95
            r2 = 95
        L3c:
            if (r2 > r0) goto L46
            int[] r4 = r7.f7374g     // Catch: java.io.IOException -> L91
            r4[r2] = r3     // Catch: java.io.IOException -> L91
            int r2 = r2 + 1
            char r2 = (char) r2     // Catch: java.io.IOException -> L91
            goto L3c
        L46:
            int r0 = r7.m3235a()     // Catch: java.io.IOException -> L91
            r2 = 0
            r3 = 1
            if (r0 != r1) goto L5b
            r6.f7358c = r3     // Catch: java.io.IOException -> L91
            int r0 = r7.m3235a()     // Catch: java.io.IOException -> L91
            if (r0 != r1) goto L5d
            r7.m3235a()     // Catch: java.io.IOException -> L91
            r0 = 1
            goto L5e
        L5b:
            r6.f7358c = r2     // Catch: java.io.IOException -> L91
        L5d:
            r0 = 0
        L5e:
            java.util.Stack r4 = r6.f7357b     // Catch: java.io.IOException -> L91
            b.o.a.a.p.r r5 = new b.o.a.a.p.r     // Catch: java.io.IOException -> L91
            r5.<init>(r6, r0, r7)     // Catch: java.io.IOException -> L91
            r4.push(r5)     // Catch: java.io.IOException -> L91
        L68:
            int r0 = r7.f7368a     // Catch: java.io.IOException -> L91
            if (r0 != r1) goto L83
            int r0 = r7.m3235a()     // Catch: java.io.IOException -> L91
            if (r0 != r1) goto L77
            r7.m3235a()     // Catch: java.io.IOException -> L91
            r0 = 1
            goto L78
        L77:
            r0 = 0
        L78:
            java.util.Stack r4 = r6.f7357b     // Catch: java.io.IOException -> L91
            b.o.a.a.p.r r5 = new b.o.a.a.p.r     // Catch: java.io.IOException -> L91
            r5.<init>(r6, r0, r7)     // Catch: java.io.IOException -> L91
            r4.push(r5)     // Catch: java.io.IOException -> L91
            goto L68
        L83:
            r1 = -1
            if (r0 != r1) goto L87
            return
        L87:
            b.o.a.a.p.b0 r0 = new b.o.a.a.p.b0     // Catch: java.io.IOException -> L91
            java.lang.String r1 = "at end of XPATH expression"
            java.lang.String r2 = "end of expression"
            r0.<init>(r6, r1, r7, r2)     // Catch: java.io.IOException -> L91
            throw r0     // Catch: java.io.IOException -> L91
        L91:
            r7 = move-exception
            b.o.a.a.p.b0 r0 = new b.o.a.a.p.b0
            r0.<init>(r6, r7)
            throw r0
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p295o.p296a.p297a.p298p.C2689a0.<init>(java.lang.String):void");
    }
}
