package R2;

import Q2.C;
import Q2.i;
import Q2.l;
import t2.j;

/* JADX INFO: loaded from: classes.dex */
public abstract class b {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private static final char[] f2637a = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

    /* JADX INFO: Access modifiers changed from: private */
    /* JADX WARN: Code restructure failed: missing block: B:39:0x005b, code lost:
    
        return -1;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final int c(byte[] r18, int r19) {
        /*
            Method dump skipped, instruction units count: 425
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: R2.b.c(byte[], int):int");
    }

    public static final l d(l lVar, String str) {
        j.f(lVar, "$this$commonDigest");
        j.f(str, "algorithm");
        c cVarA = d.a(str);
        cVarA.b(lVar.g(), 0, lVar.v());
        return new l(cVarA.a());
    }

    public static final l e(C c3, String str) {
        j.f(c3, "$this$commonSegmentDigest");
        j.f(str, "algorithm");
        c cVarA = d.a(str);
        int length = c3.C().length;
        int i3 = 0;
        int i4 = 0;
        while (i3 < length) {
            int i5 = c3.B()[length + i3];
            int i6 = c3.B()[i3];
            cVarA.b(c3.C()[i3], i5, i6 - i4);
            i3++;
            i4 = i6;
        }
        return new l(cVarA.a());
    }

    public static final void f(l lVar, i iVar, int i3, int i4) {
        j.f(lVar, "$this$commonWrite");
        j.f(iVar, "buffer");
        iVar.j(lVar.g(), i3, i4);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final int g(char c3) {
        if ('0' <= c3 && '9' >= c3) {
            return c3 - '0';
        }
        if ('a' <= c3 && 'f' >= c3) {
            return c3 - 'W';
        }
        if ('A' <= c3 && 'F' >= c3) {
            return c3 - '7';
        }
        throw new IllegalArgumentException("Unexpected hex digit: " + c3);
    }

    public static final char[] h() {
        return f2637a;
    }
}
