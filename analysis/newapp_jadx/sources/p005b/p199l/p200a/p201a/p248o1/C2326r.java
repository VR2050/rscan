package p005b.p199l.p200a.p201a.p248o1;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.Handler;
import android.os.Looper;
import android.util.SparseArray;
import androidx.annotation.Nullable;
import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import p005b.p199l.p200a.p201a.p248o1.C2326r;
import p005b.p199l.p200a.p201a.p248o1.InterfaceC2292g;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;
import p005b.p199l.p200a.p201a.p250p1.C2352l;
import p005b.p199l.p200a.p201a.p250p1.C2364x;
import p005b.p199l.p200a.p201a.p250p1.InterfaceC2346f;
import p005b.p199l.p200a.p201a.p253z0.C2408a;
import p005b.p199l.p200a.p201a.p253z0.InterfaceC2409b;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.l.a.a.o1.r */
/* loaded from: classes.dex */
public final class C2326r implements InterfaceC2292g, InterfaceC2291f0 {

    /* renamed from: a */
    public static final Map<String, int[]> f5949a;

    /* renamed from: b */
    public static final long[] f5950b;

    /* renamed from: c */
    public static final long[] f5951c;

    /* renamed from: d */
    public static final long[] f5952d;

    /* renamed from: e */
    public static final long[] f5953e;

    /* renamed from: f */
    @Nullable
    public static C2326r f5954f;

    /* renamed from: g */
    @Nullable
    public final Context f5955g;

    /* renamed from: h */
    public final SparseArray<Long> f5956h;

    /* renamed from: i */
    public final C2352l<InterfaceC2292g.a> f5957i;

    /* renamed from: j */
    public final C2364x f5958j;

    /* renamed from: k */
    public final InterfaceC2346f f5959k;

    /* renamed from: l */
    public int f5960l;

    /* renamed from: m */
    public long f5961m;

    /* renamed from: n */
    public long f5962n;

    /* renamed from: o */
    public int f5963o;

    /* renamed from: p */
    public long f5964p;

    /* renamed from: q */
    public long f5965q;

    /* renamed from: r */
    public long f5966r;

    /* renamed from: s */
    public long f5967s;

    /* renamed from: b.l.a.a.o1.r$a */
    public static final class a {

        /* renamed from: a */
        @Nullable
        public final Context f5968a;

        /* renamed from: b */
        public SparseArray<Long> f5969b;

        /* renamed from: c */
        public int f5970c;

        /* renamed from: d */
        public InterfaceC2346f f5971d;

        /* renamed from: e */
        public boolean f5972e;

        /* JADX WARN: Removed duplicated region for block: B:13:0x0041  */
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        public a(android.content.Context r11) {
            /*
                r10 = this;
                r10.<init>()
                if (r11 != 0) goto L7
                r0 = 0
                goto Lb
            L7:
                android.content.Context r0 = r11.getApplicationContext()
            Lb:
                r10.f5968a = r0
                int r0 = p005b.p199l.p200a.p201a.p250p1.C2344d0.f6035a
                if (r11 == 0) goto L2a
                java.lang.String r0 = "phone"
                java.lang.Object r11 = r11.getSystemService(r0)
                android.telephony.TelephonyManager r11 = (android.telephony.TelephonyManager) r11
                if (r11 == 0) goto L2a
                java.lang.String r11 = r11.getNetworkCountryIso()
                boolean r0 = android.text.TextUtils.isEmpty(r11)
                if (r0 != 0) goto L2a
                java.lang.String r11 = p005b.p199l.p200a.p201a.p250p1.C2344d0.m2322N(r11)
                goto L36
            L2a:
                java.util.Locale r11 = java.util.Locale.getDefault()
                java.lang.String r11 = r11.getCountry()
                java.lang.String r11 = p005b.p199l.p200a.p201a.p250p1.C2344d0.m2322N(r11)
            L36:
                java.util.Map<java.lang.String, int[]> r0 = p005b.p199l.p200a.p201a.p248o1.C2326r.f5949a
                java.lang.Object r11 = r0.get(r11)
                int[] r11 = (int[]) r11
                r0 = 4
                if (r11 != 0) goto L46
                int[] r11 = new int[r0]
                r11 = {x00b6: FILL_ARRAY_DATA , data: [2, 2, 2, 2} // fill-array
            L46:
                android.util.SparseArray r1 = new android.util.SparseArray
                r2 = 6
                r1.<init>(r2)
                r2 = 1000000(0xf4240, double:4.940656E-318)
                java.lang.Long r2 = java.lang.Long.valueOf(r2)
                r3 = 0
                r1.append(r3, r2)
                long[] r2 = p005b.p199l.p200a.p201a.p248o1.C2326r.f5950b
                r4 = r11[r3]
                r4 = r2[r4]
                java.lang.Long r4 = java.lang.Long.valueOf(r4)
                r5 = 2
                r1.append(r5, r4)
                long[] r4 = p005b.p199l.p200a.p201a.p248o1.C2326r.f5951c
                r6 = 1
                r7 = r11[r6]
                r7 = r4[r7]
                java.lang.Long r4 = java.lang.Long.valueOf(r7)
                r7 = 3
                r1.append(r7, r4)
                long[] r4 = p005b.p199l.p200a.p201a.p248o1.C2326r.f5952d
                r5 = r11[r5]
                r8 = r4[r5]
                java.lang.Long r4 = java.lang.Long.valueOf(r8)
                r1.append(r0, r4)
                r0 = 5
                long[] r4 = p005b.p199l.p200a.p201a.p248o1.C2326r.f5953e
                r5 = r11[r7]
                r7 = r4[r5]
                java.lang.Long r4 = java.lang.Long.valueOf(r7)
                r1.append(r0, r4)
                r0 = 7
                r4 = r11[r3]
                r4 = r2[r4]
                java.lang.Long r4 = java.lang.Long.valueOf(r4)
                r1.append(r0, r4)
                r0 = 9
                r11 = r11[r3]
                r3 = r2[r11]
                java.lang.Long r11 = java.lang.Long.valueOf(r3)
                r1.append(r0, r11)
                r10.f5969b = r1
                r11 = 2000(0x7d0, float:2.803E-42)
                r10.f5970c = r11
                b.l.a.a.p1.f r11 = p005b.p199l.p200a.p201a.p250p1.InterfaceC2346f.f6053a
                r10.f5971d = r11
                r10.f5972e = r6
                return
            */
            throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p200a.p201a.p248o1.C2326r.a.<init>(android.content.Context):void");
        }

        /* renamed from: a */
        public C2326r m2275a() {
            return new C2326r(this.f5968a, this.f5969b, this.f5970c, this.f5971d, this.f5972e);
        }
    }

    /* renamed from: b.l.a.a.o1.r$b */
    public static class b extends BroadcastReceiver {

        /* renamed from: a */
        public static b f5973a;

        /* renamed from: b */
        public final Handler f5974b = new Handler(Looper.getMainLooper());

        /* renamed from: c */
        public final ArrayList<WeakReference<C2326r>> f5975c = new ArrayList<>();

        /* renamed from: a */
        public final void m2276a() {
            for (int size = this.f5975c.size() - 1; size >= 0; size--) {
                if (this.f5975c.get(size).get() == null) {
                    this.f5975c.remove(size);
                }
            }
        }

        /* renamed from: b */
        public final void m2277b(C2326r c2326r) {
            Map<String, int[]> map = C2326r.f5949a;
            synchronized (c2326r) {
                Context context = c2326r.f5955g;
                int m2335m = context == null ? 0 : C2344d0.m2335m(context);
                if (c2326r.f5963o == m2335m) {
                    return;
                }
                c2326r.f5963o = m2335m;
                if (m2335m != 1 && m2335m != 0 && m2335m != 8) {
                    c2326r.f5966r = c2326r.m2273i(m2335m);
                    long mo2354c = c2326r.f5959k.mo2354c();
                    c2326r.m2274j(c2326r.f5960l > 0 ? (int) (mo2354c - c2326r.f5961m) : 0, c2326r.f5962n, c2326r.f5966r);
                    c2326r.f5961m = mo2354c;
                    c2326r.f5962n = 0L;
                    c2326r.f5965q = 0L;
                    c2326r.f5964p = 0L;
                    C2364x c2364x = c2326r.f5958j;
                    c2364x.f6143c.clear();
                    c2364x.f6145e = -1;
                    c2364x.f6146f = 0;
                    c2364x.f6147g = 0;
                }
            }
        }

        @Override // android.content.BroadcastReceiver
        public synchronized void onReceive(Context context, Intent intent) {
            if (isInitialStickyBroadcast()) {
                return;
            }
            m2276a();
            for (int i2 = 0; i2 < this.f5975c.size(); i2++) {
                C2326r c2326r = this.f5975c.get(i2).get();
                if (c2326r != null) {
                    m2277b(c2326r);
                }
            }
        }
    }

    static {
        HashMap hashMap = new HashMap();
        hashMap.put("AD", new int[]{1, 1, 0, 0});
        hashMap.put("AE", new int[]{1, 4, 4, 4});
        hashMap.put("AF", new int[]{4, 4, 3, 3});
        hashMap.put("AG", new int[]{3, 1, 0, 1});
        hashMap.put("AI", new int[]{1, 0, 0, 3});
        hashMap.put("AL", new int[]{1, 2, 0, 1});
        hashMap.put("AM", new int[]{2, 2, 2, 2});
        hashMap.put("AO", new int[]{3, 4, 2, 0});
        hashMap.put("AR", new int[]{2, 3, 2, 2});
        hashMap.put("AS", new int[]{3, 0, 4, 2});
        hashMap.put("AT", new int[]{0, 3, 0, 0});
        hashMap.put("AU", new int[]{0, 3, 0, 1});
        hashMap.put("AW", new int[]{1, 1, 0, 3});
        hashMap.put("AX", new int[]{0, 3, 0, 2});
        hashMap.put("AZ", new int[]{3, 3, 3, 3});
        hashMap.put("BA", new int[]{1, 1, 0, 1});
        hashMap.put("BB", new int[]{0, 2, 0, 0});
        hashMap.put("BD", new int[]{2, 1, 3, 3});
        hashMap.put("BE", new int[]{0, 0, 0, 1});
        hashMap.put("BF", new int[]{4, 4, 4, 1});
        hashMap.put("BG", new int[]{0, 1, 0, 0});
        hashMap.put("BH", new int[]{2, 1, 3, 4});
        hashMap.put("BI", new int[]{4, 4, 4, 4});
        hashMap.put("BJ", new int[]{4, 4, 4, 4});
        hashMap.put("BL", new int[]{1, 0, 2, 2});
        hashMap.put("BM", new int[]{1, 2, 0, 0});
        hashMap.put("BN", new int[]{4, 1, 3, 2});
        hashMap.put("BO", new int[]{1, 2, 3, 2});
        hashMap.put("BQ", new int[]{1, 1, 2, 4});
        hashMap.put("BR", new int[]{2, 3, 3, 2});
        hashMap.put("BS", new int[]{2, 1, 1, 4});
        hashMap.put("BT", new int[]{3, 0, 3, 1});
        hashMap.put("BW", new int[]{4, 4, 1, 2});
        hashMap.put("BY", new int[]{0, 1, 1, 2});
        hashMap.put("BZ", new int[]{2, 2, 2, 1});
        hashMap.put("CA", new int[]{0, 3, 1, 3});
        hashMap.put("CD", new int[]{4, 4, 2, 2});
        hashMap.put("CF", new int[]{4, 4, 3, 0});
        hashMap.put("CG", new int[]{3, 4, 2, 4});
        hashMap.put("CH", new int[]{0, 0, 1, 0});
        hashMap.put("CI", new int[]{3, 4, 3, 3});
        hashMap.put("CK", new int[]{2, 4, 1, 0});
        hashMap.put("CL", new int[]{1, 2, 2, 3});
        hashMap.put("CM", new int[]{3, 4, 3, 1});
        hashMap.put("CN", new int[]{2, 0, 2, 3});
        hashMap.put("CO", new int[]{2, 3, 2, 2});
        hashMap.put("CR", new int[]{2, 3, 4, 4});
        hashMap.put("CU", new int[]{4, 4, 3, 1});
        hashMap.put("CV", new int[]{2, 3, 1, 2});
        hashMap.put("CW", new int[]{1, 1, 0, 0});
        hashMap.put("CY", new int[]{1, 1, 0, 0});
        hashMap.put("CZ", new int[]{0, 1, 0, 0});
        hashMap.put("DE", new int[]{0, 1, 1, 3});
        hashMap.put("DJ", new int[]{4, 3, 4, 1});
        hashMap.put("DK", new int[]{0, 0, 1, 1});
        hashMap.put("DM", new int[]{1, 0, 1, 3});
        hashMap.put("DO", new int[]{3, 3, 4, 4});
        hashMap.put("DZ", new int[]{3, 3, 4, 4});
        hashMap.put("EC", new int[]{2, 3, 4, 3});
        hashMap.put("EE", new int[]{0, 1, 0, 0});
        hashMap.put("EG", new int[]{3, 4, 2, 2});
        hashMap.put("EH", new int[]{2, 0, 3, 3});
        hashMap.put("ER", new int[]{4, 2, 2, 0});
        hashMap.put("ES", new int[]{0, 1, 1, 1});
        hashMap.put("ET", new int[]{4, 4, 4, 0});
        hashMap.put("FI", new int[]{0, 0, 1, 0});
        hashMap.put("FJ", new int[]{3, 0, 3, 3});
        hashMap.put("FK", new int[]{3, 4, 2, 2});
        hashMap.put("FM", new int[]{4, 0, 4, 0});
        hashMap.put("FO", new int[]{0, 0, 0, 0});
        hashMap.put("FR", new int[]{1, 0, 3, 1});
        hashMap.put("GA", new int[]{3, 3, 2, 2});
        hashMap.put("GB", new int[]{0, 1, 3, 3});
        hashMap.put("GD", new int[]{2, 0, 4, 4});
        hashMap.put("GE", new int[]{1, 1, 1, 4});
        hashMap.put("GF", new int[]{2, 3, 4, 4});
        hashMap.put("GG", new int[]{0, 1, 0, 0});
        hashMap.put("GH", new int[]{3, 3, 2, 2});
        hashMap.put("GI", new int[]{0, 0, 0, 1});
        hashMap.put("GL", new int[]{2, 2, 0, 2});
        hashMap.put("GM", new int[]{4, 4, 3, 4});
        hashMap.put("GN", new int[]{3, 4, 4, 2});
        hashMap.put("GP", new int[]{2, 1, 1, 4});
        hashMap.put("GQ", new int[]{4, 4, 3, 0});
        hashMap.put("GR", new int[]{1, 1, 0, 2});
        hashMap.put("GT", new int[]{3, 3, 3, 3});
        hashMap.put("GU", new int[]{1, 2, 4, 4});
        hashMap.put("GW", new int[]{4, 4, 4, 1});
        hashMap.put("GY", new int[]{3, 2, 1, 1});
        hashMap.put("HK", new int[]{0, 2, 3, 4});
        hashMap.put("HN", new int[]{3, 2, 3, 2});
        hashMap.put("HR", new int[]{1, 1, 0, 1});
        hashMap.put("HT", new int[]{4, 4, 4, 4});
        hashMap.put("HU", new int[]{0, 1, 0, 0});
        hashMap.put("ID", new int[]{3, 2, 3, 4});
        hashMap.put("IE", new int[]{1, 0, 1, 1});
        hashMap.put("IL", new int[]{0, 0, 2, 3});
        hashMap.put("IM", new int[]{0, 0, 0, 1});
        hashMap.put("IN", new int[]{2, 2, 4, 4});
        hashMap.put("IO", new int[]{4, 2, 2, 2});
        hashMap.put("IQ", new int[]{3, 3, 4, 2});
        hashMap.put("IR", new int[]{3, 0, 2, 2});
        hashMap.put("IS", new int[]{0, 1, 0, 0});
        hashMap.put("IT", new int[]{1, 0, 1, 2});
        hashMap.put("JE", new int[]{1, 0, 0, 1});
        hashMap.put("JM", new int[]{2, 3, 3, 1});
        hashMap.put("JO", new int[]{1, 2, 1, 2});
        hashMap.put("JP", new int[]{0, 2, 1, 1});
        hashMap.put("KE", new int[]{3, 4, 4, 3});
        hashMap.put("KG", new int[]{1, 1, 2, 2});
        hashMap.put("KH", new int[]{1, 0, 4, 4});
        hashMap.put("KI", new int[]{4, 4, 4, 4});
        hashMap.put("KM", new int[]{4, 3, 2, 3});
        hashMap.put("KN", new int[]{1, 0, 1, 3});
        hashMap.put("KP", new int[]{4, 2, 4, 2});
        hashMap.put("KR", new int[]{0, 1, 1, 1});
        hashMap.put("KW", new int[]{2, 3, 1, 1});
        hashMap.put("KY", new int[]{1, 1, 0, 1});
        hashMap.put("KZ", new int[]{1, 2, 2, 3});
        hashMap.put("LA", new int[]{2, 2, 1, 1});
        hashMap.put("LB", new int[]{3, 2, 0, 0});
        hashMap.put("LC", new int[]{1, 1, 0, 0});
        hashMap.put("LI", new int[]{0, 0, 2, 4});
        hashMap.put("LK", new int[]{2, 1, 2, 3});
        hashMap.put("LR", new int[]{3, 4, 3, 1});
        hashMap.put("LS", new int[]{3, 3, 2, 0});
        hashMap.put("LT", new int[]{0, 0, 0, 0});
        hashMap.put("LU", new int[]{0, 0, 0, 0});
        hashMap.put("LV", new int[]{0, 0, 0, 0});
        hashMap.put("LY", new int[]{4, 4, 4, 4});
        hashMap.put("MA", new int[]{2, 1, 2, 1});
        hashMap.put("MC", new int[]{0, 0, 0, 1});
        hashMap.put("MD", new int[]{1, 1, 0, 0});
        hashMap.put("ME", new int[]{1, 2, 1, 2});
        hashMap.put("MF", new int[]{1, 1, 1, 1});
        hashMap.put("MG", new int[]{3, 4, 2, 2});
        hashMap.put("MH", new int[]{4, 0, 2, 4});
        hashMap.put("MK", new int[]{1, 0, 0, 0});
        hashMap.put("ML", new int[]{4, 4, 2, 0});
        hashMap.put("MM", new int[]{3, 3, 1, 2});
        hashMap.put("MN", new int[]{2, 3, 2, 3});
        hashMap.put("MO", new int[]{0, 0, 4, 4});
        hashMap.put("MP", new int[]{0, 2, 4, 4});
        hashMap.put("MQ", new int[]{2, 1, 1, 4});
        hashMap.put("MR", new int[]{4, 2, 4, 2});
        hashMap.put("MS", new int[]{1, 2, 3, 3});
        hashMap.put("MT", new int[]{0, 1, 0, 0});
        hashMap.put("MU", new int[]{2, 2, 3, 4});
        hashMap.put("MV", new int[]{4, 3, 0, 2});
        hashMap.put("MW", new int[]{3, 2, 1, 0});
        hashMap.put("MX", new int[]{2, 4, 4, 3});
        hashMap.put("MY", new int[]{2, 2, 3, 3});
        hashMap.put("MZ", new int[]{3, 3, 2, 1});
        hashMap.put("NA", new int[]{3, 3, 2, 1});
        hashMap.put("NC", new int[]{2, 0, 3, 3});
        hashMap.put("NE", new int[]{4, 4, 4, 3});
        hashMap.put("NF", new int[]{1, 2, 2, 2});
        hashMap.put("NG", new int[]{3, 4, 3, 1});
        hashMap.put("NI", new int[]{3, 3, 4, 4});
        hashMap.put("NL", new int[]{0, 2, 3, 3});
        hashMap.put("NO", new int[]{0, 1, 1, 0});
        hashMap.put("NP", new int[]{2, 2, 2, 2});
        hashMap.put("NR", new int[]{4, 0, 3, 1});
        hashMap.put("NZ", new int[]{0, 0, 1, 2});
        hashMap.put("OM", new int[]{3, 2, 1, 3});
        hashMap.put("PA", new int[]{1, 3, 3, 4});
        hashMap.put("PE", new int[]{2, 3, 4, 4});
        hashMap.put("PF", new int[]{2, 2, 0, 1});
        hashMap.put("PG", new int[]{4, 3, 3, 1});
        hashMap.put("PH", new int[]{3, 0, 3, 4});
        hashMap.put("PK", new int[]{3, 3, 3, 3});
        hashMap.put("PL", new int[]{1, 0, 1, 3});
        hashMap.put("PM", new int[]{0, 2, 2, 0});
        hashMap.put("PR", new int[]{1, 2, 3, 3});
        hashMap.put("PS", new int[]{3, 3, 2, 4});
        hashMap.put("PT", new int[]{1, 1, 0, 0});
        hashMap.put("PW", new int[]{2, 1, 2, 0});
        hashMap.put("PY", new int[]{2, 0, 2, 3});
        hashMap.put("QA", new int[]{2, 2, 1, 2});
        hashMap.put("RE", new int[]{1, 0, 2, 2});
        hashMap.put("RO", new int[]{0, 1, 1, 2});
        hashMap.put("RS", new int[]{1, 2, 0, 0});
        hashMap.put("RU", new int[]{0, 1, 1, 1});
        hashMap.put("RW", new int[]{4, 4, 2, 4});
        hashMap.put("SA", new int[]{2, 2, 2, 1});
        hashMap.put("SB", new int[]{4, 4, 3, 0});
        hashMap.put("SC", new int[]{4, 2, 0, 1});
        hashMap.put("SD", new int[]{4, 4, 4, 3});
        hashMap.put("SE", new int[]{0, 1, 0, 0});
        hashMap.put("SG", new int[]{0, 2, 3, 3});
        hashMap.put("SH", new int[]{4, 4, 2, 3});
        hashMap.put("SI", new int[]{0, 0, 0, 0});
        hashMap.put("SJ", new int[]{2, 0, 2, 4});
        hashMap.put("SK", new int[]{0, 1, 0, 0});
        hashMap.put("SL", new int[]{4, 3, 3, 3});
        hashMap.put("SM", new int[]{0, 0, 2, 4});
        hashMap.put("SN", new int[]{3, 4, 4, 2});
        hashMap.put("SO", new int[]{3, 4, 4, 3});
        hashMap.put("SR", new int[]{2, 2, 1, 0});
        hashMap.put("SS", new int[]{4, 3, 4, 3});
        hashMap.put("ST", new int[]{3, 4, 2, 2});
        hashMap.put("SV", new int[]{2, 3, 3, 4});
        hashMap.put("SX", new int[]{2, 4, 1, 0});
        hashMap.put("SY", new int[]{4, 3, 2, 1});
        hashMap.put("SZ", new int[]{4, 4, 3, 4});
        hashMap.put("TC", new int[]{1, 2, 1, 1});
        hashMap.put("TD", new int[]{4, 4, 4, 2});
        hashMap.put("TG", new int[]{3, 3, 1, 0});
        hashMap.put("TH", new int[]{1, 3, 4, 4});
        hashMap.put("TJ", new int[]{4, 4, 4, 4});
        hashMap.put("TL", new int[]{4, 2, 4, 4});
        hashMap.put("TM", new int[]{4, 1, 2, 2});
        hashMap.put("TN", new int[]{2, 2, 1, 2});
        hashMap.put("TO", new int[]{3, 3, 3, 1});
        hashMap.put("TR", new int[]{2, 2, 1, 2});
        hashMap.put("TT", new int[]{1, 3, 1, 2});
        hashMap.put("TV", new int[]{4, 2, 2, 4});
        hashMap.put("TW", new int[]{0, 0, 0, 0});
        hashMap.put("TZ", new int[]{3, 3, 4, 3});
        hashMap.put("UA", new int[]{0, 2, 1, 2});
        hashMap.put("UG", new int[]{4, 3, 3, 2});
        hashMap.put("US", new int[]{1, 1, 3, 3});
        hashMap.put("UY", new int[]{2, 2, 1, 1});
        hashMap.put("UZ", new int[]{2, 2, 2, 2});
        hashMap.put("VA", new int[]{1, 2, 4, 2});
        hashMap.put("VC", new int[]{2, 0, 2, 4});
        hashMap.put("VE", new int[]{4, 4, 4, 3});
        hashMap.put("VG", new int[]{3, 0, 1, 3});
        hashMap.put("VI", new int[]{1, 1, 4, 4});
        hashMap.put("VN", new int[]{0, 2, 4, 4});
        hashMap.put("VU", new int[]{4, 1, 3, 1});
        hashMap.put("WS", new int[]{3, 3, 3, 2});
        hashMap.put("XK", new int[]{1, 2, 1, 0});
        hashMap.put("YE", new int[]{4, 4, 4, 3});
        hashMap.put("YT", new int[]{2, 2, 2, 3});
        hashMap.put("ZA", new int[]{2, 4, 2, 2});
        hashMap.put("ZM", new int[]{3, 2, 2, 1});
        hashMap.put("ZW", new int[]{3, 3, 2, 1});
        f5949a = Collections.unmodifiableMap(hashMap);
        f5950b = new long[]{5700000, 3500000, 2000000, 1100000, 470000};
        f5951c = new long[]{200000, 148000, 132000, 115000, 95000};
        f5952d = new long[]{2200000, 1300000, 970000, 810000, 490000};
        f5953e = new long[]{5300000, 3200000, 2000000, 1400000, 690000};
    }

    @Deprecated
    public C2326r() {
        this(null, new SparseArray(), 2000, InterfaceC2346f.f6053a, false);
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.InterfaceC2291f0
    /* renamed from: a */
    public synchronized void mo2192a(InterfaceC2321m interfaceC2321m, C2324p c2324p, boolean z) {
        if (z) {
            C4195m.m4771I(this.f5960l > 0);
            long mo2354c = this.f5959k.mo2354c();
            int i2 = (int) (mo2354c - this.f5961m);
            this.f5964p += i2;
            long j2 = this.f5965q;
            long j3 = this.f5962n;
            this.f5965q = j2 + j3;
            if (i2 > 0) {
                this.f5958j.m2606a((int) Math.sqrt(j3), (j3 * 8000.0f) / i2);
                if (this.f5964p >= 2000 || this.f5965q >= 524288) {
                    this.f5966r = (long) this.f5958j.m2607b(0.5f);
                }
                m2274j(i2, this.f5962n, this.f5966r);
                this.f5961m = mo2354c;
                this.f5962n = 0L;
            }
            this.f5960l--;
        }
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.InterfaceC2291f0
    /* renamed from: b */
    public synchronized void mo2193b(InterfaceC2321m interfaceC2321m, C2324p c2324p, boolean z) {
        if (z) {
            if (this.f5960l == 0) {
                this.f5961m = this.f5959k.mo2354c();
            }
            this.f5960l++;
        }
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.InterfaceC2292g
    @Nullable
    /* renamed from: c */
    public InterfaceC2291f0 mo2196c() {
        return this;
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.InterfaceC2292g
    /* renamed from: d */
    public void mo2197d(InterfaceC2292g.a aVar) {
        this.f5957i.m2365c(aVar);
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.InterfaceC2292g
    /* renamed from: e */
    public synchronized long mo2198e() {
        return this.f5966r;
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.InterfaceC2291f0
    /* renamed from: f */
    public synchronized void mo2194f(InterfaceC2321m interfaceC2321m, C2324p c2324p, boolean z, int i2) {
        if (z) {
            this.f5962n += i2;
        }
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.InterfaceC2292g
    /* renamed from: g */
    public void mo2199g(Handler handler, InterfaceC2292g.a aVar) {
        this.f5957i.m2363a(handler, aVar);
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.InterfaceC2291f0
    /* renamed from: h */
    public void mo2195h(InterfaceC2321m interfaceC2321m, C2324p c2324p, boolean z) {
    }

    /* renamed from: i */
    public final long m2273i(int i2) {
        Long l2 = this.f5956h.get(i2);
        if (l2 == null) {
            l2 = this.f5956h.get(0);
        }
        if (l2 == null) {
            l2 = 1000000L;
        }
        return l2.longValue();
    }

    /* renamed from: j */
    public final void m2274j(final int i2, final long j2, final long j3) {
        if (i2 == 0 && j2 == 0 && j3 == this.f5967s) {
            return;
        }
        this.f5967s = j3;
        this.f5957i.m2364b(new C2352l.a() { // from class: b.l.a.a.o1.b
            @Override // p005b.p199l.p200a.p201a.p250p1.C2352l.a
            /* renamed from: a */
            public final void mo2190a(Object obj) {
                C2408a.a aVar;
                int i3 = i2;
                long j4 = j2;
                long j5 = j3;
                C2408a c2408a = (C2408a) ((InterfaceC2292g.a) obj);
                C2408a.b bVar = c2408a.f6405g;
                if (bVar.f6410a.isEmpty()) {
                    aVar = null;
                } else {
                    aVar = bVar.f6410a.get(r0.size() - 1);
                }
                InterfaceC2409b.a m2703e = c2408a.m2703e(aVar);
                Iterator<InterfaceC2409b> it = c2408a.f6402c.iterator();
                while (it.hasNext()) {
                    it.next().onBandwidthEstimate(m2703e, i3, j4, j5);
                }
            }
        });
    }

    public C2326r(@Nullable Context context, SparseArray<Long> sparseArray, int i2, InterfaceC2346f interfaceC2346f, boolean z) {
        final b bVar;
        this.f5955g = context == null ? null : context.getApplicationContext();
        this.f5956h = sparseArray;
        this.f5957i = new C2352l<>();
        this.f5958j = new C2364x(i2);
        this.f5959k = interfaceC2346f;
        int m2335m = context == null ? 0 : C2344d0.m2335m(context);
        this.f5963o = m2335m;
        this.f5966r = m2273i(m2335m);
        if (context == null || !z) {
            return;
        }
        b bVar2 = b.f5973a;
        synchronized (b.class) {
            if (b.f5973a == null) {
                b.f5973a = new b();
                IntentFilter intentFilter = new IntentFilter();
                intentFilter.addAction("android.net.conn.CONNECTIVITY_CHANGE");
                context.registerReceiver(b.f5973a, intentFilter);
            }
            bVar = b.f5973a;
        }
        synchronized (bVar) {
            bVar.m2276a();
            bVar.f5975c.add(new WeakReference<>(this));
            bVar.f5974b.post(new Runnable() { // from class: b.l.a.a.o1.a
                @Override // java.lang.Runnable
                public final void run() {
                    C2326r.b.this.m2277b(this);
                }
            });
        }
    }
}
