package p005b.p199l.p200a.p201a.p236l1.p242r;

import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.text.SpannableStringBuilder;
import android.util.Base64;
import android.util.Pair;
import androidx.core.view.ViewCompat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;
import java.util.TreeSet;
import p005b.p199l.p200a.p201a.p236l1.C2207b;
import p005b.p199l.p200a.p201a.p236l1.InterfaceC2210e;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;

/* renamed from: b.l.a.a.l1.r.e */
/* loaded from: classes.dex */
public final class C2238e implements InterfaceC2210e {

    /* renamed from: c */
    public final C2235b f5541c;

    /* renamed from: e */
    public final long[] f5542e;

    /* renamed from: f */
    public final Map<String, C2237d> f5543f;

    /* renamed from: g */
    public final Map<String, C2236c> f5544g;

    /* renamed from: h */
    public final Map<String, String> f5545h;

    public C2238e(C2235b c2235b, Map<String, C2237d> map, Map<String, C2236c> map2, Map<String, String> map3) {
        this.f5541c = c2235b;
        this.f5544g = map2;
        this.f5545h = map3;
        this.f5543f = Collections.unmodifiableMap(map);
        Objects.requireNonNull(c2235b);
        TreeSet<Long> treeSet = new TreeSet<>();
        int i2 = 0;
        c2235b.m2114e(treeSet, false);
        long[] jArr = new long[treeSet.size()];
        Iterator<Long> it = treeSet.iterator();
        while (it.hasNext()) {
            jArr[i2] = it.next().longValue();
            i2++;
        }
        this.f5542e = jArr;
    }

    @Override // p005b.p199l.p200a.p201a.p236l1.InterfaceC2210e
    /* renamed from: a */
    public int mo2048a(long j2) {
        int m2324b = C2344d0.m2324b(this.f5542e, j2, false, false);
        if (m2324b < this.f5542e.length) {
            return m2324b;
        }
        return -1;
    }

    @Override // p005b.p199l.p200a.p201a.p236l1.InterfaceC2210e
    /* renamed from: b */
    public long mo2049b(int i2) {
        return this.f5542e[i2];
    }

    @Override // p005b.p199l.p200a.p201a.p236l1.InterfaceC2210e
    /* renamed from: c */
    public List<C2207b> mo2050c(long j2) {
        int i2;
        int i3;
        C2235b c2235b = this.f5541c;
        Map<String, C2237d> map = this.f5543f;
        Map<String, C2236c> map2 = this.f5544g;
        Map<String, String> map3 = this.f5545h;
        Objects.requireNonNull(c2235b);
        ArrayList arrayList = new ArrayList();
        c2235b.m2116h(j2, c2235b.f5514h, arrayList);
        TreeMap treeMap = new TreeMap();
        c2235b.m2118j(j2, false, c2235b.f5514h, treeMap);
        c2235b.m2117i(j2, map, treeMap);
        ArrayList arrayList2 = new ArrayList();
        Iterator it = arrayList.iterator();
        while (it.hasNext()) {
            Pair pair = (Pair) it.next();
            String str = map3.get(pair.second);
            if (str != null) {
                byte[] decode = Base64.decode(str, 0);
                Bitmap decodeByteArray = BitmapFactory.decodeByteArray(decode, 0, decode.length);
                C2236c c2236c = map2.get(pair.first);
                arrayList2.add(new C2207b(decodeByteArray, c2236c.f5520b, 0, c2236c.f5521c, c2236c.f5523e, c2236c.f5524f, c2236c.f5525g));
            }
        }
        for (Map.Entry entry : treeMap.entrySet()) {
            C2236c c2236c2 = map2.get(entry.getKey());
            SpannableStringBuilder spannableStringBuilder = (SpannableStringBuilder) entry.getValue();
            int length = spannableStringBuilder.length();
            for (int i4 = 0; i4 < length; i4++) {
                if (spannableStringBuilder.charAt(i4) == ' ') {
                    int i5 = i4 + 1;
                    int i6 = i5;
                    while (i6 < spannableStringBuilder.length() && spannableStringBuilder.charAt(i6) == ' ') {
                        i6++;
                    }
                    int i7 = i6 - i5;
                    if (i7 > 0) {
                        spannableStringBuilder.delete(i4, i4 + i7);
                        length -= i7;
                    }
                }
            }
            if (length > 0 && spannableStringBuilder.charAt(0) == ' ') {
                spannableStringBuilder.delete(0, 1);
                length--;
            }
            int i8 = 0;
            while (true) {
                i2 = length - 1;
                if (i8 >= i2) {
                    break;
                }
                if (spannableStringBuilder.charAt(i8) == '\n') {
                    int i9 = i8 + 1;
                    if (spannableStringBuilder.charAt(i9) == ' ') {
                        spannableStringBuilder.delete(i9, i8 + 2);
                        length = i2;
                    }
                }
                i8++;
            }
            if (length > 0 && spannableStringBuilder.charAt(i2) == ' ') {
                spannableStringBuilder.delete(i2, length);
                length = i2;
            }
            int i10 = 0;
            while (true) {
                i3 = length - 1;
                if (i10 >= i3) {
                    break;
                }
                if (spannableStringBuilder.charAt(i10) == ' ') {
                    int i11 = i10 + 1;
                    if (spannableStringBuilder.charAt(i11) == '\n') {
                        spannableStringBuilder.delete(i10, i11);
                        length = i3;
                    }
                }
                i10++;
            }
            if (length > 0 && spannableStringBuilder.charAt(i3) == '\n') {
                spannableStringBuilder.delete(i3, length);
            }
            arrayList2.add(new C2207b(spannableStringBuilder, null, null, c2236c2.f5521c, c2236c2.f5522d, c2236c2.f5523e, c2236c2.f5520b, Integer.MIN_VALUE, c2236c2.f5526h, c2236c2.f5527i, c2236c2.f5524f, -3.4028235E38f, false, ViewCompat.MEASURED_STATE_MASK));
        }
        return arrayList2;
    }

    @Override // p005b.p199l.p200a.p201a.p236l1.InterfaceC2210e
    /* renamed from: d */
    public int mo2051d() {
        return this.f5542e.length;
    }
}
