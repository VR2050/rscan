package p005b.p199l.p200a.p201a.p236l1.p242r;

import android.text.SpannableStringBuilder;
import android.text.style.AbsoluteSizeSpan;
import android.text.style.AlignmentSpan;
import android.text.style.BackgroundColorSpan;
import android.text.style.ForegroundColorSpan;
import android.text.style.RelativeSizeSpan;
import android.text.style.StrikethroughSpan;
import android.text.style.StyleSpan;
import android.text.style.TypefaceSpan;
import android.text.style.UnderlineSpan;
import android.util.Pair;
import androidx.annotation.Nullable;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TreeSet;

/* renamed from: b.l.a.a.l1.r.b */
/* loaded from: classes.dex */
public final class C2235b {

    /* renamed from: a */
    @Nullable
    public final String f5507a;

    /* renamed from: b */
    @Nullable
    public final String f5508b;

    /* renamed from: c */
    public final boolean f5509c;

    /* renamed from: d */
    public final long f5510d;

    /* renamed from: e */
    public final long f5511e;

    /* renamed from: f */
    @Nullable
    public final C2237d f5512f;

    /* renamed from: g */
    @Nullable
    public final String[] f5513g;

    /* renamed from: h */
    public final String f5514h;

    /* renamed from: i */
    @Nullable
    public final String f5515i;

    /* renamed from: j */
    public final HashMap<String, Integer> f5516j;

    /* renamed from: k */
    public final HashMap<String, Integer> f5517k;

    /* renamed from: l */
    public List<C2235b> f5518l;

    public C2235b(@Nullable String str, @Nullable String str2, long j2, long j3, @Nullable C2237d c2237d, @Nullable String[] strArr, String str3, @Nullable String str4) {
        this.f5507a = str;
        this.f5508b = str2;
        this.f5515i = str4;
        this.f5512f = c2237d;
        this.f5513g = strArr;
        this.f5509c = str2 != null;
        this.f5510d = j2;
        this.f5511e = j3;
        Objects.requireNonNull(str3);
        this.f5514h = str3;
        this.f5516j = new HashMap<>();
        this.f5517k = new HashMap<>();
    }

    /* renamed from: b */
    public static C2235b m2109b(String str) {
        return new C2235b(null, str.replaceAll("\r\n", "\n").replaceAll(" *\n *", "\n").replaceAll("\n", " ").replaceAll("[ \t\\x0B\f\r]+", " "), -9223372036854775807L, -9223372036854775807L, null, null, "", null);
    }

    /* renamed from: f */
    public static SpannableStringBuilder m2110f(String str, Map<String, SpannableStringBuilder> map) {
        if (!map.containsKey(str)) {
            map.put(str, new SpannableStringBuilder());
        }
        return map.get(str);
    }

    /* renamed from: a */
    public void m2111a(C2235b c2235b) {
        if (this.f5518l == null) {
            this.f5518l = new ArrayList();
        }
        this.f5518l.add(c2235b);
    }

    /* renamed from: c */
    public C2235b m2112c(int i2) {
        List<C2235b> list = this.f5518l;
        if (list != null) {
            return list.get(i2);
        }
        throw new IndexOutOfBoundsException();
    }

    /* renamed from: d */
    public int m2113d() {
        List<C2235b> list = this.f5518l;
        if (list == null) {
            return 0;
        }
        return list.size();
    }

    /* renamed from: e */
    public final void m2114e(TreeSet<Long> treeSet, boolean z) {
        boolean equals = "p".equals(this.f5507a);
        boolean equals2 = "div".equals(this.f5507a);
        if (z || equals || (equals2 && this.f5515i != null)) {
            long j2 = this.f5510d;
            if (j2 != -9223372036854775807L) {
                treeSet.add(Long.valueOf(j2));
            }
            long j3 = this.f5511e;
            if (j3 != -9223372036854775807L) {
                treeSet.add(Long.valueOf(j3));
            }
        }
        if (this.f5518l == null) {
            return;
        }
        for (int i2 = 0; i2 < this.f5518l.size(); i2++) {
            this.f5518l.get(i2).m2114e(treeSet, z || equals);
        }
    }

    /* renamed from: g */
    public boolean m2115g(long j2) {
        long j3 = this.f5510d;
        return (j3 == -9223372036854775807L && this.f5511e == -9223372036854775807L) || (j3 <= j2 && this.f5511e == -9223372036854775807L) || ((j3 == -9223372036854775807L && j2 < this.f5511e) || (j3 <= j2 && j2 < this.f5511e));
    }

    /* renamed from: h */
    public final void m2116h(long j2, String str, List<Pair<String, String>> list) {
        if (!"".equals(this.f5514h)) {
            str = this.f5514h;
        }
        if (m2115g(j2) && "div".equals(this.f5507a) && this.f5515i != null) {
            list.add(new Pair<>(str, this.f5515i));
            return;
        }
        for (int i2 = 0; i2 < m2113d(); i2++) {
            m2112c(i2).m2116h(j2, str, list);
        }
    }

    /* renamed from: i */
    public final void m2117i(long j2, Map<String, C2237d> map, Map<String, SpannableStringBuilder> map2) {
        if (!m2115g(j2)) {
            return;
        }
        Iterator<Map.Entry<String, Integer>> it = this.f5517k.entrySet().iterator();
        while (true) {
            if (!it.hasNext()) {
                while (r2 < m2113d()) {
                    m2112c(r2).m2117i(j2, map, map2);
                    r2++;
                }
                return;
            }
            Map.Entry<String, Integer> next = it.next();
            String key = next.getKey();
            int intValue = this.f5516j.containsKey(key) ? this.f5516j.get(key).intValue() : 0;
            int intValue2 = next.getValue().intValue();
            if (intValue != intValue2) {
                SpannableStringBuilder spannableStringBuilder = map2.get(key);
                C2237d c2237d = this.f5512f;
                String[] strArr = this.f5513g;
                if (c2237d == null && strArr == null) {
                    c2237d = null;
                } else if (c2237d == null && strArr.length == 1) {
                    c2237d = map.get(strArr[0]);
                } else if (c2237d == null && strArr.length > 1) {
                    c2237d = new C2237d();
                    for (String str : strArr) {
                        c2237d.m2119a(map.get(str));
                    }
                } else if (c2237d != null && strArr != null && strArr.length == 1) {
                    c2237d.m2119a(map.get(strArr[0]));
                } else if (c2237d != null && strArr != null && strArr.length > 1) {
                    for (String str2 : strArr) {
                        c2237d.m2119a(map.get(str2));
                    }
                }
                if (c2237d == null) {
                    continue;
                } else {
                    if (c2237d.m2120b() != -1) {
                        spannableStringBuilder.setSpan(new StyleSpan(c2237d.m2120b()), intValue, intValue2, 33);
                    }
                    if (c2237d.f5533f == 1) {
                        spannableStringBuilder.setSpan(new StrikethroughSpan(), intValue, intValue2, 33);
                    }
                    if ((c2237d.f5534g == 1 ? 1 : 0) != 0) {
                        spannableStringBuilder.setSpan(new UnderlineSpan(), intValue, intValue2, 33);
                    }
                    if (c2237d.f5530c) {
                        if (!c2237d.f5530c) {
                            throw new IllegalStateException("Font color has not been defined.");
                        }
                        spannableStringBuilder.setSpan(new ForegroundColorSpan(c2237d.f5529b), intValue, intValue2, 33);
                    }
                    if (c2237d.f5532e) {
                        if (!c2237d.f5532e) {
                            throw new IllegalStateException("Background color has not been defined.");
                        }
                        spannableStringBuilder.setSpan(new BackgroundColorSpan(c2237d.f5531d), intValue, intValue2, 33);
                    }
                    if (c2237d.f5528a != null) {
                        spannableStringBuilder.setSpan(new TypefaceSpan(c2237d.f5528a), intValue, intValue2, 33);
                    }
                    if (c2237d.f5540m != null) {
                        spannableStringBuilder.setSpan(new AlignmentSpan.Standard(c2237d.f5540m), intValue, intValue2, 33);
                    }
                    int i2 = c2237d.f5537j;
                    if (i2 == 1) {
                        spannableStringBuilder.setSpan(new AbsoluteSizeSpan((int) c2237d.f5538k, true), intValue, intValue2, 33);
                    } else if (i2 == 2) {
                        spannableStringBuilder.setSpan(new RelativeSizeSpan(c2237d.f5538k), intValue, intValue2, 33);
                    } else if (i2 == 3) {
                        spannableStringBuilder.setSpan(new RelativeSizeSpan(c2237d.f5538k / 100.0f), intValue, intValue2, 33);
                    }
                }
            }
        }
    }

    /* renamed from: j */
    public final void m2118j(long j2, boolean z, String str, Map<String, SpannableStringBuilder> map) {
        this.f5516j.clear();
        this.f5517k.clear();
        if ("metadata".equals(this.f5507a)) {
            return;
        }
        if (!"".equals(this.f5514h)) {
            str = this.f5514h;
        }
        if (this.f5509c && z) {
            m2110f(str, map).append((CharSequence) this.f5508b);
            return;
        }
        if ("br".equals(this.f5507a) && z) {
            m2110f(str, map).append('\n');
            return;
        }
        if (m2115g(j2)) {
            for (Map.Entry<String, SpannableStringBuilder> entry : map.entrySet()) {
                this.f5516j.put(entry.getKey(), Integer.valueOf(entry.getValue().length()));
            }
            boolean equals = "p".equals(this.f5507a);
            for (int i2 = 0; i2 < m2113d(); i2++) {
                m2112c(i2).m2118j(j2, z || equals, str, map);
            }
            if (equals) {
                SpannableStringBuilder m2110f = m2110f(str, map);
                int length = m2110f.length();
                do {
                    length--;
                    if (length < 0) {
                        break;
                    }
                } while (m2110f.charAt(length) == ' ');
                if (length >= 0 && m2110f.charAt(length) != '\n') {
                    m2110f.append('\n');
                }
            }
            for (Map.Entry<String, SpannableStringBuilder> entry2 : map.entrySet()) {
                this.f5517k.put(entry2.getKey(), Integer.valueOf(entry2.getValue().length()));
            }
        }
    }
}
