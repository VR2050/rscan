package p005b.p199l.p200a.p201a.p236l1.p244t;

import android.text.SpannableStringBuilder;
import android.text.TextUtils;
import android.text.style.AbsoluteSizeSpan;
import android.text.style.BackgroundColorSpan;
import android.text.style.ForegroundColorSpan;
import android.text.style.RelativeSizeSpan;
import android.text.style.StrikethroughSpan;
import android.text.style.StyleSpan;
import android.text.style.TypefaceSpan;
import android.text.style.UnderlineSpan;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import p005b.p199l.p200a.p201a.p236l1.p244t.C2245e;
import p005b.p199l.p200a.p201a.p250p1.C2360t;

/* renamed from: b.l.a.a.l1.t.f */
/* loaded from: classes.dex */
public final class C2246f {

    /* renamed from: a */
    public static final Pattern f5587a = Pattern.compile("^(\\S+)\\s+-->\\s+(\\S+)(.*)?$");

    /* renamed from: b */
    public static final Pattern f5588b = Pattern.compile("(\\S+?):(\\S+)");

    /* renamed from: c */
    public final StringBuilder f5589c = new StringBuilder();

    /* renamed from: b.l.a.a.l1.t.f$a */
    public static final class a {

        /* renamed from: a */
        public static final String[] f5590a = new String[0];

        /* renamed from: b */
        public final String f5591b;

        /* renamed from: c */
        public final int f5592c;

        /* renamed from: d */
        public final String f5593d;

        /* renamed from: e */
        public final String[] f5594e;

        public a(String str, int i2, String str2, String[] strArr) {
            this.f5592c = i2;
            this.f5591b = str;
            this.f5593d = str2;
            this.f5594e = strArr;
        }
    }

    /* renamed from: b.l.a.a.l1.t.f$b */
    public static final class b implements Comparable<b> {

        /* renamed from: c */
        public final int f5595c;

        /* renamed from: e */
        public final C2244d f5596e;

        public b(int i2, C2244d c2244d) {
            this.f5595c = i2;
            this.f5596e = c2244d;
        }

        @Override // java.lang.Comparable
        public int compareTo(@NonNull b bVar) {
            return this.f5595c - bVar.f5595c;
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* renamed from: a */
    public static void m2130a(@Nullable String str, a aVar, SpannableStringBuilder spannableStringBuilder, List<C2244d> list, List<b> list2) {
        char c2;
        int i2;
        int i3;
        int size;
        int i4 = aVar.f5592c;
        int length = spannableStringBuilder.length();
        String str2 = aVar.f5591b;
        str2.hashCode();
        int hashCode = str2.hashCode();
        int i5 = 0;
        if (hashCode == 0) {
            if (str2.equals("")) {
                c2 = 0;
            }
            c2 = 65535;
        } else if (hashCode == 105) {
            if (str2.equals("i")) {
                c2 = 3;
            }
            c2 = 65535;
        } else if (hashCode == 3314158) {
            if (str2.equals("lang")) {
                c2 = 6;
            }
            c2 = 65535;
        } else if (hashCode == 98) {
            if (str2.equals("b")) {
                c2 = 1;
            }
            c2 = 65535;
        } else if (hashCode == 99) {
            if (str2.equals("c")) {
                c2 = 2;
            }
            c2 = 65535;
        } else if (hashCode != 117) {
            if (hashCode == 118 && str2.equals("v")) {
                c2 = 5;
            }
            c2 = 65535;
        } else {
            if (str2.equals("u")) {
                c2 = 4;
            }
            c2 = 65535;
        }
        switch (c2) {
            case 0:
            case 2:
            case 5:
            case 6:
                break;
            case 1:
                spannableStringBuilder.setSpan(new StyleSpan(1), i4, length, 33);
                break;
            case 3:
                spannableStringBuilder.setSpan(new StyleSpan(2), i4, length, 33);
                break;
            case 4:
                spannableStringBuilder.setSpan(new UnderlineSpan(), i4, length, 33);
                break;
            default:
                return;
        }
        list2.clear();
        int size2 = list.size();
        int i6 = 0;
        while (i6 < size2) {
            C2244d c2244d = list.get(i6);
            String str3 = aVar.f5591b;
            String[] strArr = aVar.f5594e;
            String str4 = aVar.f5593d;
            if (c2244d.f5561a.isEmpty() && c2244d.f5562b.isEmpty() && c2244d.f5563c.isEmpty() && c2244d.f5564d.isEmpty()) {
                size = TextUtils.isEmpty(str3);
            } else {
                int m2126b = C2244d.m2126b(C2244d.m2126b(C2244d.m2126b(i5, c2244d.f5561a, str, 1073741824), c2244d.f5562b, str3, 2), c2244d.f5564d, str4, 4);
                size = (m2126b == -1 || !Arrays.asList(strArr).containsAll(c2244d.f5563c)) ? 0 : m2126b + (c2244d.f5563c.size() * 4);
            }
            if (size > 0) {
                list2.add(new b(size, c2244d));
            }
            i6++;
            i5 = 0;
        }
        Collections.sort(list2);
        int size3 = list2.size();
        for (int i7 = 0; i7 < size3; i7++) {
            C2244d c2244d2 = list2.get(i7).f5596e;
            if (c2244d2 != null) {
                if (c2244d2.m2127a() != -1) {
                    i2 = 33;
                    spannableStringBuilder.setSpan(new StyleSpan(c2244d2.m2127a()), i4, length, 33);
                } else {
                    i2 = 33;
                }
                if (c2244d2.f5570j == 1) {
                    spannableStringBuilder.setSpan(new StrikethroughSpan(), i4, length, i2);
                }
                if (c2244d2.f5571k == 1) {
                    spannableStringBuilder.setSpan(new UnderlineSpan(), i4, length, i2);
                }
                if (c2244d2.f5567g) {
                    if (!c2244d2.f5567g) {
                        throw new IllegalStateException("Font color not defined");
                    }
                    spannableStringBuilder.setSpan(new ForegroundColorSpan(c2244d2.f5566f), i4, length, i2);
                }
                if (c2244d2.f5569i) {
                    if (!c2244d2.f5569i) {
                        throw new IllegalStateException("Background color not defined.");
                    }
                    spannableStringBuilder.setSpan(new BackgroundColorSpan(c2244d2.f5568h), i4, length, 33);
                }
                if (c2244d2.f5565e != null) {
                    i3 = 33;
                    spannableStringBuilder.setSpan(new TypefaceSpan(c2244d2.f5565e), i4, length, 33);
                } else {
                    i3 = 33;
                }
                int i8 = c2244d2.f5574n;
                if (i8 == 1) {
                    spannableStringBuilder.setSpan(new AbsoluteSizeSpan((int) 0.0f, true), i4, length, i3);
                } else if (i8 == 2) {
                    spannableStringBuilder.setSpan(new RelativeSizeSpan(0.0f), i4, length, i3);
                } else if (i8 == 3) {
                    spannableStringBuilder.setSpan(new RelativeSizeSpan(0.0f), i4, length, i3);
                }
            }
        }
    }

    /* renamed from: b */
    public static boolean m2131b(@Nullable String str, Matcher matcher, C2360t c2360t, C2245e.b bVar, StringBuilder sb, List<C2244d> list) {
        try {
            bVar.f5577a = C2248h.m2137c(matcher.group(1));
            bVar.f5578b = C2248h.m2137c(matcher.group(2));
            m2132c(matcher.group(3), bVar);
            sb.setLength(0);
            String m2574f = c2360t.m2574f();
            while (!TextUtils.isEmpty(m2574f)) {
                if (sb.length() > 0) {
                    sb.append("\n");
                }
                sb.append(m2574f.trim());
                m2574f = c2360t.m2574f();
            }
            m2133d(str, sb.toString(), bVar, list);
            return true;
        } catch (NumberFormatException unused) {
            matcher.group();
            return false;
        }
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Code restructure failed: missing block: B:54:0x0092, code lost:
    
        if (r3.equals("end") == false) goto L38;
     */
    /* renamed from: c */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static void m2132c(java.lang.String r8, p005b.p199l.p200a.p201a.p236l1.p244t.C2245e.b r9) {
        /*
            java.util.regex.Pattern r0 = p005b.p199l.p200a.p201a.p236l1.p244t.C2246f.f5588b
            java.util.regex.Matcher r8 = r0.matcher(r8)
        L6:
            boolean r0 = r8.find()
            if (r0 == 0) goto Le3
            r0 = 1
            java.lang.String r1 = r8.group(r0)
            r2 = 2
            java.lang.String r3 = r8.group(r2)
            java.lang.String r4 = "line"
            boolean r4 = r4.equals(r1)     // Catch: java.lang.NumberFormatException -> Lde
            r5 = 44
            r6 = 0
            r7 = -1
            if (r4 == 0) goto L57
            int r1 = r3.indexOf(r5)     // Catch: java.lang.NumberFormatException -> Lde
            if (r1 == r7) goto L38
            int r2 = r1 + 1
            java.lang.String r2 = r3.substring(r2)     // Catch: java.lang.NumberFormatException -> Lde
            int r2 = m2134e(r2)     // Catch: java.lang.NumberFormatException -> Lde
            r9.f5583g = r2     // Catch: java.lang.NumberFormatException -> Lde
            java.lang.String r3 = r3.substring(r6, r1)     // Catch: java.lang.NumberFormatException -> Lde
        L38:
            java.lang.String r1 = "%"
            boolean r1 = r3.endsWith(r1)     // Catch: java.lang.NumberFormatException -> Lde
            if (r1 == 0) goto L49
            float r0 = p005b.p199l.p200a.p201a.p236l1.p244t.C2248h.m2136b(r3)     // Catch: java.lang.NumberFormatException -> Lde
            r9.f5581e = r0     // Catch: java.lang.NumberFormatException -> Lde
            r9.f5582f = r6     // Catch: java.lang.NumberFormatException -> Lde
            goto L6
        L49:
            int r1 = java.lang.Integer.parseInt(r3)     // Catch: java.lang.NumberFormatException -> Lde
            if (r1 >= 0) goto L51
            int r1 = r1 + (-1)
        L51:
            float r1 = (float) r1     // Catch: java.lang.NumberFormatException -> Lde
            r9.f5581e = r1     // Catch: java.lang.NumberFormatException -> Lde
            r9.f5582f = r0     // Catch: java.lang.NumberFormatException -> Lde
            goto L6
        L57:
            java.lang.String r4 = "align"
            boolean r4 = r4.equals(r1)     // Catch: java.lang.NumberFormatException -> Lde
            if (r4 == 0) goto La8
            r3.hashCode()     // Catch: java.lang.NumberFormatException -> Lde
            int r1 = r3.hashCode()
            r4 = 3
            switch(r1) {
                case 100571: goto L8c;
                case 3317767: goto L81;
                case 108511772: goto L76;
                case 109757538: goto L6b;
                default: goto L6a;
            }
        L6a:
            goto L94
        L6b:
            java.lang.String r1 = "start"
            boolean r1 = r3.equals(r1)
            if (r1 != 0) goto L74
            goto L94
        L74:
            r6 = 3
            goto L95
        L76:
            java.lang.String r1 = "right"
            boolean r1 = r3.equals(r1)
            if (r1 != 0) goto L7f
            goto L94
        L7f:
            r6 = 2
            goto L95
        L81:
            java.lang.String r1 = "left"
            boolean r1 = r3.equals(r1)
            if (r1 != 0) goto L8a
            goto L94
        L8a:
            r6 = 1
            goto L95
        L8c:
            java.lang.String r1 = "end"
            boolean r1 = r3.equals(r1)
            if (r1 != 0) goto L95
        L94:
            r6 = -1
        L95:
            if (r6 == 0) goto La3
            if (r6 == r0) goto La1
            if (r6 == r2) goto L9f
            if (r6 == r4) goto La4
            r0 = 2
            goto La4
        L9f:
            r0 = 5
            goto La4
        La1:
            r0 = 4
            goto La4
        La3:
            r0 = 3
        La4:
            r9.f5580d = r0     // Catch: java.lang.NumberFormatException -> Lde
            goto L6
        La8:
            java.lang.String r0 = "position"
            boolean r0 = r0.equals(r1)     // Catch: java.lang.NumberFormatException -> Lde
            if (r0 == 0) goto Lce
            int r0 = r3.indexOf(r5)     // Catch: java.lang.NumberFormatException -> Lde
            if (r0 == r7) goto Lc6
            int r1 = r0 + 1
            java.lang.String r1 = r3.substring(r1)     // Catch: java.lang.NumberFormatException -> Lde
            int r1 = m2134e(r1)     // Catch: java.lang.NumberFormatException -> Lde
            r9.f5585i = r1     // Catch: java.lang.NumberFormatException -> Lde
            java.lang.String r3 = r3.substring(r6, r0)     // Catch: java.lang.NumberFormatException -> Lde
        Lc6:
            float r0 = p005b.p199l.p200a.p201a.p236l1.p244t.C2248h.m2136b(r3)     // Catch: java.lang.NumberFormatException -> Lde
            r9.f5584h = r0     // Catch: java.lang.NumberFormatException -> Lde
            goto L6
        Lce:
            java.lang.String r0 = "size"
            boolean r0 = r0.equals(r1)     // Catch: java.lang.NumberFormatException -> Lde
            if (r0 == 0) goto L6
            float r0 = p005b.p199l.p200a.p201a.p236l1.p244t.C2248h.m2136b(r3)     // Catch: java.lang.NumberFormatException -> Lde
            r9.f5586j = r0     // Catch: java.lang.NumberFormatException -> Lde
            goto L6
        Lde:
            r8.group()
            goto L6
        Le3:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p200a.p201a.p236l1.p244t.C2246f.m2132c(java.lang.String, b.l.a.a.l1.t.e$b):void");
    }

    /* JADX WARN: Removed duplicated region for block: B:80:0x00fb  */
    /* JADX WARN: Removed duplicated region for block: B:91:0x0110  */
    /* renamed from: d */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static void m2133d(@androidx.annotation.Nullable java.lang.String r16, java.lang.String r17, p005b.p199l.p200a.p201a.p236l1.p244t.C2245e.b r18, java.util.List<p005b.p199l.p200a.p201a.p236l1.p244t.C2244d> r19) {
        /*
            Method dump skipped, instructions count: 558
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p200a.p201a.p236l1.p244t.C2246f.m2133d(java.lang.String, java.lang.String, b.l.a.a.l1.t.e$b, java.util.List):void");
    }

    /* renamed from: e */
    public static int m2134e(String str) {
        str.hashCode();
        switch (str) {
            case "center":
            case "middle":
                return 1;
            case "end":
                return 2;
            case "start":
                return 0;
            default:
                return Integer.MIN_VALUE;
        }
    }
}
