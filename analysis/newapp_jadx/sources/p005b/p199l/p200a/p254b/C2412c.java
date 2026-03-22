package p005b.p199l.p200a.p254b;

import android.util.SparseIntArray;
import android.view.View;
import android.view.ViewGroup;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.core.view.MarginLayoutParamsCompat;
import com.google.android.flexbox.FlexItem;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import p005b.p131d.p132a.p133a.C1499a;

/* renamed from: b.l.a.b.c */
/* loaded from: classes.dex */
public class C2412c {

    /* renamed from: a */
    public final InterfaceC2410a f6436a;

    /* renamed from: b */
    public boolean[] f6437b;

    /* renamed from: c */
    @Nullable
    public int[] f6438c;

    /* renamed from: d */
    @Nullable
    public long[] f6439d;

    /* renamed from: e */
    @Nullable
    public long[] f6440e;

    /* renamed from: b.l.a.b.c$b */
    public static class b {

        /* renamed from: a */
        public List<C2411b> f6441a;

        /* renamed from: b */
        public int f6442b;

        /* renamed from: a */
        public void m2750a() {
            this.f6441a = null;
            this.f6442b = 0;
        }
    }

    /* renamed from: b.l.a.b.c$c */
    public static class c implements Comparable<c> {

        /* renamed from: c */
        public int f6443c;

        /* renamed from: e */
        public int f6444e;

        public c() {
        }

        @Override // java.lang.Comparable
        public int compareTo(@NonNull c cVar) {
            c cVar2 = cVar;
            int i2 = this.f6444e;
            int i3 = cVar2.f6444e;
            return i2 != i3 ? i2 - i3 : this.f6443c - cVar2.f6443c;
        }

        @NonNull
        public String toString() {
            StringBuilder m586H = C1499a.m586H("Order{order=");
            m586H.append(this.f6444e);
            m586H.append(", index=");
            return C1499a.m579A(m586H, this.f6443c, '}');
        }

        public c(a aVar) {
        }
    }

    public C2412c(InterfaceC2410a interfaceC2410a) {
        this.f6436a = interfaceC2410a;
    }

    /* renamed from: A */
    public void m2722A(int i2) {
        View mo2712c;
        if (i2 >= this.f6436a.getFlexItemCount()) {
            return;
        }
        int flexDirection = this.f6436a.getFlexDirection();
        if (this.f6436a.getAlignItems() != 4) {
            for (C2411b c2411b : this.f6436a.getFlexLinesInternal()) {
                for (Integer num : c2411b.f6431n) {
                    View mo2712c2 = this.f6436a.mo2712c(num.intValue());
                    if (flexDirection == 0 || flexDirection == 1) {
                        m2749z(mo2712c2, c2411b.f6424g, num.intValue());
                    } else {
                        if (flexDirection != 2 && flexDirection != 3) {
                            throw new IllegalArgumentException(C1499a.m626l("Invalid flex direction: ", flexDirection));
                        }
                        m2748y(mo2712c2, c2411b.f6424g, num.intValue());
                    }
                }
            }
            return;
        }
        int[] iArr = this.f6438c;
        List<C2411b> flexLinesInternal = this.f6436a.getFlexLinesInternal();
        int size = flexLinesInternal.size();
        for (int i3 = iArr != null ? iArr[i2] : 0; i3 < size; i3++) {
            C2411b c2411b2 = flexLinesInternal.get(i3);
            int i4 = c2411b2.f6425h;
            for (int i5 = 0; i5 < i4; i5++) {
                int i6 = c2411b2.f6432o + i5;
                if (i5 < this.f6436a.getFlexItemCount() && (mo2712c = this.f6436a.mo2712c(i6)) != null && mo2712c.getVisibility() != 8) {
                    FlexItem flexItem = (FlexItem) mo2712c.getLayoutParams();
                    if (flexItem.mo4134a() == -1 || flexItem.mo4134a() == 4) {
                        if (flexDirection == 0 || flexDirection == 1) {
                            m2749z(mo2712c, c2411b2.f6424g, i6);
                        } else {
                            if (flexDirection != 2 && flexDirection != 3) {
                                throw new IllegalArgumentException(C1499a.m626l("Invalid flex direction: ", flexDirection));
                            }
                            m2748y(mo2712c, c2411b2.f6424g, i6);
                        }
                    }
                }
            }
        }
    }

    /* renamed from: B */
    public final void m2723B(int i2, int i3, int i4, View view) {
        long[] jArr = this.f6439d;
        if (jArr != null) {
            jArr[i2] = (i3 & 4294967295L) | (i4 << 32);
        }
        long[] jArr2 = this.f6440e;
        if (jArr2 != null) {
            jArr2[i2] = (view.getMeasuredWidth() & 4294967295L) | (view.getMeasuredHeight() << 32);
        }
    }

    /* renamed from: a */
    public final void m2724a(List<C2411b> list, C2411b c2411b, int i2, int i3) {
        c2411b.f6430m = i3;
        this.f6436a.mo2711b(c2411b);
        c2411b.f6433p = i2;
        list.add(c2411b);
    }

    /* JADX WARN: Code restructure failed: missing block: B:140:0x022c, code lost:
    
        if (r2 < (r8 + r11)) goto L88;
     */
    /* JADX WARN: Removed duplicated region for block: B:102:0x039f  */
    /* JADX WARN: Removed duplicated region for block: B:110:0x03c5 A[ADDED_TO_REGION] */
    /* JADX WARN: Removed duplicated region for block: B:119:0x0334  */
    /* JADX WARN: Removed duplicated region for block: B:120:0x0300  */
    /* JADX WARN: Removed duplicated region for block: B:121:0x02e7  */
    /* JADX WARN: Removed duplicated region for block: B:122:0x02d4  */
    /* JADX WARN: Removed duplicated region for block: B:128:0x02b9  */
    /* JADX WARN: Removed duplicated region for block: B:66:0x0233  */
    /* JADX WARN: Removed duplicated region for block: B:78:0x02d1  */
    /* JADX WARN: Removed duplicated region for block: B:81:0x02e4  */
    /* JADX WARN: Removed duplicated region for block: B:84:0x02f1  */
    /* JADX WARN: Removed duplicated region for block: B:87:0x02fb  */
    /* JADX WARN: Removed duplicated region for block: B:90:0x032f  */
    /* JADX WARN: Removed duplicated region for block: B:93:0x035b  */
    /* JADX WARN: Removed duplicated region for block: B:99:0x0394  */
    /* renamed from: b */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void m2725b(p005b.p199l.p200a.p254b.C2412c.b r24, int r25, int r26, int r27, int r28, int r29, @androidx.annotation.Nullable java.util.List<p005b.p199l.p200a.p254b.C2411b> r30) {
        /*
            Method dump skipped, instructions count: 999
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p200a.p254b.C2412c.m2725b(b.l.a.b.c$b, int, int, int, int, int, java.util.List):void");
    }

    /* JADX WARN: Removed duplicated region for block: B:12:? A[RETURN, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:13:0x0032  */
    /* JADX WARN: Removed duplicated region for block: B:7:0x002d  */
    /* JADX WARN: Removed duplicated region for block: B:9:0x0040  */
    /* renamed from: c */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void m2726c(android.view.View r7, int r8) {
        /*
            r6 = this;
            android.view.ViewGroup$LayoutParams r0 = r7.getLayoutParams()
            com.google.android.flexbox.FlexItem r0 = (com.google.android.flexbox.FlexItem) r0
            int r1 = r7.getMeasuredWidth()
            int r2 = r7.getMeasuredHeight()
            int r3 = r0.mo4136f()
            r4 = 1
            if (r1 >= r3) goto L1a
            int r1 = r0.mo4136f()
            goto L24
        L1a:
            int r3 = r0.mo4148v()
            if (r1 <= r3) goto L26
            int r1 = r0.mo4148v()
        L24:
            r3 = 1
            goto L27
        L26:
            r3 = 0
        L27:
            int r5 = r0.mo4145r()
            if (r2 >= r5) goto L32
            int r2 = r0.mo4145r()
            goto L3e
        L32:
            int r5 = r0.mo4147t()
            if (r2 <= r5) goto L3d
            int r2 = r0.mo4147t()
            goto L3e
        L3d:
            r4 = r3
        L3e:
            if (r4 == 0) goto L55
            r0 = 1073741824(0x40000000, float:2.0)
            int r1 = android.view.View.MeasureSpec.makeMeasureSpec(r1, r0)
            int r0 = android.view.View.MeasureSpec.makeMeasureSpec(r2, r0)
            r7.measure(r1, r0)
            r6.m2723B(r8, r1, r0, r7)
            b.l.a.b.a r0 = r6.f6436a
            r0.mo2714e(r8, r7)
        L55:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p200a.p254b.C2412c.m2726c(android.view.View, int):void");
    }

    /* renamed from: d */
    public void m2727d(List<C2411b> list, int i2) {
        int i3 = this.f6438c[i2];
        if (i3 == -1) {
            i3 = 0;
        }
        for (int size = list.size() - 1; size >= i3; size--) {
            list.remove(size);
        }
        int[] iArr = this.f6438c;
        int length = iArr.length - 1;
        if (i2 > length) {
            Arrays.fill(iArr, -1);
        } else {
            Arrays.fill(iArr, i2, length, -1);
        }
        long[] jArr = this.f6439d;
        int length2 = jArr.length - 1;
        if (i2 > length2) {
            Arrays.fill(jArr, 0L);
        } else {
            Arrays.fill(jArr, i2, length2, 0L);
        }
    }

    /* renamed from: e */
    public final List<C2411b> m2728e(List<C2411b> list, int i2, int i3) {
        int i4 = (i2 - i3) / 2;
        ArrayList arrayList = new ArrayList();
        C2411b c2411b = new C2411b();
        c2411b.f6424g = i4;
        int size = list.size();
        for (int i5 = 0; i5 < size; i5++) {
            if (i5 == 0) {
                arrayList.add(c2411b);
            }
            arrayList.add(list.get(i5));
            if (i5 == list.size() - 1) {
                arrayList.add(c2411b);
            }
        }
        return arrayList;
    }

    @NonNull
    /* renamed from: f */
    public final List<c> m2729f(int i2) {
        ArrayList arrayList = new ArrayList(i2);
        for (int i3 = 0; i3 < i2; i3++) {
            FlexItem flexItem = (FlexItem) this.f6436a.mo2715f(i3).getLayoutParams();
            c cVar = new c(null);
            cVar.f6444e = flexItem.getOrder();
            cVar.f6443c = i3;
            arrayList.add(cVar);
        }
        return arrayList;
    }

    /* renamed from: g */
    public void m2730g(int i2, int i3, int i4) {
        int i5;
        int i6;
        int flexDirection = this.f6436a.getFlexDirection();
        if (flexDirection == 0 || flexDirection == 1) {
            int mode = View.MeasureSpec.getMode(i3);
            int size = View.MeasureSpec.getSize(i3);
            i5 = mode;
            i6 = size;
        } else {
            if (flexDirection != 2 && flexDirection != 3) {
                throw new IllegalArgumentException(C1499a.m626l("Invalid flex direction: ", flexDirection));
            }
            i5 = View.MeasureSpec.getMode(i2);
            i6 = View.MeasureSpec.getSize(i2);
        }
        List<C2411b> flexLinesInternal = this.f6436a.getFlexLinesInternal();
        if (i5 == 1073741824) {
            int sumOfCrossSize = this.f6436a.getSumOfCrossSize() + i4;
            int i7 = 0;
            if (flexLinesInternal.size() == 1) {
                flexLinesInternal.get(0).f6424g = i6 - i4;
                return;
            }
            if (flexLinesInternal.size() >= 2) {
                int alignContent = this.f6436a.getAlignContent();
                if (alignContent == 1) {
                    int i8 = i6 - sumOfCrossSize;
                    C2411b c2411b = new C2411b();
                    c2411b.f6424g = i8;
                    flexLinesInternal.add(0, c2411b);
                    return;
                }
                if (alignContent == 2) {
                    this.f6436a.setFlexLines(m2728e(flexLinesInternal, i6, sumOfCrossSize));
                    return;
                }
                if (alignContent == 3) {
                    if (sumOfCrossSize >= i6) {
                        return;
                    }
                    float size2 = (i6 - sumOfCrossSize) / (flexLinesInternal.size() - 1);
                    ArrayList arrayList = new ArrayList();
                    int size3 = flexLinesInternal.size();
                    float f2 = 0.0f;
                    while (i7 < size3) {
                        arrayList.add(flexLinesInternal.get(i7));
                        if (i7 != flexLinesInternal.size() - 1) {
                            C2411b c2411b2 = new C2411b();
                            if (i7 == flexLinesInternal.size() - 2) {
                                c2411b2.f6424g = Math.round(f2 + size2);
                                f2 = 0.0f;
                            } else {
                                c2411b2.f6424g = Math.round(size2);
                            }
                            int i9 = c2411b2.f6424g;
                            float f3 = (size2 - i9) + f2;
                            if (f3 > 1.0f) {
                                c2411b2.f6424g = i9 + 1;
                                f3 -= 1.0f;
                            } else if (f3 < -1.0f) {
                                c2411b2.f6424g = i9 - 1;
                                f3 += 1.0f;
                            }
                            arrayList.add(c2411b2);
                            f2 = f3;
                        }
                        i7++;
                    }
                    this.f6436a.setFlexLines(arrayList);
                    return;
                }
                if (alignContent == 4) {
                    if (sumOfCrossSize >= i6) {
                        this.f6436a.setFlexLines(m2728e(flexLinesInternal, i6, sumOfCrossSize));
                        return;
                    }
                    int size4 = (i6 - sumOfCrossSize) / (flexLinesInternal.size() * 2);
                    ArrayList arrayList2 = new ArrayList();
                    C2411b c2411b3 = new C2411b();
                    c2411b3.f6424g = size4;
                    for (C2411b c2411b4 : flexLinesInternal) {
                        arrayList2.add(c2411b3);
                        arrayList2.add(c2411b4);
                        arrayList2.add(c2411b3);
                    }
                    this.f6436a.setFlexLines(arrayList2);
                    return;
                }
                if (alignContent == 5 && sumOfCrossSize < i6) {
                    float size5 = (i6 - sumOfCrossSize) / flexLinesInternal.size();
                    int size6 = flexLinesInternal.size();
                    float f4 = 0.0f;
                    while (i7 < size6) {
                        C2411b c2411b5 = flexLinesInternal.get(i7);
                        float f5 = c2411b5.f6424g + size5;
                        if (i7 == flexLinesInternal.size() - 1) {
                            f5 += f4;
                            f4 = 0.0f;
                        }
                        int round = Math.round(f5);
                        float f6 = (f5 - round) + f4;
                        if (f6 > 1.0f) {
                            round++;
                            f6 -= 1.0f;
                        } else if (f6 < -1.0f) {
                            round--;
                            f6 += 1.0f;
                        }
                        f4 = f6;
                        c2411b5.f6424g = round;
                        i7++;
                    }
                }
            }
        }
    }

    /* renamed from: h */
    public void m2731h(int i2, int i3, int i4) {
        int size;
        int paddingLeft;
        int paddingRight;
        int flexItemCount = this.f6436a.getFlexItemCount();
        boolean[] zArr = this.f6437b;
        if (zArr == null) {
            if (flexItemCount < 10) {
                flexItemCount = 10;
            }
            this.f6437b = new boolean[flexItemCount];
        } else if (zArr.length < flexItemCount) {
            int length = zArr.length * 2;
            if (length >= flexItemCount) {
                flexItemCount = length;
            }
            this.f6437b = new boolean[flexItemCount];
        } else {
            Arrays.fill(zArr, false);
        }
        if (i4 >= this.f6436a.getFlexItemCount()) {
            return;
        }
        int flexDirection = this.f6436a.getFlexDirection();
        int flexDirection2 = this.f6436a.getFlexDirection();
        if (flexDirection2 == 0 || flexDirection2 == 1) {
            int mode = View.MeasureSpec.getMode(i2);
            size = View.MeasureSpec.getSize(i2);
            int largestMainSize = this.f6436a.getLargestMainSize();
            if (mode != 1073741824 && largestMainSize <= size) {
                size = largestMainSize;
            }
            paddingLeft = this.f6436a.getPaddingLeft();
            paddingRight = this.f6436a.getPaddingRight();
        } else {
            if (flexDirection2 != 2 && flexDirection2 != 3) {
                throw new IllegalArgumentException(C1499a.m626l("Invalid flex direction: ", flexDirection));
            }
            int mode2 = View.MeasureSpec.getMode(i3);
            size = View.MeasureSpec.getSize(i3);
            if (mode2 != 1073741824) {
                size = this.f6436a.getLargestMainSize();
            }
            paddingLeft = this.f6436a.getPaddingTop();
            paddingRight = this.f6436a.getPaddingBottom();
        }
        int i5 = paddingRight + paddingLeft;
        int[] iArr = this.f6438c;
        List<C2411b> flexLinesInternal = this.f6436a.getFlexLinesInternal();
        int size2 = flexLinesInternal.size();
        for (int i6 = iArr != null ? iArr[i4] : 0; i6 < size2; i6++) {
            C2411b c2411b = flexLinesInternal.get(i6);
            int i7 = c2411b.f6422e;
            if (i7 < size && c2411b.f6434q) {
                m2735l(i2, i3, c2411b, size, i5, false);
            } else if (i7 > size && c2411b.f6435r) {
                m2746w(i2, i3, c2411b, size, i5, false);
            }
        }
    }

    /* renamed from: i */
    public void m2732i(int i2) {
        int[] iArr = this.f6438c;
        if (iArr == null) {
            if (i2 < 10) {
                i2 = 10;
            }
            this.f6438c = new int[i2];
        } else if (iArr.length < i2) {
            int length = iArr.length * 2;
            if (length >= i2) {
                i2 = length;
            }
            this.f6438c = Arrays.copyOf(iArr, i2);
        }
    }

    /* renamed from: j */
    public void m2733j(int i2) {
        long[] jArr = this.f6439d;
        if (jArr == null) {
            if (i2 < 10) {
                i2 = 10;
            }
            this.f6439d = new long[i2];
        } else if (jArr.length < i2) {
            int length = jArr.length * 2;
            if (length >= i2) {
                i2 = length;
            }
            this.f6439d = Arrays.copyOf(jArr, i2);
        }
    }

    /* renamed from: k */
    public void m2734k(int i2) {
        long[] jArr = this.f6440e;
        if (jArr == null) {
            if (i2 < 10) {
                i2 = 10;
            }
            this.f6440e = new long[i2];
        } else if (jArr.length < i2) {
            int length = jArr.length * 2;
            if (length >= i2) {
                i2 = length;
            }
            this.f6440e = Arrays.copyOf(jArr, i2);
        }
    }

    /* renamed from: l */
    public final void m2735l(int i2, int i3, C2411b c2411b, int i4, int i5, boolean z) {
        int i6;
        int i7;
        int i8;
        double d2;
        int i9;
        double d3;
        float f2 = c2411b.f6427j;
        float f3 = 0.0f;
        if (f2 <= 0.0f || i4 < (i6 = c2411b.f6422e)) {
            return;
        }
        float f4 = (i4 - i6) / f2;
        c2411b.f6422e = i5 + c2411b.f6423f;
        if (!z) {
            c2411b.f6424g = Integer.MIN_VALUE;
        }
        int i10 = 0;
        boolean z2 = false;
        int i11 = 0;
        float f5 = 0.0f;
        while (i10 < c2411b.f6425h) {
            int i12 = c2411b.f6432o + i10;
            View mo2712c = this.f6436a.mo2712c(i12);
            if (mo2712c == null || mo2712c.getVisibility() == 8) {
                i7 = i6;
            } else {
                FlexItem flexItem = (FlexItem) mo2712c.getLayoutParams();
                int flexDirection = this.f6436a.getFlexDirection();
                if (flexDirection == 0 || flexDirection == 1) {
                    int i13 = i6;
                    int measuredWidth = mo2712c.getMeasuredWidth();
                    long[] jArr = this.f6440e;
                    if (jArr != null) {
                        measuredWidth = (int) jArr[i12];
                    }
                    int measuredHeight = mo2712c.getMeasuredHeight();
                    long[] jArr2 = this.f6440e;
                    i7 = i13;
                    if (jArr2 != null) {
                        measuredHeight = m2736m(jArr2[i12]);
                    }
                    if (!this.f6437b[i12] && flexItem.mo4142m() > 0.0f) {
                        float mo4142m = (flexItem.mo4142m() * f4) + measuredWidth;
                        if (i10 == c2411b.f6425h - 1) {
                            mo4142m += f5;
                            f5 = 0.0f;
                        }
                        int round = Math.round(mo4142m);
                        if (round > flexItem.mo4148v()) {
                            round = flexItem.mo4148v();
                            this.f6437b[i12] = true;
                            c2411b.f6427j -= flexItem.mo4142m();
                            z2 = true;
                        } else {
                            float f6 = (mo4142m - round) + f5;
                            double d4 = f6;
                            if (d4 > 1.0d) {
                                round++;
                                d2 = d4 - 1.0d;
                            } else {
                                if (d4 < -1.0d) {
                                    round--;
                                    d2 = d4 + 1.0d;
                                }
                                f5 = f6;
                            }
                            f6 = (float) d2;
                            f5 = f6;
                        }
                        int m2737n = m2737n(i3, flexItem, c2411b.f6430m);
                        int makeMeasureSpec = View.MeasureSpec.makeMeasureSpec(round, 1073741824);
                        mo2712c.measure(makeMeasureSpec, m2737n);
                        int measuredWidth2 = mo2712c.getMeasuredWidth();
                        int measuredHeight2 = mo2712c.getMeasuredHeight();
                        m2723B(i12, makeMeasureSpec, m2737n, mo2712c);
                        this.f6436a.mo2714e(i12, mo2712c);
                        measuredWidth = measuredWidth2;
                        measuredHeight = measuredHeight2;
                    }
                    int max = Math.max(i11, this.f6436a.mo2719j(mo2712c) + flexItem.mo4138h() + flexItem.mo4140j() + measuredHeight);
                    c2411b.f6422e = flexItem.mo4144p() + flexItem.mo4139i() + measuredWidth + c2411b.f6422e;
                    i8 = max;
                } else {
                    int measuredHeight3 = mo2712c.getMeasuredHeight();
                    long[] jArr3 = this.f6440e;
                    if (jArr3 != null) {
                        measuredHeight3 = m2736m(jArr3[i12]);
                    }
                    int measuredWidth3 = mo2712c.getMeasuredWidth();
                    long[] jArr4 = this.f6440e;
                    if (jArr4 != null) {
                        measuredWidth3 = (int) jArr4[i12];
                    }
                    if (this.f6437b[i12] || flexItem.mo4142m() <= f3) {
                        i9 = i6;
                    } else {
                        float mo4142m2 = (flexItem.mo4142m() * f4) + measuredHeight3;
                        if (i10 == c2411b.f6425h - 1) {
                            mo4142m2 += f5;
                            f5 = 0.0f;
                        }
                        int round2 = Math.round(mo4142m2);
                        if (round2 > flexItem.mo4147t()) {
                            round2 = flexItem.mo4147t();
                            this.f6437b[i12] = true;
                            c2411b.f6427j -= flexItem.mo4142m();
                            i9 = i6;
                            z2 = true;
                        } else {
                            float f7 = (mo4142m2 - round2) + f5;
                            i9 = i6;
                            double d5 = f7;
                            if (d5 > 1.0d) {
                                round2++;
                                d3 = d5 - 1.0d;
                            } else if (d5 < -1.0d) {
                                round2--;
                                d3 = d5 + 1.0d;
                            } else {
                                f5 = f7;
                            }
                            f5 = (float) d3;
                        }
                        int m2738o = m2738o(i2, flexItem, c2411b.f6430m);
                        int makeMeasureSpec2 = View.MeasureSpec.makeMeasureSpec(round2, 1073741824);
                        mo2712c.measure(m2738o, makeMeasureSpec2);
                        measuredWidth3 = mo2712c.getMeasuredWidth();
                        int measuredHeight4 = mo2712c.getMeasuredHeight();
                        m2723B(i12, m2738o, makeMeasureSpec2, mo2712c);
                        this.f6436a.mo2714e(i12, mo2712c);
                        measuredHeight3 = measuredHeight4;
                    }
                    i8 = Math.max(i11, this.f6436a.mo2719j(mo2712c) + flexItem.mo4144p() + flexItem.mo4139i() + measuredWidth3);
                    c2411b.f6422e = flexItem.mo4138h() + flexItem.mo4140j() + measuredHeight3 + c2411b.f6422e;
                    i7 = i9;
                }
                c2411b.f6424g = Math.max(c2411b.f6424g, i8);
                i11 = i8;
            }
            i10++;
            i6 = i7;
            f3 = 0.0f;
        }
        int i14 = i6;
        if (!z2 || i14 == c2411b.f6422e) {
            return;
        }
        m2735l(i2, i3, c2411b, i4, i5, true);
    }

    /* renamed from: m */
    public int m2736m(long j2) {
        return (int) (j2 >> 32);
    }

    /* renamed from: n */
    public final int m2737n(int i2, FlexItem flexItem, int i3) {
        InterfaceC2410a interfaceC2410a = this.f6436a;
        int mo2717h = interfaceC2410a.mo2717h(i2, flexItem.mo4138h() + flexItem.mo4140j() + this.f6436a.getPaddingBottom() + interfaceC2410a.getPaddingTop() + i3, flexItem.getHeight());
        int size = View.MeasureSpec.getSize(mo2717h);
        return size > flexItem.mo4147t() ? View.MeasureSpec.makeMeasureSpec(flexItem.mo4147t(), View.MeasureSpec.getMode(mo2717h)) : size < flexItem.mo4145r() ? View.MeasureSpec.makeMeasureSpec(flexItem.mo4145r(), View.MeasureSpec.getMode(mo2717h)) : mo2717h;
    }

    /* renamed from: o */
    public final int m2738o(int i2, FlexItem flexItem, int i3) {
        InterfaceC2410a interfaceC2410a = this.f6436a;
        int mo2713d = interfaceC2410a.mo2713d(i2, flexItem.mo4144p() + flexItem.mo4139i() + this.f6436a.getPaddingRight() + interfaceC2410a.getPaddingLeft() + i3, flexItem.getWidth());
        int size = View.MeasureSpec.getSize(mo2713d);
        return size > flexItem.mo4148v() ? View.MeasureSpec.makeMeasureSpec(flexItem.mo4148v(), View.MeasureSpec.getMode(mo2713d)) : size < flexItem.mo4136f() ? View.MeasureSpec.makeMeasureSpec(flexItem.mo4136f(), View.MeasureSpec.getMode(mo2713d)) : mo2713d;
    }

    /* renamed from: p */
    public final int m2739p(FlexItem flexItem, boolean z) {
        return z ? flexItem.mo4138h() : flexItem.mo4144p();
    }

    /* renamed from: q */
    public final int m2740q(FlexItem flexItem, boolean z) {
        return z ? flexItem.mo4144p() : flexItem.mo4138h();
    }

    /* renamed from: r */
    public final int m2741r(FlexItem flexItem, boolean z) {
        return z ? flexItem.mo4140j() : flexItem.mo4139i();
    }

    /* renamed from: s */
    public final int m2742s(FlexItem flexItem, boolean z) {
        return z ? flexItem.mo4139i() : flexItem.mo4140j();
    }

    /* renamed from: t */
    public final boolean m2743t(int i2, int i3, C2411b c2411b) {
        return i2 == i3 - 1 && c2411b.m2720a() != 0;
    }

    /* renamed from: u */
    public void m2744u(View view, C2411b c2411b, int i2, int i3, int i4, int i5) {
        FlexItem flexItem = (FlexItem) view.getLayoutParams();
        int alignItems = this.f6436a.getAlignItems();
        if (flexItem.mo4134a() != -1) {
            alignItems = flexItem.mo4134a();
        }
        int i6 = c2411b.f6424g;
        if (alignItems != 0) {
            if (alignItems == 1) {
                if (this.f6436a.getFlexWrap() != 2) {
                    int i7 = i3 + i6;
                    view.layout(i2, (i7 - view.getMeasuredHeight()) - flexItem.mo4138h(), i4, i7 - flexItem.mo4138h());
                    return;
                }
                view.layout(i2, flexItem.mo4140j() + view.getMeasuredHeight() + (i3 - i6), i4, flexItem.mo4140j() + view.getMeasuredHeight() + (i5 - i6));
                return;
            }
            if (alignItems == 2) {
                int mo4140j = ((flexItem.mo4140j() + (i6 - view.getMeasuredHeight())) - flexItem.mo4138h()) / 2;
                if (this.f6436a.getFlexWrap() != 2) {
                    int i8 = i3 + mo4140j;
                    view.layout(i2, i8, i4, view.getMeasuredHeight() + i8);
                    return;
                } else {
                    int i9 = i3 - mo4140j;
                    view.layout(i2, i9, i4, view.getMeasuredHeight() + i9);
                    return;
                }
            }
            if (alignItems == 3) {
                if (this.f6436a.getFlexWrap() != 2) {
                    int max = Math.max(c2411b.f6429l - view.getBaseline(), flexItem.mo4140j());
                    view.layout(i2, i3 + max, i4, i5 + max);
                    return;
                } else {
                    int max2 = Math.max(view.getBaseline() + (c2411b.f6429l - view.getMeasuredHeight()), flexItem.mo4138h());
                    view.layout(i2, i3 - max2, i4, i5 - max2);
                    return;
                }
            }
            if (alignItems != 4) {
                return;
            }
        }
        if (this.f6436a.getFlexWrap() != 2) {
            view.layout(i2, flexItem.mo4140j() + i3, i4, flexItem.mo4140j() + i5);
        } else {
            view.layout(i2, i3 - flexItem.mo4138h(), i4, i5 - flexItem.mo4138h());
        }
    }

    /* renamed from: v */
    public void m2745v(View view, C2411b c2411b, boolean z, int i2, int i3, int i4, int i5) {
        FlexItem flexItem = (FlexItem) view.getLayoutParams();
        int alignItems = this.f6436a.getAlignItems();
        if (flexItem.mo4134a() != -1) {
            alignItems = flexItem.mo4134a();
        }
        int i6 = c2411b.f6424g;
        if (alignItems != 0) {
            if (alignItems == 1) {
                if (!z) {
                    view.layout(((i2 + i6) - view.getMeasuredWidth()) - flexItem.mo4144p(), i3, ((i4 + i6) - view.getMeasuredWidth()) - flexItem.mo4144p(), i5);
                    return;
                }
                view.layout(flexItem.mo4139i() + view.getMeasuredWidth() + (i2 - i6), i3, flexItem.mo4139i() + view.getMeasuredWidth() + (i4 - i6), i5);
                return;
            }
            if (alignItems == 2) {
                ViewGroup.MarginLayoutParams marginLayoutParams = (ViewGroup.MarginLayoutParams) view.getLayoutParams();
                int marginStart = ((MarginLayoutParamsCompat.getMarginStart(marginLayoutParams) + (i6 - view.getMeasuredWidth())) - MarginLayoutParamsCompat.getMarginEnd(marginLayoutParams)) / 2;
                if (z) {
                    view.layout(i2 - marginStart, i3, i4 - marginStart, i5);
                    return;
                } else {
                    view.layout(i2 + marginStart, i3, i4 + marginStart, i5);
                    return;
                }
            }
            if (alignItems != 3 && alignItems != 4) {
                return;
            }
        }
        if (z) {
            view.layout(i2 - flexItem.mo4144p(), i3, i4 - flexItem.mo4144p(), i5);
        } else {
            view.layout(flexItem.mo4139i() + i2, i3, flexItem.mo4139i() + i4, i5);
        }
    }

    /* renamed from: w */
    public final void m2746w(int i2, int i3, C2411b c2411b, int i4, int i5, boolean z) {
        int i6;
        int i7;
        int i8;
        int i9;
        int i10 = c2411b.f6422e;
        float f2 = c2411b.f6428k;
        float f3 = 0.0f;
        if (f2 <= 0.0f || i4 > i10) {
            return;
        }
        float f4 = (i10 - i4) / f2;
        c2411b.f6422e = i5 + c2411b.f6423f;
        if (!z) {
            c2411b.f6424g = Integer.MIN_VALUE;
        }
        int i11 = 0;
        boolean z2 = false;
        int i12 = 0;
        float f5 = 0.0f;
        while (i11 < c2411b.f6425h) {
            int i13 = c2411b.f6432o + i11;
            View mo2712c = this.f6436a.mo2712c(i13);
            if (mo2712c == null || mo2712c.getVisibility() == 8) {
                i6 = i10;
                i7 = i11;
            } else {
                FlexItem flexItem = (FlexItem) mo2712c.getLayoutParams();
                int flexDirection = this.f6436a.getFlexDirection();
                if (flexDirection == 0 || flexDirection == 1) {
                    i6 = i10;
                    int i14 = i11;
                    int measuredWidth = mo2712c.getMeasuredWidth();
                    long[] jArr = this.f6440e;
                    if (jArr != null) {
                        measuredWidth = (int) jArr[i13];
                    }
                    int measuredHeight = mo2712c.getMeasuredHeight();
                    long[] jArr2 = this.f6440e;
                    if (jArr2 != null) {
                        measuredHeight = m2736m(jArr2[i13]);
                    }
                    if (this.f6437b[i13] || flexItem.mo4135c() <= 0.0f) {
                        i7 = i14;
                    } else {
                        float mo4135c = measuredWidth - (flexItem.mo4135c() * f4);
                        i7 = i14;
                        if (i7 == c2411b.f6425h - 1) {
                            mo4135c += f5;
                            f5 = 0.0f;
                        }
                        int round = Math.round(mo4135c);
                        if (round < flexItem.mo4136f()) {
                            i9 = flexItem.mo4136f();
                            this.f6437b[i13] = true;
                            c2411b.f6428k -= flexItem.mo4135c();
                            z2 = true;
                        } else {
                            float f6 = (mo4135c - round) + f5;
                            double d2 = f6;
                            if (d2 > 1.0d) {
                                round++;
                                f6 -= 1.0f;
                            } else if (d2 < -1.0d) {
                                round--;
                                f6 += 1.0f;
                            }
                            f5 = f6;
                            i9 = round;
                        }
                        int m2737n = m2737n(i3, flexItem, c2411b.f6430m);
                        int makeMeasureSpec = View.MeasureSpec.makeMeasureSpec(i9, 1073741824);
                        mo2712c.measure(makeMeasureSpec, m2737n);
                        int measuredWidth2 = mo2712c.getMeasuredWidth();
                        int measuredHeight2 = mo2712c.getMeasuredHeight();
                        m2723B(i13, makeMeasureSpec, m2737n, mo2712c);
                        this.f6436a.mo2714e(i13, mo2712c);
                        measuredWidth = measuredWidth2;
                        measuredHeight = measuredHeight2;
                    }
                    int max = Math.max(i12, this.f6436a.mo2719j(mo2712c) + flexItem.mo4138h() + flexItem.mo4140j() + measuredHeight);
                    c2411b.f6422e = flexItem.mo4144p() + flexItem.mo4139i() + measuredWidth + c2411b.f6422e;
                    i8 = max;
                } else {
                    int measuredHeight3 = mo2712c.getMeasuredHeight();
                    long[] jArr3 = this.f6440e;
                    if (jArr3 != null) {
                        measuredHeight3 = m2736m(jArr3[i13]);
                    }
                    int measuredWidth3 = mo2712c.getMeasuredWidth();
                    long[] jArr4 = this.f6440e;
                    if (jArr4 != null) {
                        measuredWidth3 = (int) jArr4[i13];
                    }
                    if (this.f6437b[i13] || flexItem.mo4135c() <= f3) {
                        i6 = i10;
                        i7 = i11;
                    } else {
                        float mo4135c2 = measuredHeight3 - (flexItem.mo4135c() * f4);
                        if (i11 == c2411b.f6425h - 1) {
                            mo4135c2 += f5;
                            f5 = 0.0f;
                        }
                        int round2 = Math.round(mo4135c2);
                        if (round2 < flexItem.mo4145r()) {
                            int mo4145r = flexItem.mo4145r();
                            this.f6437b[i13] = true;
                            c2411b.f6428k -= flexItem.mo4135c();
                            i7 = i11;
                            round2 = mo4145r;
                            z2 = true;
                            i6 = i10;
                        } else {
                            float f7 = (mo4135c2 - round2) + f5;
                            i6 = i10;
                            i7 = i11;
                            double d3 = f7;
                            if (d3 > 1.0d) {
                                round2++;
                                f7 -= 1.0f;
                            } else if (d3 < -1.0d) {
                                round2--;
                                f7 += 1.0f;
                            }
                            f5 = f7;
                        }
                        int m2738o = m2738o(i2, flexItem, c2411b.f6430m);
                        int makeMeasureSpec2 = View.MeasureSpec.makeMeasureSpec(round2, 1073741824);
                        mo2712c.measure(m2738o, makeMeasureSpec2);
                        measuredWidth3 = mo2712c.getMeasuredWidth();
                        int measuredHeight4 = mo2712c.getMeasuredHeight();
                        m2723B(i13, m2738o, makeMeasureSpec2, mo2712c);
                        this.f6436a.mo2714e(i13, mo2712c);
                        measuredHeight3 = measuredHeight4;
                    }
                    i8 = Math.max(i12, this.f6436a.mo2719j(mo2712c) + flexItem.mo4144p() + flexItem.mo4139i() + measuredWidth3);
                    c2411b.f6422e = flexItem.mo4138h() + flexItem.mo4140j() + measuredHeight3 + c2411b.f6422e;
                }
                c2411b.f6424g = Math.max(c2411b.f6424g, i8);
                i12 = i8;
            }
            i11 = i7 + 1;
            i10 = i6;
            f3 = 0.0f;
        }
        int i15 = i10;
        if (!z2 || i15 == c2411b.f6422e) {
            return;
        }
        m2746w(i2, i3, c2411b, i4, i5, true);
    }

    /* renamed from: x */
    public final int[] m2747x(int i2, List<c> list, SparseIntArray sparseIntArray) {
        Collections.sort(list);
        sparseIntArray.clear();
        int[] iArr = new int[i2];
        int i3 = 0;
        for (c cVar : list) {
            int i4 = cVar.f6443c;
            iArr[i3] = i4;
            sparseIntArray.append(i4, cVar.f6444e);
            i3++;
        }
        return iArr;
    }

    /* renamed from: y */
    public final void m2748y(View view, int i2, int i3) {
        FlexItem flexItem = (FlexItem) view.getLayoutParams();
        int min = Math.min(Math.max(((i2 - flexItem.mo4139i()) - flexItem.mo4144p()) - this.f6436a.mo2719j(view), flexItem.mo4136f()), flexItem.mo4148v());
        long[] jArr = this.f6440e;
        int makeMeasureSpec = View.MeasureSpec.makeMeasureSpec(jArr != null ? m2736m(jArr[i3]) : view.getMeasuredHeight(), 1073741824);
        int makeMeasureSpec2 = View.MeasureSpec.makeMeasureSpec(min, 1073741824);
        view.measure(makeMeasureSpec2, makeMeasureSpec);
        m2723B(i3, makeMeasureSpec2, makeMeasureSpec, view);
        this.f6436a.mo2714e(i3, view);
    }

    /* renamed from: z */
    public final void m2749z(View view, int i2, int i3) {
        FlexItem flexItem = (FlexItem) view.getLayoutParams();
        int min = Math.min(Math.max(((i2 - flexItem.mo4140j()) - flexItem.mo4138h()) - this.f6436a.mo2719j(view), flexItem.mo4145r()), flexItem.mo4147t());
        long[] jArr = this.f6440e;
        int makeMeasureSpec = View.MeasureSpec.makeMeasureSpec(jArr != null ? (int) jArr[i3] : view.getMeasuredWidth(), 1073741824);
        int makeMeasureSpec2 = View.MeasureSpec.makeMeasureSpec(min, 1073741824);
        view.measure(makeMeasureSpec, makeMeasureSpec2);
        m2723B(i3, makeMeasureSpec, makeMeasureSpec2, view);
        this.f6436a.mo2714e(i3, view);
    }
}
