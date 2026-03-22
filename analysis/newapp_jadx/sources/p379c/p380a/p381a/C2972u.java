package p379c.p380a.p381a;

import java.lang.Comparable;
import java.util.Arrays;
import kotlin.PublishedApi;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p379c.p380a.AbstractC3094r0;
import p379c.p380a.p381a.InterfaceC2973v;

/* renamed from: c.a.a.u */
/* loaded from: classes2.dex */
public class C2972u<T extends InterfaceC2973v & Comparable<? super T>> {
    public volatile int _size = 0;

    /* renamed from: a */
    public T[] f8137a;

    @PublishedApi
    /* renamed from: a */
    public final void m3447a(@NotNull T t) {
        AbstractC3094r0.b bVar = (AbstractC3094r0.b) t;
        bVar.mo3453b(this);
        T[] tArr = this.f8137a;
        if (tArr == null) {
            tArr = (T[]) new InterfaceC2973v[4];
            this.f8137a = tArr;
        } else if (this._size >= tArr.length) {
            Object[] copyOf = Arrays.copyOf(tArr, this._size * 2);
            Intrinsics.checkNotNullExpressionValue(copyOf, "java.util.Arrays.copyOf(this, newSize)");
            tArr = (T[]) ((InterfaceC2973v[]) copyOf);
            this.f8137a = tArr;
        }
        int i2 = this._size;
        this._size = i2 + 1;
        tArr[i2] = t;
        bVar.f8451e = i2;
        m3450d(i2);
    }

    @PublishedApi
    @Nullable
    /* renamed from: b */
    public final T m3448b() {
        T[] tArr = this.f8137a;
        if (tArr != null) {
            return tArr[0];
        }
        return null;
    }

    @PublishedApi
    @NotNull
    /* renamed from: c */
    public final T m3449c(int i2) {
        T[] tArr = this.f8137a;
        Intrinsics.checkNotNull(tArr);
        this._size--;
        if (i2 < this._size) {
            m3451e(i2, this._size);
            int i3 = (i2 - 1) / 2;
            if (i2 > 0) {
                T t = tArr[i2];
                Intrinsics.checkNotNull(t);
                T t2 = tArr[i3];
                Intrinsics.checkNotNull(t2);
                if (((Comparable) t).compareTo(t2) < 0) {
                    m3451e(i2, i3);
                    m3450d(i3);
                }
            }
            while (true) {
                int i4 = (i2 * 2) + 1;
                if (i4 >= this._size) {
                    break;
                }
                T[] tArr2 = this.f8137a;
                Intrinsics.checkNotNull(tArr2);
                int i5 = i4 + 1;
                if (i5 < this._size) {
                    T t3 = tArr2[i5];
                    Intrinsics.checkNotNull(t3);
                    T t4 = tArr2[i4];
                    Intrinsics.checkNotNull(t4);
                    if (((Comparable) t3).compareTo(t4) < 0) {
                        i4 = i5;
                    }
                }
                T t5 = tArr2[i2];
                Intrinsics.checkNotNull(t5);
                T t6 = tArr2[i4];
                Intrinsics.checkNotNull(t6);
                if (((Comparable) t5).compareTo(t6) <= 0) {
                    break;
                }
                m3451e(i2, i4);
                i2 = i4;
            }
        }
        T t7 = tArr[this._size];
        Intrinsics.checkNotNull(t7);
        t7.mo3453b(null);
        t7.mo3452a(-1);
        tArr[this._size] = null;
        return t7;
    }

    /* renamed from: d */
    public final void m3450d(int i2) {
        while (i2 > 0) {
            T[] tArr = this.f8137a;
            Intrinsics.checkNotNull(tArr);
            int i3 = (i2 - 1) / 2;
            T t = tArr[i3];
            Intrinsics.checkNotNull(t);
            T t2 = tArr[i2];
            Intrinsics.checkNotNull(t2);
            if (((Comparable) t).compareTo(t2) <= 0) {
                return;
            }
            m3451e(i2, i3);
            i2 = i3;
        }
    }

    /* renamed from: e */
    public final void m3451e(int i2, int i3) {
        T[] tArr = this.f8137a;
        Intrinsics.checkNotNull(tArr);
        T t = tArr[i3];
        Intrinsics.checkNotNull(t);
        T t2 = tArr[i2];
        Intrinsics.checkNotNull(t2);
        tArr[i2] = t;
        tArr[i3] = t2;
        t.mo3452a(i2);
        t2.mo3452a(i3);
    }
}
