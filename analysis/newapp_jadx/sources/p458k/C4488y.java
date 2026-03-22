package p458k;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import kotlin.Pair;
import kotlin.TuplesKt;
import kotlin.TypeCastException;
import kotlin.collections.CollectionsKt__CollectionsKt;
import kotlin.collections.CollectionsKt__MutableCollectionsKt;
import kotlin.jvm.JvmName;
import kotlin.jvm.JvmStatic;
import kotlin.jvm.internal.ArrayIteratorKt;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.markers.KMappedMarker;
import kotlin.ranges.IntProgression;
import kotlin.ranges.RangesKt___RangesKt;
import kotlin.text.StringsKt__StringsJVMKt;
import kotlin.text.StringsKt__StringsKt;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p458k.p459p0.C4401c;

/* renamed from: k.y */
/* loaded from: classes3.dex */
public final class C4488y implements Iterable<Pair<? extends String, ? extends String>>, KMappedMarker {

    /* renamed from: c */
    public static final b f12040c = new b(null);

    /* renamed from: e */
    public final String[] f12041e;

    /* renamed from: k.y$a */
    public static final class a {

        /* renamed from: a */
        @NotNull
        public final List<String> f12042a = new ArrayList(20);

        @NotNull
        /* renamed from: a */
        public final a m5282a(@NotNull String name, @NotNull String value) {
            Intrinsics.checkParameterIsNotNull(name, "name");
            Intrinsics.checkParameterIsNotNull(value, "value");
            b bVar = C4488y.f12040c;
            bVar.m5288a(name);
            bVar.m5289b(value, name);
            m5284c(name, value);
            return this;
        }

        @NotNull
        /* renamed from: b */
        public final a m5283b(@NotNull String line) {
            Intrinsics.checkParameterIsNotNull(line, "line");
            int indexOf$default = StringsKt__StringsKt.indexOf$default((CharSequence) line, ':', 1, false, 4, (Object) null);
            if (indexOf$default != -1) {
                String substring = line.substring(0, indexOf$default);
                Intrinsics.checkExpressionValueIsNotNull(substring, "(this as java.lang.Strin…ing(startIndex, endIndex)");
                String substring2 = line.substring(indexOf$default + 1);
                Intrinsics.checkExpressionValueIsNotNull(substring2, "(this as java.lang.String).substring(startIndex)");
                m5284c(substring, substring2);
            } else if (line.charAt(0) == ':') {
                String substring3 = line.substring(1);
                Intrinsics.checkExpressionValueIsNotNull(substring3, "(this as java.lang.String).substring(startIndex)");
                m5284c("", substring3);
            } else {
                m5284c("", line);
            }
            return this;
        }

        @NotNull
        /* renamed from: c */
        public final a m5284c(@NotNull String name, @NotNull String value) {
            Intrinsics.checkParameterIsNotNull(name, "name");
            Intrinsics.checkParameterIsNotNull(value, "value");
            this.f12042a.add(name);
            this.f12042a.add(StringsKt__StringsKt.trim((CharSequence) value).toString());
            return this;
        }

        @NotNull
        /* renamed from: d */
        public final C4488y m5285d() {
            Object[] array = this.f12042a.toArray(new String[0]);
            if (array != null) {
                return new C4488y((String[]) array, null);
            }
            throw new TypeCastException("null cannot be cast to non-null type kotlin.Array<T>");
        }

        @Nullable
        /* renamed from: e */
        public final String m5286e(@NotNull String name) {
            Intrinsics.checkParameterIsNotNull(name, "name");
            IntProgression step = RangesKt___RangesKt.step(RangesKt___RangesKt.downTo(this.f12042a.size() - 2, 0), 2);
            int first = step.getFirst();
            int last = step.getLast();
            int step2 = step.getStep();
            if (step2 >= 0) {
                if (first > last) {
                    return null;
                }
            } else if (first < last) {
                return null;
            }
            while (!StringsKt__StringsJVMKt.equals(name, this.f12042a.get(first), true)) {
                if (first == last) {
                    return null;
                }
                first += step2;
            }
            return this.f12042a.get(first + 1);
        }

        @NotNull
        /* renamed from: f */
        public final a m5287f(@NotNull String name) {
            Intrinsics.checkParameterIsNotNull(name, "name");
            int i2 = 0;
            while (i2 < this.f12042a.size()) {
                if (StringsKt__StringsJVMKt.equals(name, this.f12042a.get(i2), true)) {
                    this.f12042a.remove(i2);
                    this.f12042a.remove(i2);
                    i2 -= 2;
                }
                i2 += 2;
            }
            return this;
        }
    }

    /* renamed from: k.y$b */
    public static final class b {
        public b(DefaultConstructorMarker defaultConstructorMarker) {
        }

        /* renamed from: a */
        public final void m5288a(String str) {
            if (!(str.length() > 0)) {
                throw new IllegalArgumentException("name is empty".toString());
            }
            int length = str.length();
            for (int i2 = 0; i2 < length; i2++) {
                char charAt = str.charAt(i2);
                if (!('!' <= charAt && '~' >= charAt)) {
                    throw new IllegalArgumentException(C4401c.m5024i("Unexpected char %#04x at %d in header name: %s", Integer.valueOf(charAt), Integer.valueOf(i2), str).toString());
                }
            }
        }

        /* renamed from: b */
        public final void m5289b(String str, String str2) {
            int length = str.length();
            for (int i2 = 0; i2 < length; i2++) {
                char charAt = str.charAt(i2);
                if (!(charAt == '\t' || (' ' <= charAt && '~' >= charAt))) {
                    throw new IllegalArgumentException(C4401c.m5024i("Unexpected char %#04x at %d in %s value: %s", Integer.valueOf(charAt), Integer.valueOf(i2), str2, str).toString());
                }
            }
        }

        @JvmStatic
        @JvmName(name = "of")
        @NotNull
        /* renamed from: c */
        public final C4488y m5290c(@NotNull String... namesAndValues) {
            Intrinsics.checkParameterIsNotNull(namesAndValues, "namesAndValues");
            if (!(namesAndValues.length % 2 == 0)) {
                throw new IllegalArgumentException("Expected alternating header names and values".toString());
            }
            Object clone = namesAndValues.clone();
            if (clone == null) {
                throw new TypeCastException("null cannot be cast to non-null type kotlin.Array<kotlin.String>");
            }
            String[] strArr = (String[]) clone;
            int length = strArr.length;
            for (int i2 = 0; i2 < length; i2++) {
                if (!(strArr[i2] != null)) {
                    throw new IllegalArgumentException("Headers cannot be null".toString());
                }
                String str = strArr[i2];
                if (str == null) {
                    throw new TypeCastException("null cannot be cast to non-null type kotlin.CharSequence");
                }
                strArr[i2] = StringsKt__StringsKt.trim((CharSequence) str).toString();
            }
            IntProgression step = RangesKt___RangesKt.step(RangesKt___RangesKt.until(0, strArr.length), 2);
            int first = step.getFirst();
            int last = step.getLast();
            int step2 = step.getStep();
            if (step2 < 0 ? first >= last : first <= last) {
                while (true) {
                    String str2 = strArr[first];
                    String str3 = strArr[first + 1];
                    m5288a(str2);
                    m5289b(str3, str2);
                    if (first == last) {
                        break;
                    }
                    first += step2;
                }
            }
            return new C4488y(strArr, null);
        }
    }

    public C4488y(String[] strArr, DefaultConstructorMarker defaultConstructorMarker) {
        this.f12041e = strArr;
    }

    @Nullable
    /* renamed from: a */
    public final String m5277a(@NotNull String name) {
        Intrinsics.checkParameterIsNotNull(name, "name");
        String[] strArr = this.f12041e;
        IntProgression step = RangesKt___RangesKt.step(RangesKt___RangesKt.downTo(strArr.length - 2, 0), 2);
        int first = step.getFirst();
        int last = step.getLast();
        int step2 = step.getStep();
        if (step2 < 0 ? first >= last : first <= last) {
            while (!StringsKt__StringsJVMKt.equals(name, strArr[first], true)) {
                if (first != last) {
                    first += step2;
                }
            }
            return strArr[first + 1];
        }
        return null;
    }

    @NotNull
    /* renamed from: b */
    public final String m5278b(int i2) {
        return this.f12041e[i2 * 2];
    }

    @NotNull
    /* renamed from: c */
    public final a m5279c() {
        a aVar = new a();
        CollectionsKt__MutableCollectionsKt.addAll(aVar.f12042a, this.f12041e);
        return aVar;
    }

    @NotNull
    /* renamed from: d */
    public final String m5280d(int i2) {
        return this.f12041e[(i2 * 2) + 1];
    }

    @NotNull
    /* renamed from: e */
    public final List<String> m5281e(@NotNull String name) {
        Intrinsics.checkParameterIsNotNull(name, "name");
        int size = size();
        ArrayList arrayList = null;
        for (int i2 = 0; i2 < size; i2++) {
            if (StringsKt__StringsJVMKt.equals(name, m5278b(i2), true)) {
                if (arrayList == null) {
                    arrayList = new ArrayList(2);
                }
                arrayList.add(m5280d(i2));
            }
        }
        if (arrayList == null) {
            return CollectionsKt__CollectionsKt.emptyList();
        }
        List<String> unmodifiableList = Collections.unmodifiableList(arrayList);
        Intrinsics.checkExpressionValueIsNotNull(unmodifiableList, "Collections.unmodifiableList(result)");
        return unmodifiableList;
    }

    public boolean equals(@Nullable Object obj) {
        return (obj instanceof C4488y) && Arrays.equals(this.f12041e, ((C4488y) obj).f12041e);
    }

    public int hashCode() {
        return Arrays.hashCode(this.f12041e);
    }

    @Override // java.lang.Iterable
    @NotNull
    public Iterator<Pair<? extends String, ? extends String>> iterator() {
        int size = size();
        Pair[] pairArr = new Pair[size];
        for (int i2 = 0; i2 < size; i2++) {
            pairArr[i2] = TuplesKt.m5318to(m5278b(i2), m5280d(i2));
        }
        return ArrayIteratorKt.iterator(pairArr);
    }

    @JvmName(name = "size")
    public final int size() {
        return this.f12041e.length / 2;
    }

    @NotNull
    public String toString() {
        StringBuilder sb = new StringBuilder();
        int size = size();
        for (int i2 = 0; i2 < size; i2++) {
            sb.append(m5278b(i2));
            sb.append(": ");
            sb.append(m5280d(i2));
            sb.append("\n");
        }
        String sb2 = sb.toString();
        Intrinsics.checkExpressionValueIsNotNull(sb2, "StringBuilder().apply(builderAction).toString()");
        return sb2;
    }
}
