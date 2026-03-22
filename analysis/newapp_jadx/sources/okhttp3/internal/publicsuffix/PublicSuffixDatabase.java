package okhttp3.internal.publicsuffix;

import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.net.IDN;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicBoolean;
import kotlin.TypeCastException;
import kotlin.Unit;
import kotlin.collections.CollectionsKt__CollectionsJVMKt;
import kotlin.collections.CollectionsKt__CollectionsKt;
import kotlin.collections.CollectionsKt___CollectionsKt;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.p472io.CloseableKt;
import kotlin.sequences.SequencesKt___SequencesKt;
import kotlin.text.StringsKt__StringsKt;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p458k.p459p0.C4401c;
import p458k.p459p0.p467k.C4463g;
import p474l.C4751m;
import p474l.InterfaceC4746h;

/* loaded from: classes3.dex */
public final class PublicSuffixDatabase {

    /* renamed from: e */
    public final AtomicBoolean f12979e = new AtomicBoolean(false);

    /* renamed from: f */
    public final CountDownLatch f12980f = new CountDownLatch(1);

    /* renamed from: g */
    public byte[] f12981g;

    /* renamed from: h */
    public byte[] f12982h;

    /* renamed from: d */
    public static final C5036a f12978d = new C5036a(null);

    /* renamed from: a */
    public static final byte[] f12975a = {(byte) 42};

    /* renamed from: b */
    public static final List<String> f12976b = CollectionsKt__CollectionsJVMKt.listOf("*");

    /* renamed from: c */
    public static final PublicSuffixDatabase f12977c = new PublicSuffixDatabase();

    /* renamed from: okhttp3.internal.publicsuffix.PublicSuffixDatabase$a */
    public static final class C5036a {
        public C5036a(DefaultConstructorMarker defaultConstructorMarker) {
        }

        /* renamed from: a */
        public static final String m5698a(C5036a c5036a, byte[] bArr, byte[][] bArr2, int i2) {
            int i3;
            boolean z;
            int i4;
            int i5;
            int length = bArr.length;
            int i6 = 0;
            while (i6 < length) {
                int i7 = (i6 + length) / 2;
                while (i7 > -1 && bArr[i7] != ((byte) 10)) {
                    i7--;
                }
                int i8 = i7 + 1;
                int i9 = 1;
                while (true) {
                    i3 = i8 + i9;
                    if (bArr[i3] == ((byte) 10)) {
                        break;
                    }
                    i9++;
                }
                int i10 = i3 - i8;
                int i11 = i2;
                boolean z2 = false;
                int i12 = 0;
                int i13 = 0;
                while (true) {
                    if (z2) {
                        i4 = 46;
                        z = false;
                    } else {
                        byte b2 = bArr2[i11][i12];
                        byte[] bArr3 = C4401c.f11556a;
                        int i14 = b2 & 255;
                        z = z2;
                        i4 = i14;
                    }
                    byte b3 = bArr[i8 + i13];
                    byte[] bArr4 = C4401c.f11556a;
                    i5 = i4 - (b3 & 255);
                    if (i5 != 0) {
                        break;
                    }
                    i13++;
                    i12++;
                    if (i13 == i10) {
                        break;
                    }
                    if (bArr2[i11].length != i12) {
                        z2 = z;
                    } else {
                        if (i11 == bArr2.length - 1) {
                            break;
                        }
                        i11++;
                        z2 = true;
                        i12 = -1;
                    }
                }
                if (i5 >= 0) {
                    if (i5 <= 0) {
                        int i15 = i10 - i13;
                        int length2 = bArr2[i11].length - i12;
                        int length3 = bArr2.length;
                        for (int i16 = i11 + 1; i16 < length3; i16++) {
                            length2 += bArr2[i16].length;
                        }
                        if (length2 >= i15) {
                            if (length2 <= i15) {
                                Charset UTF_8 = StandardCharsets.UTF_8;
                                Intrinsics.checkExpressionValueIsNotNull(UTF_8, "UTF_8");
                                return new String(bArr, i8, i10, UTF_8);
                            }
                        }
                    }
                    i6 = i3 + 1;
                }
                length = i8 - 1;
            }
            return null;
        }
    }

    @Nullable
    /* renamed from: a */
    public final String m5696a(@NotNull String domain) {
        String str;
        String str2;
        String str3;
        List<String> emptyList;
        List<String> emptyList2;
        int size;
        int size2;
        Intrinsics.checkParameterIsNotNull(domain, "domain");
        String unicodeDomain = IDN.toUnicode(domain);
        Intrinsics.checkExpressionValueIsNotNull(unicodeDomain, "unicodeDomain");
        List split$default = StringsKt__StringsKt.split$default((CharSequence) unicodeDomain, new char[]{'.'}, false, 0, 6, (Object) null);
        if (this.f12979e.get() || !this.f12979e.compareAndSet(false, true)) {
            try {
                this.f12980f.await();
            } catch (InterruptedException unused) {
                Thread.currentThread().interrupt();
            }
        } else {
            boolean z = false;
            while (true) {
                try {
                    try {
                        try {
                            m5697b();
                            if (!z) {
                                break;
                            }
                            Thread.currentThread().interrupt();
                            break;
                        } catch (InterruptedIOException unused2) {
                            Thread.interrupted();
                            z = true;
                        }
                    } catch (IOException e2) {
                        C4463g.a aVar = C4463g.f11988c;
                        C4463g.f11986a.mo5236k("Failed to read public suffix list", 5, e2);
                        if (z) {
                            Thread.currentThread().interrupt();
                        }
                    }
                } catch (Throwable th) {
                    if (z) {
                        Thread.currentThread().interrupt();
                    }
                    throw th;
                }
            }
        }
        if (!(this.f12981g != null)) {
            throw new IllegalStateException("Unable to load publicsuffixes.gz resource from the classpath.".toString());
        }
        int size3 = split$default.size();
        byte[][] bArr = new byte[size3][];
        for (int i2 = 0; i2 < size3; i2++) {
            String str4 = (String) split$default.get(i2);
            Charset UTF_8 = StandardCharsets.UTF_8;
            Intrinsics.checkExpressionValueIsNotNull(UTF_8, "UTF_8");
            if (str4 == null) {
                throw new TypeCastException("null cannot be cast to non-null type java.lang.String");
            }
            byte[] bytes = str4.getBytes(UTF_8);
            Intrinsics.checkExpressionValueIsNotNull(bytes, "(this as java.lang.String).getBytes(charset)");
            bArr[i2] = bytes;
        }
        int i3 = 0;
        while (true) {
            if (i3 >= size3) {
                str = null;
                break;
            }
            C5036a c5036a = f12978d;
            byte[] bArr2 = this.f12981g;
            if (bArr2 == null) {
                Intrinsics.throwUninitializedPropertyAccessException("publicSuffixListBytes");
            }
            String m5698a = C5036a.m5698a(c5036a, bArr2, bArr, i3);
            if (m5698a != null) {
                str = m5698a;
                break;
            }
            i3++;
        }
        if (size3 > 1) {
            byte[][] bArr3 = (byte[][]) bArr.clone();
            int length = bArr3.length - 1;
            for (int i4 = 0; i4 < length; i4++) {
                bArr3[i4] = f12975a;
                C5036a c5036a2 = f12978d;
                byte[] bArr4 = this.f12981g;
                if (bArr4 == null) {
                    Intrinsics.throwUninitializedPropertyAccessException("publicSuffixListBytes");
                }
                String m5698a2 = C5036a.m5698a(c5036a2, bArr4, bArr3, i4);
                if (m5698a2 != null) {
                    str2 = m5698a2;
                    break;
                }
            }
        }
        str2 = null;
        if (str2 != null) {
            int i5 = size3 - 1;
            for (int i6 = 0; i6 < i5; i6++) {
                C5036a c5036a3 = f12978d;
                byte[] bArr5 = this.f12982h;
                if (bArr5 == null) {
                    Intrinsics.throwUninitializedPropertyAccessException("publicSuffixExceptionListBytes");
                }
                str3 = C5036a.m5698a(c5036a3, bArr5, bArr, i6);
                if (str3 != null) {
                    break;
                }
            }
        }
        str3 = null;
        if (str3 != null) {
            emptyList = StringsKt__StringsKt.split$default((CharSequence) ('!' + str3), new char[]{'.'}, false, 0, 6, (Object) null);
        } else if (str == null && str2 == null) {
            emptyList = f12976b;
        } else {
            if (str == null || (emptyList = StringsKt__StringsKt.split$default((CharSequence) str, new char[]{'.'}, false, 0, 6, (Object) null)) == null) {
                emptyList = CollectionsKt__CollectionsKt.emptyList();
            }
            if (str2 == null || (emptyList2 = StringsKt__StringsKt.split$default((CharSequence) str2, new char[]{'.'}, false, 0, 6, (Object) null)) == null) {
                emptyList2 = CollectionsKt__CollectionsKt.emptyList();
            }
            if (emptyList.size() <= emptyList2.size()) {
                emptyList = emptyList2;
            }
        }
        if (split$default.size() == emptyList.size() && emptyList.get(0).charAt(0) != '!') {
            return null;
        }
        if (emptyList.get(0).charAt(0) == '!') {
            size = split$default.size();
            size2 = emptyList.size();
        } else {
            size = split$default.size();
            size2 = emptyList.size() + 1;
        }
        return SequencesKt___SequencesKt.joinToString$default(SequencesKt___SequencesKt.drop(CollectionsKt___CollectionsKt.asSequence(StringsKt__StringsKt.split$default((CharSequence) domain, new char[]{'.'}, false, 0, 6, (Object) null)), size - size2), ".", null, null, 0, null, null, 62, null);
    }

    /* renamed from: b */
    public final void m5697b() {
        InputStream resourceAsStream = PublicSuffixDatabase.class.getResourceAsStream("publicsuffixes.gz");
        if (resourceAsStream == null) {
            return;
        }
        InterfaceC4746h m2500o = C2354n.m2500o(new C4751m(C2354n.m2397H1(resourceAsStream)));
        try {
            byte[] mo5355F = m2500o.mo5355F(m2500o.readInt());
            byte[] mo5355F2 = m2500o.mo5355F(m2500o.readInt());
            Unit unit = Unit.INSTANCE;
            CloseableKt.closeFinally(m2500o, null);
            synchronized (this) {
                if (mo5355F == null) {
                    Intrinsics.throwNpe();
                }
                this.f12981g = mo5355F;
                if (mo5355F2 == null) {
                    Intrinsics.throwNpe();
                }
                this.f12982h = mo5355F2;
            }
            this.f12980f.countDown();
        } finally {
        }
    }
}
