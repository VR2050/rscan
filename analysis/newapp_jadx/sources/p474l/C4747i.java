package p474l;

import java.io.EOFException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.lang.reflect.Field;
import java.security.MessageDigest;
import java.util.Arrays;
import kotlin.collections.ArraysKt___ArraysJvmKt;
import kotlin.jvm.JvmField;
import kotlin.jvm.JvmStatic;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.Charsets;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p474l.p475b0.C4740b;

/* renamed from: l.i */
/* loaded from: classes3.dex */
public class C4747i implements Serializable, Comparable<C4747i> {
    private static final long serialVersionUID = 1;

    /* renamed from: f */
    public transient int f12137f;

    /* renamed from: g */
    @Nullable
    public transient String f12138g;

    /* renamed from: h */
    @NotNull
    public final byte[] f12139h;

    /* renamed from: e */
    public static final a f12136e = new a(null);

    /* renamed from: c */
    @JvmField
    @NotNull
    public static final C4747i f12135c = new C4747i(new byte[0]);

    /* renamed from: l.i$a */
    public static final class a {
        public a(DefaultConstructorMarker defaultConstructorMarker) {
        }

        /* renamed from: d */
        public static C4747i m5409d(a aVar, byte[] toByteString, int i2, int i3, int i4) {
            if ((i4 & 1) != 0) {
                i2 = 0;
            }
            if ((i4 & 2) != 0) {
                i3 = toByteString.length;
            }
            Intrinsics.checkNotNullParameter(toByteString, "$this$toByteString");
            C2354n.m2530y(toByteString.length, i2, i3);
            return new C4747i(ArraysKt___ArraysJvmKt.copyOfRange(toByteString, i2, i3 + i2));
        }

        @JvmStatic
        @Nullable
        /* renamed from: a */
        public final C4747i m5410a(@NotNull String decodeBase64ToArray) {
            int i2;
            int i3;
            char charAt;
            Intrinsics.checkNotNullParameter(decodeBase64ToArray, "$this$decodeBase64");
            byte[] bArr = C4736a.f12114a;
            Intrinsics.checkNotNullParameter(decodeBase64ToArray, "$this$decodeBase64ToArray");
            int length = decodeBase64ToArray.length();
            while (length > 0 && ((charAt = decodeBase64ToArray.charAt(length - 1)) == '=' || charAt == '\n' || charAt == '\r' || charAt == ' ' || charAt == '\t')) {
                length = i3;
            }
            int i4 = (int) ((length * 6) / 8);
            byte[] bArr2 = new byte[i4];
            int i5 = 0;
            int i6 = 0;
            int i7 = 0;
            int i8 = 0;
            while (true) {
                if (i5 < length) {
                    char charAt2 = decodeBase64ToArray.charAt(i5);
                    if ('A' <= charAt2 && 'Z' >= charAt2) {
                        i2 = charAt2 - 'A';
                    } else if ('a' <= charAt2 && 'z' >= charAt2) {
                        i2 = charAt2 - 'G';
                    } else if ('0' <= charAt2 && '9' >= charAt2) {
                        i2 = charAt2 + 4;
                    } else if (charAt2 == '+' || charAt2 == '-') {
                        i2 = 62;
                    } else if (charAt2 == '/' || charAt2 == '_') {
                        i2 = 63;
                    } else {
                        if (charAt2 != '\n' && charAt2 != '\r' && charAt2 != ' ' && charAt2 != '\t') {
                            break;
                        }
                        i5++;
                    }
                    i7 = (i7 << 6) | i2;
                    i6++;
                    if (i6 % 4 == 0) {
                        int i9 = i8 + 1;
                        bArr2[i8] = (byte) (i7 >> 16);
                        int i10 = i9 + 1;
                        bArr2[i9] = (byte) (i7 >> 8);
                        bArr2[i10] = (byte) i7;
                        i8 = i10 + 1;
                    }
                    i5++;
                } else {
                    int i11 = i6 % 4;
                    if (i11 != 1) {
                        if (i11 == 2) {
                            bArr2[i8] = (byte) ((i7 << 12) >> 16);
                            i8++;
                        } else if (i11 == 3) {
                            int i12 = i7 << 6;
                            int i13 = i8 + 1;
                            bArr2[i8] = (byte) (i12 >> 16);
                            i8 = i13 + 1;
                            bArr2[i13] = (byte) (i12 >> 8);
                        }
                        if (i8 != i4) {
                            bArr2 = Arrays.copyOf(bArr2, i8);
                            Intrinsics.checkNotNullExpressionValue(bArr2, "java.util.Arrays.copyOf(this, newSize)");
                        }
                    }
                }
            }
            bArr2 = null;
            if (bArr2 != null) {
                return new C4747i(bArr2);
            }
            return null;
        }

        @JvmStatic
        @NotNull
        /* renamed from: b */
        public final C4747i m5411b(@NotNull String decodeHex) {
            Intrinsics.checkNotNullParameter(decodeHex, "$this$decodeHex");
            if (!(decodeHex.length() % 2 == 0)) {
                throw new IllegalArgumentException(C1499a.m637w("Unexpected hex string: ", decodeHex).toString());
            }
            int length = decodeHex.length() / 2;
            byte[] bArr = new byte[length];
            for (int i2 = 0; i2 < length; i2++) {
                int i3 = i2 * 2;
                bArr[i2] = (byte) (C4740b.m5349a(decodeHex.charAt(i3 + 1)) + (C4740b.m5349a(decodeHex.charAt(i3)) << 4));
            }
            return new C4747i(bArr);
        }

        @JvmStatic
        @NotNull
        /* renamed from: c */
        public final C4747i m5412c(@NotNull String asUtf8ToByteArray) {
            Intrinsics.checkNotNullParameter(asUtf8ToByteArray, "$this$encodeUtf8");
            Intrinsics.checkNotNullParameter(asUtf8ToByteArray, "$this$asUtf8ToByteArray");
            byte[] bytes = asUtf8ToByteArray.getBytes(Charsets.UTF_8);
            Intrinsics.checkNotNullExpressionValue(bytes, "(this as java.lang.String).getBytes(charset)");
            C4747i c4747i = new C4747i(bytes);
            c4747i.f12138g = asUtf8ToByteArray;
            return c4747i;
        }
    }

    public C4747i(@NotNull byte[] data) {
        Intrinsics.checkNotNullParameter(data, "data");
        this.f12139h = data;
    }

    private final void readObject(ObjectInputStream readByteString) {
        int readInt = readByteString.readInt();
        Intrinsics.checkNotNullParameter(readByteString, "$this$readByteString");
        int i2 = 0;
        if (!(readInt >= 0)) {
            throw new IllegalArgumentException(C1499a.m626l("byteCount < 0: ", readInt).toString());
        }
        byte[] data = new byte[readInt];
        while (i2 < readInt) {
            int read = readByteString.read(data, i2, readInt - i2);
            if (read == -1) {
                throw new EOFException();
            }
            i2 += read;
        }
        Intrinsics.checkNotNullParameter(data, "data");
        Field field = C4747i.class.getDeclaredField("h");
        Intrinsics.checkNotNullExpressionValue(field, "field");
        field.setAccessible(true);
        field.set(this, data);
    }

    private final void writeObject(ObjectOutputStream objectOutputStream) {
        objectOutputStream.writeInt(this.f12139h.length);
        objectOutputStream.write(this.f12139h);
    }

    @NotNull
    /* renamed from: a */
    public String mo5398a() {
        byte[] encodeBase64 = this.f12139h;
        byte[] bArr = C4736a.f12114a;
        byte[] map = C4736a.f12114a;
        Intrinsics.checkNotNullParameter(encodeBase64, "$this$encodeBase64");
        Intrinsics.checkNotNullParameter(map, "map");
        byte[] toUtf8String = new byte[((encodeBase64.length + 2) / 3) * 4];
        int length = encodeBase64.length - (encodeBase64.length % 3);
        int i2 = 0;
        int i3 = 0;
        while (i2 < length) {
            int i4 = i2 + 1;
            byte b2 = encodeBase64[i2];
            int i5 = i4 + 1;
            byte b3 = encodeBase64[i4];
            int i6 = i5 + 1;
            byte b4 = encodeBase64[i5];
            int i7 = i3 + 1;
            toUtf8String[i3] = map[(b2 & 255) >> 2];
            int i8 = i7 + 1;
            toUtf8String[i7] = map[((b2 & 3) << 4) | ((b3 & 255) >> 4)];
            int i9 = i8 + 1;
            toUtf8String[i8] = map[((b3 & 15) << 2) | ((b4 & 255) >> 6)];
            i3 = i9 + 1;
            toUtf8String[i9] = map[b4 & 63];
            i2 = i6;
        }
        int length2 = encodeBase64.length - length;
        if (length2 == 1) {
            byte b5 = encodeBase64[i2];
            int i10 = i3 + 1;
            toUtf8String[i3] = map[(b5 & 255) >> 2];
            int i11 = i10 + 1;
            toUtf8String[i10] = map[(b5 & 3) << 4];
            byte b6 = (byte) 61;
            toUtf8String[i11] = b6;
            toUtf8String[i11 + 1] = b6;
        } else if (length2 == 2) {
            int i12 = i2 + 1;
            byte b7 = encodeBase64[i2];
            byte b8 = encodeBase64[i12];
            int i13 = i3 + 1;
            toUtf8String[i3] = map[(b7 & 255) >> 2];
            int i14 = i13 + 1;
            toUtf8String[i13] = map[((b7 & 3) << 4) | ((b8 & 255) >> 4)];
            toUtf8String[i14] = map[(b8 & 15) << 2];
            toUtf8String[i14 + 1] = (byte) 61;
        }
        Intrinsics.checkNotNullParameter(toUtf8String, "$this$toUtf8String");
        return new String(toUtf8String, Charsets.UTF_8);
    }

    @NotNull
    /* renamed from: b */
    public C4747i mo5399b(@NotNull String algorithm) {
        Intrinsics.checkNotNullParameter(algorithm, "algorithm");
        Intrinsics.checkNotNullParameter(this, "$this$commonDigest");
        Intrinsics.checkNotNullParameter(algorithm, "algorithm");
        Intrinsics.checkNotNullParameter(algorithm, "algorithm");
        MessageDigest messageDigest = MessageDigest.getInstance(algorithm);
        byte[] input = this.f12139h;
        int mo5400c = mo5400c();
        Intrinsics.checkNotNullParameter(input, "input");
        messageDigest.update(input, 0, mo5400c);
        return new C4747i(messageDigest.digest());
    }

    /* renamed from: c */
    public int mo5400c() {
        return this.f12139h.length;
    }

    /* JADX WARN: Removed duplicated region for block: B:10:0x0030 A[RETURN, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:8:0x0032 A[ORIG_RETURN, RETURN] */
    @Override // java.lang.Comparable
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public int compareTo(p474l.C4747i r8) {
        /*
            r7 = this;
            l.i r8 = (p474l.C4747i) r8
            java.lang.String r0 = "other"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r8, r0)
            int r0 = r7.mo5400c()
            int r1 = r8.mo5400c()
            int r2 = java.lang.Math.min(r0, r1)
            r3 = 0
            r4 = 0
        L15:
            if (r4 >= r2) goto L2b
            byte r5 = r7.mo5403f(r4)
            r5 = r5 & 255(0xff, float:3.57E-43)
            byte r6 = r8.mo5403f(r4)
            r6 = r6 & 255(0xff, float:3.57E-43)
            if (r5 != r6) goto L28
            int r4 = r4 + 1
            goto L15
        L28:
            if (r5 >= r6) goto L32
            goto L30
        L2b:
            if (r0 != r1) goto L2e
            goto L33
        L2e:
            if (r0 >= r1) goto L32
        L30:
            r3 = -1
            goto L33
        L32:
            r3 = 1
        L33:
            return r3
        */
        throw new UnsupportedOperationException("Method not decompiled: p474l.C4747i.compareTo(java.lang.Object):int");
    }

    @NotNull
    /* renamed from: d */
    public String mo5401d() {
        byte[] bArr = this.f12139h;
        char[] cArr = new char[bArr.length * 2];
        int i2 = 0;
        for (byte b2 : bArr) {
            int i3 = i2 + 1;
            char[] cArr2 = C4740b.f12127a;
            cArr[i2] = cArr2[(b2 >> 4) & 15];
            i2 = i3 + 1;
            cArr[i3] = cArr2[b2 & 15];
        }
        return new String(cArr);
    }

    @NotNull
    /* renamed from: e */
    public byte[] mo5402e() {
        return this.f12139h;
    }

    public boolean equals(@Nullable Object obj) {
        if (obj == this) {
            return true;
        }
        if (obj instanceof C4747i) {
            C4747i c4747i = (C4747i) obj;
            int mo5400c = c4747i.mo5400c();
            byte[] bArr = this.f12139h;
            if (mo5400c == bArr.length && c4747i.mo5405h(0, bArr, 0, bArr.length)) {
                return true;
            }
        }
        return false;
    }

    /* renamed from: f */
    public byte mo5403f(int i2) {
        return this.f12139h[i2];
    }

    /* renamed from: g */
    public boolean mo5404g(int i2, @NotNull C4747i other, int i3, int i4) {
        Intrinsics.checkNotNullParameter(other, "other");
        return other.mo5405h(i3, this.f12139h, i2, i4);
    }

    /* renamed from: h */
    public boolean mo5405h(int i2, @NotNull byte[] other, int i3, int i4) {
        Intrinsics.checkNotNullParameter(other, "other");
        if (i2 >= 0) {
            byte[] bArr = this.f12139h;
            if (i2 <= bArr.length - i4 && i3 >= 0 && i3 <= other.length - i4 && C2354n.m2482i(bArr, i2, other, i3, i4)) {
                return true;
            }
        }
        return false;
    }

    public int hashCode() {
        int i2 = this.f12137f;
        if (i2 != 0) {
            return i2;
        }
        int hashCode = Arrays.hashCode(this.f12139h);
        this.f12137f = hashCode;
        return hashCode;
    }

    @NotNull
    /* renamed from: i */
    public C4747i mo5406i() {
        byte b2;
        int i2 = 0;
        while (true) {
            byte[] bArr = this.f12139h;
            if (i2 >= bArr.length) {
                return this;
            }
            byte b3 = bArr[i2];
            byte b4 = (byte) 65;
            if (b3 >= b4 && b3 <= (b2 = (byte) 90)) {
                byte[] copyOf = Arrays.copyOf(bArr, bArr.length);
                Intrinsics.checkNotNullExpressionValue(copyOf, "java.util.Arrays.copyOf(this, size)");
                copyOf[i2] = (byte) (b3 + 32);
                for (int i3 = i2 + 1; i3 < copyOf.length; i3++) {
                    byte b5 = copyOf[i3];
                    if (b5 >= b4 && b5 <= b2) {
                        copyOf[i3] = (byte) (b5 + 32);
                    }
                }
                return new C4747i(copyOf);
            }
            i2++;
        }
    }

    @NotNull
    /* renamed from: j */
    public String m5407j() {
        String str = this.f12138g;
        if (str != null) {
            return str;
        }
        byte[] toUtf8String = mo5402e();
        Intrinsics.checkNotNullParameter(toUtf8String, "$this$toUtf8String");
        String str2 = new String(toUtf8String, Charsets.UTF_8);
        this.f12138g = str2;
        return str2;
    }

    /* renamed from: k */
    public void mo5408k(@NotNull C4744f buffer, int i2, int i3) {
        Intrinsics.checkNotNullParameter(buffer, "buffer");
        Intrinsics.checkNotNullParameter(this, "$this$commonWrite");
        Intrinsics.checkNotNullParameter(buffer, "buffer");
        buffer.m5372Z(this.f12139h, i2, i3);
    }

    /* JADX WARN: Code restructure failed: missing block: B:101:0x0195, code lost:
    
        if (r4 == 64) goto L214;
     */
    /* JADX WARN: Code restructure failed: missing block: B:104:0x0186, code lost:
    
        if (r4 == 64) goto L214;
     */
    /* JADX WARN: Code restructure failed: missing block: B:107:0x0175, code lost:
    
        if (r4 == 64) goto L214;
     */
    /* JADX WARN: Code restructure failed: missing block: B:110:0x0162, code lost:
    
        if (r4 == 64) goto L214;
     */
    /* JADX WARN: Code restructure failed: missing block: B:112:0x01f1, code lost:
    
        if (r4 == 64) goto L214;
     */
    /* JADX WARN: Code restructure failed: missing block: B:129:0x0122, code lost:
    
        if (r4 == 64) goto L214;
     */
    /* JADX WARN: Code restructure failed: missing block: B:156:0x0119, code lost:
    
        if (r4 == 64) goto L214;
     */
    /* JADX WARN: Code restructure failed: missing block: B:158:0x0107, code lost:
    
        if (r4 == 64) goto L214;
     */
    /* JADX WARN: Code restructure failed: missing block: B:161:0x00f8, code lost:
    
        if (r4 == 64) goto L214;
     */
    /* JADX WARN: Code restructure failed: missing block: B:164:0x00e5, code lost:
    
        if (r4 == 64) goto L214;
     */
    /* JADX WARN: Code restructure failed: missing block: B:197:0x00a5, code lost:
    
        if (r4 == 64) goto L214;
     */
    /* JADX WARN: Code restructure failed: missing block: B:199:0x009a, code lost:
    
        if (r4 == 64) goto L214;
     */
    /* JADX WARN: Code restructure failed: missing block: B:202:0x0089, code lost:
    
        if (r4 == 64) goto L214;
     */
    /* JADX WARN: Code restructure failed: missing block: B:40:0x01b3, code lost:
    
        if (r4 == 64) goto L214;
     */
    /* JADX WARN: Code restructure failed: missing block: B:41:0x01f4, code lost:
    
        r5 = -1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:97:0x01ba, code lost:
    
        if (r4 == 64) goto L214;
     */
    /* JADX WARN: Code restructure failed: missing block: B:99:0x01ab, code lost:
    
        if (r4 == 64) goto L214;
     */
    @org.jetbrains.annotations.NotNull
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.String toString() {
        /*
            Method dump skipped, instructions count: 724
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p474l.C4747i.toString():java.lang.String");
    }
}
