package p403d.p404a.p405a.p407b.p408a;

import android.annotation.SuppressLint;
import android.app.Application;
import android.content.ClipData;
import android.content.ComponentName;
import android.content.ContentValues;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.res.Resources;
import android.database.Cursor;
import android.database.DatabaseUtils;
import android.database.SQLException;
import android.database.sqlite.SQLiteDatabase;
import android.graphics.BitmapFactory;
import android.graphics.Rect;
import android.graphics.drawable.BitmapDrawable;
import android.graphics.drawable.Drawable;
import android.media.MediaFormat;
import android.net.Uri;
import android.os.Bundle;
import android.os.Environment;
import android.text.TextUtils;
import android.util.Base64;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import androidx.annotation.LayoutRes;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.RequiresApi;
import androidx.annotation.VisibleForTesting;
import androidx.core.graphics.drawable.DrawableCompat;
import androidx.core.math.MathUtils;
import androidx.recyclerview.widget.RecyclerView;
import com.bumptech.glide.load.ImageHeaderParser;
import com.drake.brv.BindingAdapter;
import com.drake.brv.DefaultDecoration;
import com.drake.brv.annotaion.DividerOrientation;
import com.drake.brv.layoutmanager.HoverGridLayoutManager;
import com.drake.brv.layoutmanager.HoverLinearLayoutManager;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.io.StringReader;
import java.io.StringWriter;
import java.lang.reflect.Field;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;
import javax.crypto.Cipher;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Lambda;
import kotlin.text.StringsKt__StringNumberConversionsJVMKt;
import kotlin.text.StringsKt__StringsJVMKt;
import kotlin.text.StringsKt__StringsKt;
import org.checkerframework.checker.nullness.qual.EnsuresNonNull;
import org.conscrypt.EvpMdRef;
import org.jetbrains.annotations.NotNull;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import p005b.p085c.p088b.p089a.p090h.C1351a;
import p005b.p085c.p088b.p093d.C1360a;
import p005b.p085c.p088b.p093d.C1361b;
import p005b.p085c.p088b.p099i.C1375a;
import p005b.p085c.p088b.p100j.C1382g;
import p005b.p085c.p102c.p103a.p104a.p110e.C1403b;
import p005b.p085c.p102c.p103a.p104a.p110e.p112e.C1408b;
import p005b.p085c.p102c.p103a.p104a.p110e.p112e.InterfaceC1407a;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p139f.p140a.p142b.C1535e;
import p005b.p139f.p140a.p142b.C1540j;
import p005b.p139f.p140a.p142b.C1541k;
import p005b.p139f.p140a.p142b.C1549s;
import p005b.p139f.p140a.p142b.C1550t;
import p005b.p139f.p140a.p142b.RunnableC1531a;
import p005b.p143g.p144a.p147m.InterfaceC1577i;
import p005b.p143g.p144a.p147m.InterfaceC1578j;
import p005b.p143g.p144a.p147m.p150t.p151c0.InterfaceC1612b;
import p005b.p143g.p144a.p147m.p156v.p157c.C1719x;
import p005b.p199l.p200a.p201a.C2205l0;
import p005b.p199l.p200a.p201a.p203b1.C1937a;
import p005b.p199l.p200a.p201a.p208f1.C2003e;
import p005b.p199l.p200a.p201a.p208f1.C2054u;
import p005b.p199l.p200a.p201a.p208f1.InterfaceC2052s;
import p005b.p199l.p200a.p201a.p208f1.p215g0.C2038b;
import p005b.p199l.p200a.p201a.p208f1.p215g0.C2039c;
import p005b.p199l.p200a.p201a.p220h1.p223i.C2087a;
import p005b.p199l.p200a.p201a.p220h1.p223i.C2088b;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;
import p005b.p199l.p200a.p201a.p250p1.C2353m;
import p005b.p199l.p200a.p201a.p250p1.C2360t;

@RequiresApi(22)
/* renamed from: d.a.a.b.a.m */
/* loaded from: classes.dex */
public class C4195m {

    /* renamed from: a */
    public static volatile String f10933a;

    /* renamed from: b */
    public static volatile String f10934b;

    /* renamed from: c */
    public static List<Field> f10935c;

    /* renamed from: d */
    @SuppressLint({"StaticFieldLeak"})
    public static Application f10936d;

    /* renamed from: d.a.a.b.a.m$a */
    public class a implements InterfaceC1578j {

        /* renamed from: a */
        public final /* synthetic */ InputStream f10937a;

        public a(InputStream inputStream) {
            this.f10937a = inputStream;
        }

        @Override // p005b.p143g.p144a.p147m.InterfaceC1578j
        /* renamed from: a */
        public ImageHeaderParser.ImageType mo823a(ImageHeaderParser imageHeaderParser) {
            try {
                return imageHeaderParser.mo997b(this.f10937a);
            } finally {
                this.f10937a.reset();
            }
        }
    }

    /* renamed from: d.a.a.b.a.m$b */
    public class b implements InterfaceC1577i {

        /* renamed from: a */
        public final /* synthetic */ InputStream f10938a;

        /* renamed from: b */
        public final /* synthetic */ InterfaceC1612b f10939b;

        public b(InputStream inputStream, InterfaceC1612b interfaceC1612b) {
            this.f10938a = inputStream;
            this.f10939b = interfaceC1612b;
        }

        @Override // p005b.p143g.p144a.p147m.InterfaceC1577i
        /* renamed from: a */
        public int mo824a(ImageHeaderParser imageHeaderParser) {
            try {
                return imageHeaderParser.mo998c(this.f10938a, this.f10939b);
            } finally {
                this.f10938a.reset();
            }
        }
    }

    @Metadata(m5310d1 = {"\u0000\f\n\u0000\n\u0002\u0010\u0002\n\u0002\u0018\u0002\n\u0000\u0010\u0000\u001a\u00020\u0001*\u00020\u0002H\n¢\u0006\u0002\b\u0003"}, m5311d2 = {"<anonymous>", "", "Lcom/drake/brv/DefaultDecoration;", "invoke"}, m5312k = 3, m5313mv = {1, 6, 0}, m5315xi = 48)
    /* renamed from: d.a.a.b.a.m$c */
    public static final class c extends Lambda implements Function1<DefaultDecoration, Unit> {

        /* renamed from: c */
        public final /* synthetic */ int f10940c;

        /* renamed from: e */
        public final /* synthetic */ DividerOrientation f10941e;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public c(int i2, DividerOrientation dividerOrientation) {
            super(1);
            this.f10940c = i2;
            this.f10941e = dividerOrientation;
        }

        @Override // kotlin.jvm.functions.Function1
        public Unit invoke(DefaultDecoration defaultDecoration) {
            DefaultDecoration divider = defaultDecoration;
            Intrinsics.checkNotNullParameter(divider, "$this$divider");
            DefaultDecoration.m3943c(divider, this.f10940c, false, 2);
            divider.m3946d(this.f10941e);
            return Unit.INSTANCE;
        }
    }

    /* renamed from: A */
    public static byte[] m4755A(UUID uuid, @Nullable UUID[] uuidArr, @Nullable byte[] bArr) {
        int length = (bArr != null ? bArr.length : 0) + 32;
        if (uuidArr != null) {
            length += (uuidArr.length * 16) + 4;
        }
        ByteBuffer allocate = ByteBuffer.allocate(length);
        allocate.putInt(length);
        allocate.putInt(1886614376);
        allocate.putInt(uuidArr != null ? 16777216 : 0);
        allocate.putLong(uuid.getMostSignificantBits());
        allocate.putLong(uuid.getLeastSignificantBits());
        if (uuidArr != null) {
            allocate.putInt(uuidArr.length);
            for (UUID uuid2 : uuidArr) {
                allocate.putLong(uuid2.getMostSignificantBits());
                allocate.putLong(uuid2.getLeastSignificantBits());
            }
        }
        if (bArr != null && bArr.length != 0) {
            allocate.putInt(bArr.length);
            allocate.put(bArr);
        }
        return allocate.array();
    }

    @Nullable
    /* renamed from: A0 */
    public static C2038b m4756A0(C2003e c2003e) {
        byte[] bArr;
        Objects.requireNonNull(c2003e);
        C2360t c2360t = new C2360t(16);
        if (C2039c.m1621a(c2003e, c2360t).f4159a != 1380533830) {
            return null;
        }
        c2003e.m1565e(c2360t.f6133a, 0, 4, false);
        c2360t.m2567C(0);
        if (c2360t.m2573e() != 1463899717) {
            return null;
        }
        C2039c m1621a = C2039c.m1621a(c2003e, c2360t);
        while (m1621a.f4159a != 1718449184) {
            c2003e.m1561a((int) m1621a.f4160b, false);
            m1621a = C2039c.m1621a(c2003e, c2360t);
        }
        m4771I(m1621a.f4160b >= 16);
        c2003e.m1565e(c2360t.f6133a, 0, 16, false);
        c2360t.m2567C(0);
        int m2578j = c2360t.m2578j();
        int m2578j2 = c2360t.m2578j();
        int m2577i = c2360t.m2577i();
        int m2577i2 = c2360t.m2577i();
        int m2578j3 = c2360t.m2578j();
        int m2578j4 = c2360t.m2578j();
        int i2 = ((int) m1621a.f4160b) - 16;
        if (i2 > 0) {
            byte[] bArr2 = new byte[i2];
            c2003e.m1565e(bArr2, 0, i2, false);
            bArr = bArr2;
        } else {
            bArr = C2344d0.f6040f;
        }
        return new C2038b(m2578j, m2578j2, m2577i, m2577i2, m2578j3, m2578j4, bArr);
    }

    /* renamed from: B */
    public static String m4757B(Bundle bundle) {
        Iterator<String> it = bundle.keySet().iterator();
        if (!it.hasNext()) {
            return "Bundle {}";
        }
        StringBuilder sb = new StringBuilder(128);
        sb.append("Bundle { ");
        while (true) {
            String next = it.next();
            Object obj = bundle.get(next);
            sb.append(next);
            sb.append('=');
            if (obj instanceof Bundle) {
                sb.append(obj == bundle ? "(this Bundle)" : m4757B((Bundle) obj));
            } else {
                sb.append(C1535e.m688a(obj));
            }
            if (!it.hasNext()) {
                sb.append(" }");
                return sb.toString();
            }
            sb.append(',');
            sb.append(' ');
        }
    }

    @Nullable
    /* renamed from: B0 */
    public static com.google.android.exoplayer2.metadata.Metadata m4758B0(C2003e c2003e, boolean z) {
        C2087a c2087a;
        if (z) {
            c2087a = null;
        } else {
            int i2 = C2088b.f4389a;
            c2087a = new C2088b.a() { // from class: b.l.a.a.h1.i.a
                @Override // p005b.p199l.p200a.p201a.p220h1.p223i.C2088b.a
                /* renamed from: a */
                public final boolean mo1501a(int i3, int i4, int i5, int i6, int i7) {
                    int i8 = C2088b.f4389a;
                    return false;
                }
            };
        }
        C2360t c2360t = new C2360t(10);
        com.google.android.exoplayer2.metadata.Metadata metadata = null;
        int i3 = 0;
        while (true) {
            try {
                c2003e.m1565e(c2360t.f6133a, 0, 10, false);
                c2360t.m2567C(0);
                if (c2360t.m2587s() != 4801587) {
                    break;
                }
                c2360t.m2568D(3);
                int m2584p = c2360t.m2584p();
                int i4 = m2584p + 10;
                if (metadata == null) {
                    byte[] bArr = new byte[i4];
                    System.arraycopy(c2360t.f6133a, 0, bArr, 0, 10);
                    c2003e.m1565e(bArr, 10, m2584p, false);
                    metadata = new C2088b(c2087a).m1734c(bArr, i4);
                } else {
                    c2003e.m1561a(m2584p, false);
                }
                i3 += i4;
            } catch (EOFException unused) {
            }
        }
        c2003e.f3791f = 0;
        c2003e.m1561a(i3, false);
        if (metadata == null || metadata.f9273c.length == 0) {
            return null;
        }
        return metadata;
    }

    @NotNull
    /* renamed from: C */
    public static final int[] m4759C(@NotNull View view, @org.jetbrains.annotations.Nullable String str, @org.jetbrains.annotations.Nullable String str2, int i2, int i3, int i4, int i5) {
        Float floatOrNull;
        Float floatOrNull2;
        Intrinsics.checkNotNullParameter(view, "<this>");
        int[] iArr = {-1, -1};
        if (TextUtils.isEmpty(str) && TextUtils.isEmpty(str2)) {
            return iArr;
        }
        if (!TextUtils.isEmpty(str)) {
            Intrinsics.checkNotNull(str);
            if (StringsKt__StringsKt.contains((CharSequence) str, (CharSequence) "sw", true)) {
                Float floatOrNull3 = StringsKt__StringNumberConversionsJVMKt.toFloatOrNull(StringsKt__StringsJVMKt.replace(str, "sw", "", true));
                if (floatOrNull3 != null) {
                    floatOrNull3.floatValue();
                    float floatValue = floatOrNull3.floatValue();
                    Intrinsics.checkNotNullParameter(view, "<this>");
                    iArr[0] = (int) (floatValue * (view.getContext().getResources().getDisplayMetrics().widthPixels - i4));
                }
            } else if (StringsKt__StringsKt.contains((CharSequence) str, (CharSequence) "pw", true) && (floatOrNull2 = StringsKt__StringNumberConversionsJVMKt.toFloatOrNull(StringsKt__StringsJVMKt.replace(str, "pw", "", true))) != null) {
                floatOrNull2.floatValue();
                iArr[0] = (int) (floatOrNull2.floatValue() * (i2 - i4));
            }
        }
        if (!TextUtils.isEmpty(str2)) {
            Intrinsics.checkNotNull(str2);
            if (StringsKt__StringsKt.contains((CharSequence) str2, (CharSequence) "sh", true)) {
                Float floatOrNull4 = StringsKt__StringNumberConversionsJVMKt.toFloatOrNull(StringsKt__StringsJVMKt.replace(str2, "sh", "", true));
                if (floatOrNull4 != null) {
                    floatOrNull4.floatValue();
                    float floatValue2 = floatOrNull4.floatValue();
                    Intrinsics.checkNotNullParameter(view, "<this>");
                    iArr[1] = (int) (floatValue2 * (view.getContext().getResources().getDisplayMetrics().heightPixels - i5));
                }
            } else if (StringsKt__StringsKt.contains((CharSequence) str2, (CharSequence) "ph", true) && (floatOrNull = StringsKt__StringNumberConversionsJVMKt.toFloatOrNull(StringsKt__StringsJVMKt.replace(str2, "ph", "", true))) != null) {
                floatOrNull.floatValue();
                iArr[1] = (int) (floatOrNull.floatValue() * (i3 - i5));
            }
        }
        return iArr;
    }

    /* JADX WARN: Removed duplicated region for block: B:10:0x003a A[EDGE_INSN: B:10:0x003a->B:11:0x003a BREAK  A[LOOP:0: B:2:0x0001->B:9:0x0038], SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:9:0x0038 A[LOOP:0: B:2:0x0001->B:9:0x0038, LOOP_END] */
    /* renamed from: C0 */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static int m4760C0(p005b.p199l.p200a.p201a.p208f1.C2003e r9, byte[] r10, int r11, int r12) {
        /*
            r0 = 0
        L1:
            if (r0 >= r12) goto L3a
            int r1 = r11 + r0
            int r5 = r12 - r0
            r9.m1563c(r5)
            int r2 = r9.f3792g
            int r4 = r9.f3791f
            int r2 = r2 - r4
            r8 = -1
            if (r2 != 0) goto L25
            byte[] r3 = r9.f3790e
            r6 = 0
            r7 = 1
            r2 = r9
            int r2 = r2.m1567g(r3, r4, r5, r6, r7)
            if (r2 != r8) goto L1f
            r2 = -1
            goto L35
        L1f:
            int r3 = r9.f3792g
            int r3 = r3 + r2
            r9.f3792g = r3
            goto L29
        L25:
            int r2 = java.lang.Math.min(r5, r2)
        L29:
            byte[] r3 = r9.f3790e
            int r4 = r9.f3791f
            java.lang.System.arraycopy(r3, r4, r10, r1, r2)
            int r1 = r9.f3791f
            int r1 = r1 + r2
            r9.f3791f = r1
        L35:
            if (r2 != r8) goto L38
            goto L3a
        L38:
            int r0 = r0 + r2
            goto L1
        L3a:
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: p403d.p404a.p405a.p407b.p408a.C4195m.m4760C0(b.l.a.a.f1.e, byte[], int, int):int");
    }

    /* renamed from: D */
    public static void m4761D(boolean z, Object obj) {
        if (!z) {
            throw new IllegalArgumentException(String.valueOf(obj));
        }
    }

    /* renamed from: D0 */
    public static int m4762D0(C2360t c2360t) {
        int i2 = 0;
        while (c2360t.m2569a() != 0) {
            int m2585q = c2360t.m2585q();
            i2 += m2585q;
            if (m2585q != 255) {
                return i2;
            }
        }
        return -1;
    }

    /* renamed from: E */
    public static void m4763E(boolean z, @NonNull String str) {
        if (!z) {
            throw new IllegalArgumentException(str);
        }
    }

    /* renamed from: E0 */
    public static long m4764E0(C2360t c2360t, int i2, int i3) {
        c2360t.m2567C(i2);
        if (c2360t.m2569a() < 5) {
            return -9223372036854775807L;
        }
        int m2573e = c2360t.m2573e();
        if ((8388608 & m2573e) != 0 || ((2096896 & m2573e) >> 8) != i3) {
            return -9223372036854775807L;
        }
        if (((m2573e & 32) != 0) && c2360t.m2585q() >= 7 && c2360t.m2569a() >= 7) {
            if ((c2360t.m2585q() & 16) == 16) {
                System.arraycopy(c2360t.f6133a, c2360t.f6134b, new byte[6], 0, 6);
                c2360t.f6134b += 6;
                return ((r0[0] & 255) << 25) | ((r0[1] & 255) << 17) | ((r0[2] & 255) << 9) | ((r0[3] & 255) << 1) | ((r0[4] & 255) >> 7);
            }
        }
        return -9223372036854775807L;
    }

    /* renamed from: F */
    public static void m4765F(boolean z) {
        if (!z) {
            throw new IllegalArgumentException();
        }
    }

    /* renamed from: F0 */
    public static C2353m.a m4766F0(C2360t c2360t) {
        c2360t.m2568D(1);
        int m2587s = c2360t.m2587s();
        long j2 = c2360t.f6134b + m2587s;
        int i2 = m2587s / 18;
        long[] jArr = new long[i2];
        long[] jArr2 = new long[i2];
        int i3 = 0;
        while (true) {
            if (i3 >= i2) {
                break;
            }
            long m2579k = c2360t.m2579k();
            if (m2579k == -1) {
                jArr = Arrays.copyOf(jArr, i3);
                jArr2 = Arrays.copyOf(jArr2, i3);
                break;
            }
            jArr[i3] = m2579k;
            jArr2[i3] = c2360t.m2579k();
            c2360t.m2568D(2);
            i3++;
        }
        c2360t.m2568D((int) (j2 - c2360t.f6134b));
        return new C2353m.a(jArr, jArr2);
    }

    /* renamed from: G */
    public static int m4767G(int i2, int i3, int i4) {
        if (i2 < i3 || i2 >= i4) {
            throw new IndexOutOfBoundsException();
        }
        return i2;
    }

    /* renamed from: G0 */
    public static C2054u m4768G0(C2360t c2360t, boolean z, boolean z2) {
        if (z) {
            m4780M0(3, c2360t, false);
        }
        String m2582n = c2360t.m2582n((int) c2360t.m2576h());
        int length = m2582n.length() + 11;
        long m2576h = c2360t.m2576h();
        String[] strArr = new String[(int) m2576h];
        int i2 = length + 4;
        for (int i3 = 0; i3 < m2576h; i3++) {
            strArr[i3] = c2360t.m2582n((int) c2360t.m2576h());
            i2 = i2 + 4 + strArr[i3].length();
        }
        if (z2 && (c2360t.m2585q() & 1) == 0) {
            throw new C2205l0("framing bit expected to be set");
        }
        return new C2054u(m2582n, strArr, i2 + 1);
    }

    @EnsuresNonNull({"#1"})
    /* renamed from: H */
    public static String m4769H(@Nullable String str) {
        if (TextUtils.isEmpty(str)) {
            throw new IllegalArgumentException();
        }
        return str;
    }

    /* renamed from: H0 */
    public static void m4770H0(MediaFormat mediaFormat, List<byte[]> list) {
        for (int i2 = 0; i2 < list.size(); i2++) {
            mediaFormat.setByteBuffer(C1499a.m626l("csd-", i2), ByteBuffer.wrap(list.get(i2)));
        }
    }

    /* renamed from: I */
    public static void m4771I(boolean z) {
        if (!z) {
            throw new IllegalStateException();
        }
    }

    /* renamed from: I0 */
    public static void m4772I0(SQLiteDatabase sQLiteDatabase, int i2, String str, int i3) {
        try {
            sQLiteDatabase.execSQL("CREATE TABLE IF NOT EXISTS ExoPlayerVersions (feature INTEGER NOT NULL,instance_uid TEXT NOT NULL,version INTEGER NOT NULL,PRIMARY KEY (feature, instance_uid))");
            ContentValues contentValues = new ContentValues();
            contentValues.put("feature", Integer.valueOf(i2));
            contentValues.put("instance_uid", str);
            contentValues.put("version", Integer.valueOf(i3));
            sQLiteDatabase.replaceOrThrow("ExoPlayerVersions", null, contentValues);
        } catch (SQLException e2) {
            throw new C1937a(e2);
        }
    }

    /* renamed from: J */
    public static void m4773J(boolean z, Object obj) {
        if (!z) {
            throw new IllegalStateException(String.valueOf(obj));
        }
    }

    @NotNull
    /* renamed from: J0 */
    public static final BindingAdapter m4774J0(@NotNull RecyclerView recyclerView, @NotNull Function2<? super BindingAdapter, ? super RecyclerView, Unit> block) {
        Intrinsics.checkNotNullParameter(recyclerView, "<this>");
        Intrinsics.checkNotNullParameter(block, "block");
        BindingAdapter bindingAdapter = new BindingAdapter();
        block.invoke(bindingAdapter, recyclerView);
        recyclerView.setAdapter(bindingAdapter);
        return bindingAdapter;
    }

    @EnsuresNonNull({"#1"})
    /* renamed from: K */
    public static <T> T m4775K(@Nullable T t) {
        if (t != null) {
            return t;
        }
        throw new IllegalStateException();
    }

    @VisibleForTesting
    /* renamed from: K0 */
    public static boolean m4776K0(SQLiteDatabase sQLiteDatabase, String str) {
        return DatabaseUtils.queryNumEntries(sQLiteDatabase, "sqlite_master", "tbl_name = ?", new String[]{str}) > 0;
    }

    /* renamed from: L */
    public static void m4777L(float f2, float f3, float f4) {
        if (f2 >= f3) {
            throw new IllegalArgumentException("Minimum zoom has to be less than Medium zoom. Call setMinimumZoom() with a more appropriate value");
        }
        if (f3 >= f4) {
            throw new IllegalArgumentException("Medium zoom has to be less than Maximum zoom. Call setMaximumZoom() with a more appropriate value");
        }
    }

    @org.jetbrains.annotations.Nullable
    /* renamed from: L0 */
    public static final Drawable m4778L0(@org.jetbrains.annotations.Nullable Drawable drawable, int i2) {
        Drawable mutate = DrawableCompat.wrap(drawable).mutate();
        Intrinsics.checkNotNullExpressionValue(mutate, "wrap(this).mutate()");
        DrawableCompat.setTint(mutate, i2);
        return mutate;
    }

    /* renamed from: M */
    public static void m4779M(final View view, long j2, final Function1 block, int i2) {
        if ((i2 & 1) != 0) {
            j2 = 600;
        }
        Intrinsics.checkNotNullParameter(view, "<this>");
        Intrinsics.checkNotNullParameter(block, "block");
        view.setTag(1123461123, Long.valueOf(j2));
        view.setOnClickListener(new View.OnClickListener() { // from class: b.b.a.a.a.n.a
            @Override // android.view.View.OnClickListener
            public final void onClick(View view2) {
                long j3;
                long j4;
                boolean z;
                View this_clickWithTrigger = view;
                Function1 block2 = block;
                Intrinsics.checkNotNullParameter(this_clickWithTrigger, "$this_clickWithTrigger");
                Intrinsics.checkNotNullParameter(block2, "$block");
                long currentTimeMillis = System.currentTimeMillis();
                if (this_clickWithTrigger.getTag(1123460103) != null) {
                    Object tag = this_clickWithTrigger.getTag(1123460103);
                    Objects.requireNonNull(tag, "null cannot be cast to non-null type kotlin.Long");
                    j3 = ((Long) tag).longValue();
                } else {
                    j3 = -601;
                }
                long j5 = currentTimeMillis - j3;
                if (this_clickWithTrigger.getTag(1123461123) != null) {
                    Object tag2 = this_clickWithTrigger.getTag(1123461123);
                    Objects.requireNonNull(tag2, "null cannot be cast to non-null type kotlin.Long");
                    j4 = ((Long) tag2).longValue();
                } else {
                    j4 = 600;
                }
                if (j5 >= j4) {
                    z = true;
                    this_clickWithTrigger.setTag(1123460103, Long.valueOf(currentTimeMillis));
                } else {
                    z = false;
                }
                if (z) {
                    Objects.requireNonNull(view2, "null cannot be cast to non-null type T of com.chad.library.adapter.base.util.ViewClickDelayKt.clickWithTrigger$lambda-1");
                    block2.invoke(view2);
                }
            }
        });
    }

    /* renamed from: M0 */
    public static boolean m4780M0(int i2, C2360t c2360t, boolean z) {
        if (c2360t.m2569a() < 7) {
            if (z) {
                return false;
            }
            StringBuilder m586H = C1499a.m586H("too short header: ");
            m586H.append(c2360t.m2569a());
            throw new C2205l0(m586H.toString());
        }
        if (c2360t.m2585q() != i2) {
            if (z) {
                return false;
            }
            StringBuilder m586H2 = C1499a.m586H("expected header type ");
            m586H2.append(Integer.toHexString(i2));
            throw new C2205l0(m586H2.toString());
        }
        if (c2360t.m2585q() == 118 && c2360t.m2585q() == 111 && c2360t.m2585q() == 114 && c2360t.m2585q() == 98 && c2360t.m2585q() == 105 && c2360t.m2585q() == 115) {
            return true;
        }
        if (z) {
            return false;
        }
        throw new C2205l0("expected characters 'vorbis'");
    }

    /* renamed from: N */
    public static void m4781N(long j2, C2360t c2360t, InterfaceC2052s[] interfaceC2052sArr) {
        while (true) {
            if (c2360t.m2569a() <= 1) {
                return;
            }
            int m4762D0 = m4762D0(c2360t);
            int m4762D02 = m4762D0(c2360t);
            int i2 = c2360t.f6134b + m4762D02;
            if (m4762D02 == -1 || m4762D02 > c2360t.m2569a()) {
                i2 = c2360t.f6135c;
            } else if (m4762D0 == 4 && m4762D02 >= 8) {
                int m2585q = c2360t.m2585q();
                int m2590v = c2360t.m2590v();
                int m2573e = m2590v == 49 ? c2360t.m2573e() : 0;
                int m2585q2 = c2360t.m2585q();
                if (m2590v == 47) {
                    c2360t.m2568D(1);
                }
                boolean z = m2585q == 181 && (m2590v == 49 || m2590v == 47) && m2585q2 == 3;
                if (m2590v == 49) {
                    z &= m2573e == 1195456820;
                }
                if (z) {
                    m4782O(j2, c2360t, interfaceC2052sArr);
                }
            }
            c2360t.m2567C(i2);
        }
    }

    /* renamed from: O */
    public static void m4782O(long j2, C2360t c2360t, InterfaceC2052s[] interfaceC2052sArr) {
        int m2585q = c2360t.m2585q();
        if ((m2585q & 64) != 0) {
            c2360t.m2568D(1);
            int i2 = (m2585q & 31) * 3;
            int i3 = c2360t.f6134b;
            for (InterfaceC2052s interfaceC2052s : interfaceC2052sArr) {
                c2360t.m2567C(i3);
                interfaceC2052s.mo1613b(c2360t, i2);
                interfaceC2052s.mo1614c(j2, 1, i2, 0, null);
            }
        }
    }

    @NotNull
    /* renamed from: P */
    public static final RecyclerView m4783P(@NotNull RecyclerView recyclerView, @NotNull Function1<? super DefaultDecoration, Unit> block) {
        Intrinsics.checkNotNullParameter(recyclerView, "<this>");
        Intrinsics.checkNotNullParameter(block, "block");
        Context context = recyclerView.getContext();
        Intrinsics.checkNotNullExpressionValue(context, "context");
        DefaultDecoration defaultDecoration = new DefaultDecoration(context);
        block.invoke(defaultDecoration);
        recyclerView.addItemDecoration(defaultDecoration);
        return recyclerView;
    }

    @NotNull
    /* renamed from: Q */
    public static final RecyclerView m4784Q(@NotNull RecyclerView recyclerView, int i2, @NotNull DividerOrientation orientation) {
        Intrinsics.checkNotNullParameter(recyclerView, "<this>");
        Intrinsics.checkNotNullParameter(orientation, "orientation");
        m4783P(recyclerView, new c(i2, orientation));
        return recyclerView;
    }

    /* renamed from: R */
    public static int m4785R(float f2) {
        return (int) ((f2 * Resources.getSystem().getDisplayMetrics().density) + 0.5f);
    }

    /* renamed from: S */
    public static String m4786S(String str) {
        String[] split = str.split("=");
        if (split.length <= 1) {
            return null;
        }
        String str2 = split[1];
        return str2.contains("\"") ? str2.replaceAll("\"", "") : str2;
    }

    /* renamed from: T */
    public static String m4787T(String str, String str2) {
        if (str == null) {
            str = "";
        }
        if (str2 == null) {
            str2 = "";
        }
        return String.format("[%s][%s]", str, str2);
    }

    /* renamed from: U */
    public static String m4788U(String str) {
        try {
            if (m4822o(str)) {
                return null;
            }
            MessageDigest messageDigest = MessageDigest.getInstance(EvpMdRef.SHA1.JCA_NAME);
            messageDigest.update(str.getBytes("UTF-8"));
            byte[] digest = messageDigest.digest();
            StringBuilder sb = new StringBuilder();
            for (byte b2 : digest) {
                sb.append(String.format("%02x", Byte.valueOf(b2)));
            }
            return sb.toString();
        } catch (Exception unused) {
            return null;
        }
    }

    /* renamed from: V */
    public static final int m4789V(float f2, int i2, int i3) {
        float clamp = MathUtils.clamp(f2, 0.0f, 1.0f);
        return ((((i2 >> 24) & 255) + ((int) ((((i3 >> 24) & 255) - r0) * clamp))) << 24) | ((((i2 >> 16) & 255) + ((int) ((((i3 >> 16) & 255) - r1) * clamp))) << 16) | ((((i2 >> 8) & 255) + ((int) ((((i3 >> 8) & 255) - r2) * clamp))) << 8) | ((i2 & 255) + ((int) (clamp * ((i3 & 255) - r7))));
    }

    /* renamed from: W */
    public static final int m4790W(int i2) {
        return View.MeasureSpec.makeMeasureSpec(i2, 1073741824);
    }

    /* renamed from: X */
    public static String m4791X(String str) {
        try {
            byte[] array = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(str.length()).array();
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream(str.length());
            GZIPOutputStream gZIPOutputStream = new GZIPOutputStream(byteArrayOutputStream);
            gZIPOutputStream.write(str.getBytes("UTF-8"));
            gZIPOutputStream.close();
            byteArrayOutputStream.close();
            byte[] bArr = new byte[byteArrayOutputStream.toByteArray().length + 4];
            System.arraycopy(array, 0, bArr, 0, 4);
            System.arraycopy(byteArrayOutputStream.toByteArray(), 0, bArr, 4, byteArrayOutputStream.toByteArray().length);
            return Base64.encodeToString(bArr, 8);
        } catch (Exception unused) {
            return "";
        }
    }

    /* renamed from: Y */
    public static Application m4792Y() {
        Object invoke;
        Application application = f10936d;
        if (application != null) {
            return application;
        }
        C1549s c1549s = C1549s.f1795c;
        Objects.requireNonNull(c1549s);
        Application application2 = null;
        try {
            Class<?> cls = Class.forName("android.app.ActivityThread");
            Object m720c = c1549s.m720c();
            if (m720c != null && (invoke = cls.getMethod("getApplication", new Class[0]).invoke(m720c, new Object[0])) != null) {
                application2 = (Application) invoke;
            }
        } catch (Exception e2) {
            e2.printStackTrace();
        }
        m4827q0(application2);
        Objects.requireNonNull(f10936d, "reflect failed.");
        C1550t.m725b();
        return f10936d;
    }

    @NotNull
    /* renamed from: Z */
    public static final BindingAdapter m4793Z(@NotNull RecyclerView recyclerView) {
        Intrinsics.checkNotNullParameter(recyclerView, "<this>");
        RecyclerView.Adapter adapter = recyclerView.getAdapter();
        BindingAdapter bindingAdapter = adapter instanceof BindingAdapter ? (BindingAdapter) adapter : null;
        Objects.requireNonNull(bindingAdapter, "RecyclerView without BindingAdapter");
        return bindingAdapter;
    }

    /* renamed from: a */
    public static synchronized int m4794a(Context context, String str) {
        synchronized (C4195m.class) {
            m4787T("RecordPref", "stat remove " + str);
            if (context != null && !TextUtils.isEmpty(str)) {
                C1351a m4836v = m4836v(context);
                if (m4836v.f1181a.isEmpty()) {
                    return 0;
                }
                try {
                    ArrayList arrayList = new ArrayList();
                    for (Map.Entry<String, String> entry : m4836v.f1181a.entrySet()) {
                        if (str.equals(entry.getValue())) {
                            arrayList.add(entry.getKey());
                        }
                    }
                    Iterator it = arrayList.iterator();
                    while (it.hasNext()) {
                        m4836v.f1181a.remove((String) it.next());
                    }
                    m4810i(context, m4836v);
                    return arrayList.size();
                } catch (Throwable th) {
                    m4816l(th);
                    int size = m4836v.f1181a.size();
                    m4810i(context, new C1351a());
                    return size;
                }
            }
            return 0;
        }
    }

    @org.jetbrains.annotations.Nullable
    /* renamed from: a0 */
    public static final View m4795a0(@NotNull View view, int i2) {
        Intrinsics.checkNotNullParameter(view, "<this>");
        if (!(view instanceof ViewGroup)) {
            return view;
        }
        boolean z = false;
        if (i2 >= 0 && i2 < ((ViewGroup) view).getChildCount()) {
            z = true;
        }
        if (z) {
            return ((ViewGroup) view).getChildAt(i2);
        }
        return null;
    }

    /* renamed from: b */
    public static Drawable m4796b(String str, Context context) {
        ByteArrayInputStream byteArrayInputStream;
        try {
            byteArrayInputStream = new ByteArrayInputStream(C1360a.m388b(str));
            try {
                BitmapFactory.Options options = new BitmapFactory.Options();
                options.inDensity = 480;
                options.inTargetDensity = context.getResources().getDisplayMetrics().densityDpi;
                BitmapDrawable bitmapDrawable = new BitmapDrawable(context.getResources(), BitmapFactory.decodeStream(byteArrayInputStream, null, options));
                try {
                    byteArrayInputStream.close();
                } catch (Throwable unused) {
                }
                return bitmapDrawable;
            } catch (Throwable unused2) {
                if (byteArrayInputStream == null) {
                    return null;
                }
                try {
                    byteArrayInputStream.close();
                    return null;
                } catch (Throwable unused3) {
                    return null;
                }
            }
        } catch (Throwable unused4) {
            byteArrayInputStream = null;
        }
    }

    /* renamed from: b0 */
    public static final float m4797b0() {
        return Resources.getSystem().getDisplayMetrics().density;
    }

    /* renamed from: c */
    public static Class<?> m4798c(Type type) {
        while (!(type instanceof Class)) {
            if (!(type instanceof ParameterizedType)) {
                throw new IllegalArgumentException("TODO");
            }
            type = ((ParameterizedType) type).getRawType();
        }
        return (Class) type;
    }

    /* renamed from: c0 */
    public static final int m4799c0(@NotNull Number dp) {
        Intrinsics.checkNotNullParameter(dp, "$this$dp");
        float floatValue = dp.floatValue();
        Intrinsics.checkNotNullExpressionValue(Resources.getSystem(), "Resources.getSystem()");
        return (int) ((floatValue * r0.getDisplayMetrics().density) + 0.5d);
    }

    /* renamed from: d */
    public static String m4800d() {
        String str;
        try {
            str = C1375a.f1260a.getApplicationContext().getPackageName();
        } catch (Throwable th) {
            m4816l(th);
            str = "";
        }
        return (str + "0000000000000000000000000000").substring(0, 24);
    }

    /* renamed from: d0 */
    public static final int m4801d0() {
        return (int) m4797b0();
    }

    /* renamed from: e */
    public static synchronized String m4802e(Context context, String str, String str2) {
        synchronized (C4195m.class) {
            m4787T("RecordPref", "stat append " + str2 + " , " + str);
            if (TextUtils.isEmpty(str)) {
                return null;
            }
            if (TextUtils.isEmpty(str2)) {
                str2 = UUID.randomUUID().toString();
            }
            C1351a m4836v = m4836v(context);
            if (m4836v.f1181a.size() > 20) {
                m4836v.f1181a.clear();
            }
            m4836v.f1181a.put(str2, str);
            m4810i(context, m4836v);
            return str2;
        }
    }

    @NotNull
    /* renamed from: e0 */
    public static final View m4803e0(@NotNull ViewGroup viewGroup, @LayoutRes int i2) {
        Intrinsics.checkNotNullParameter(viewGroup, "<this>");
        View inflate = LayoutInflater.from(viewGroup.getContext()).inflate(i2, viewGroup, false);
        Intrinsics.checkNotNullExpressionValue(inflate, "from(this.context).inflate(layoutResId, this, false)");
        return inflate;
    }

    /* renamed from: f */
    public static String m4804f(String str, String str2) {
        File file;
        StringBuilder sb = new StringBuilder();
        BufferedReader bufferedReader = null;
        try {
            try {
                file = new File(str, str2);
            } catch (Throwable unused) {
            }
        } catch (IOException unused2) {
        } catch (Throwable th) {
            th = th;
        }
        if (!file.exists()) {
            return null;
        }
        BufferedReader bufferedReader2 = new BufferedReader(new InputStreamReader(new FileInputStream(file), "UTF-8"));
        while (true) {
            try {
                String readLine = bufferedReader2.readLine();
                if (readLine == null) {
                    break;
                }
                sb.append(readLine);
            } catch (IOException unused3) {
                bufferedReader = bufferedReader2;
                if (bufferedReader != null) {
                    bufferedReader.close();
                }
                return sb.toString();
            } catch (Throwable th2) {
                th = th2;
                bufferedReader = bufferedReader2;
                if (bufferedReader != null) {
                    try {
                        bufferedReader.close();
                    } catch (Throwable unused4) {
                    }
                }
                throw th;
            }
        }
        bufferedReader2.close();
        return sb.toString();
    }

    /* renamed from: f0 */
    public static final void m4805f0(View view, View view2, Rect rect) {
        Object parent = view.getParent();
        if (parent instanceof View) {
            rect.left = view.getLeft() + rect.left;
            rect.top = view.getTop() + rect.top;
            if (Intrinsics.areEqual(parent, view2)) {
                return;
            }
            m4805f0((View) parent, view2, rect);
        }
    }

    /* renamed from: g */
    public static String m4806g(String str, String str2, boolean z) {
        Context context = C1375a.f1260a;
        String str3 = null;
        if (context == null) {
            return null;
        }
        String string = context.getSharedPreferences(str, 0).getString(str2, null);
        if (!TextUtils.isEmpty(string) && z) {
            try {
                str3 = new String(C1361b.m392b(m4800d(), C1360a.m388b(string), string));
            } catch (Exception unused) {
            }
            if (TextUtils.isEmpty(str3)) {
                m4787T("mspl", "tid_str: pref failed");
            }
            string = str3;
        }
        m4787T("mspl", "tid_str: from local");
        return string;
    }

    /* renamed from: g0 */
    public static int m4807g0(@NonNull List<ImageHeaderParser> list, @Nullable InputStream inputStream, @NonNull InterfaceC1612b interfaceC1612b) {
        if (inputStream == null) {
            return -1;
        }
        if (!inputStream.markSupported()) {
            inputStream = new C1719x(inputStream, interfaceC1612b);
        }
        inputStream.mark(5242880);
        return m4809h0(list, new b(inputStream, interfaceC1612b));
    }

    /* renamed from: h */
    public static String m4808h(Map<String, String> map, String str, String str2) {
        String str3;
        return (map == null || (str3 = map.get(str)) == null) ? str2 : str3;
    }

    /* renamed from: h0 */
    public static int m4809h0(@NonNull List<ImageHeaderParser> list, InterfaceC1577i interfaceC1577i) {
        int size = list.size();
        for (int i2 = 0; i2 < size; i2++) {
            int mo824a = interfaceC1577i.mo824a(list.get(i2));
            if (mo824a != -1) {
                return mo824a;
            }
        }
        return -1;
    }

    /* renamed from: i */
    public static synchronized void m4810i(Context context, C1351a c1351a) {
        synchronized (C4195m.class) {
            try {
                C1382g.m435b(null, context, "alipay_cashier_statistic_record", c1351a.m359a());
            } catch (Throwable th) {
                m4816l(th);
            }
        }
    }

    @NonNull
    /* renamed from: i0 */
    public static ImageHeaderParser.ImageType m4811i0(@NonNull List<ImageHeaderParser> list, @Nullable InputStream inputStream, @NonNull InterfaceC1612b interfaceC1612b) {
        if (inputStream == null) {
            return ImageHeaderParser.ImageType.UNKNOWN;
        }
        if (!inputStream.markSupported()) {
            inputStream = new C1719x(inputStream, interfaceC1612b);
        }
        inputStream.mark(5242880);
        return m4813j0(list, new a(inputStream));
    }

    /* renamed from: j */
    public static void m4812j(Context context, String str, Map<String, String> map) {
        SharedPreferences.Editor edit = context.getSharedPreferences(str, 0).edit();
        if (edit != null) {
            for (String str2 : map.keySet()) {
                edit.putString(str2, map.get(str2));
            }
            edit.commit();
        }
    }

    @NonNull
    /* renamed from: j0 */
    public static ImageHeaderParser.ImageType m4813j0(@NonNull List<ImageHeaderParser> list, InterfaceC1578j interfaceC1578j) {
        int size = list.size();
        for (int i2 = 0; i2 < size; i2++) {
            ImageHeaderParser.ImageType mo823a = interfaceC1578j.mo823a(list.get(i2));
            if (mo823a != ImageHeaderParser.ImageType.UNKNOWN) {
                return mo823a;
            }
        }
        return ImageHeaderParser.ImageType.UNKNOWN;
    }

    /* renamed from: k */
    public static void m4814k(String str, String str2, String str3, boolean z) {
        String str4;
        Context context = C1375a.f1260a;
        if (context == null) {
            return;
        }
        SharedPreferences sharedPreferences = context.getSharedPreferences(str, 0);
        if (z) {
            String m4800d = m4800d();
            try {
                str4 = C1360a.m387a(C1361b.m391a(m4800d, str3.getBytes(), str3));
            } catch (Exception unused) {
                str4 = null;
            }
            if (TextUtils.isEmpty(str4)) {
                String.format("LocalPreference::putLocalPreferences failed %s，%s", str3, m4800d);
            }
            str3 = str4;
        }
        sharedPreferences.edit().putString(str2, str3).apply();
    }

    /* renamed from: k0 */
    public static int m4815k0(SQLiteDatabase sQLiteDatabase, int i2, String str) {
        try {
            if (!m4776K0(sQLiteDatabase, "ExoPlayerVersions")) {
                return -1;
            }
            Cursor query = sQLiteDatabase.query("ExoPlayerVersions", new String[]{"version"}, "feature = ? AND instance_uid = ?", new String[]{Integer.toString(i2), str}, null, null, null);
            try {
                if (query.getCount() == 0) {
                    query.close();
                    return -1;
                }
                query.moveToNext();
                int i3 = query.getInt(0);
                query.close();
                return i3;
            } finally {
            }
        } catch (SQLException e2) {
            throw new C1937a(e2);
        }
    }

    /* renamed from: l */
    public static void m4816l(Throwable th) {
        try {
            StringWriter stringWriter = new StringWriter();
            th.printStackTrace(new PrintWriter(stringWriter));
            stringWriter.toString();
        } catch (Throwable unused) {
        }
    }

    /* renamed from: l0 */
    public static final int m4817l0(@NotNull View view) {
        Intrinsics.checkNotNullParameter(view, "<this>");
        return (view.getMeasuredHeight() - view.getPaddingTop()) - view.getPaddingBottom();
    }

    /* renamed from: m */
    public static boolean m4818m() {
        String externalStorageState = Environment.getExternalStorageState();
        if (externalStorageState == null || externalStorageState.length() <= 0) {
            return false;
        }
        return (externalStorageState.equals("mounted") || externalStorageState.equals("mounted_ro")) && Environment.getExternalStorageDirectory() != null;
    }

    /* renamed from: m0 */
    public static final int m4819m0(@NotNull View view) {
        Intrinsics.checkNotNullParameter(view, "<this>");
        return (view.getMeasuredWidth() - view.getPaddingLeft()) - view.getPaddingRight();
    }

    /* renamed from: n */
    public static boolean m4820n(Class<?> cls) {
        return cls.isPrimitive() || cls.equals(String.class) || cls.equals(Integer.class) || cls.equals(Long.class) || cls.equals(Double.class) || cls.equals(Float.class) || cls.equals(Boolean.class) || cls.equals(Short.class) || cls.equals(Character.class) || cls.equals(Byte.class) || cls.equals(Void.class);
    }

    /* renamed from: n0 */
    public static RecyclerView m4821n0(RecyclerView recyclerView, int i2, int i3, boolean z, boolean z2, int i4) {
        if ((i4 & 1) != 0) {
            i2 = 1;
        }
        if ((i4 & 2) != 0) {
            i3 = 1;
        }
        if ((i4 & 4) != 0) {
            z = false;
        }
        if ((i4 & 8) != 0) {
            z2 = true;
        }
        Intrinsics.checkNotNullParameter(recyclerView, "<this>");
        HoverGridLayoutManager hoverGridLayoutManager = new HoverGridLayoutManager(recyclerView.getContext(), i2, i3, z);
        hoverGridLayoutManager.f8980k = z2;
        recyclerView.setLayoutManager(hoverGridLayoutManager);
        return recyclerView;
    }

    /* renamed from: o */
    public static boolean m4822o(String str) {
        int length;
        if (str != null && (length = str.length()) != 0) {
            for (int i2 = 0; i2 < length; i2++) {
                if (!Character.isWhitespace(str.charAt(i2))) {
                    return false;
                }
            }
        }
        return true;
    }

    /* renamed from: o0 */
    public static final boolean m4823o0(int i2, int i3) {
        if (i2 != 0 && i3 != 0) {
            if (i2 == 0 && i3 == 0) {
                return true;
            }
            if (((i2 > 0 && i3 > 0) || (i2 < 0 && i3 < 0)) && (i2 & i3) == i3) {
                return true;
            }
        }
        return false;
    }

    /* renamed from: p */
    public static boolean m4824p(String str, String str2) {
        return str == null ? str2 == null : str.equals(str2);
    }

    /* renamed from: p0 */
    public static int m4825p0(int i2) {
        int i3 = 0;
        while (i2 > 0) {
            i3++;
            i2 >>>= 1;
        }
        return i3;
    }

    /* renamed from: q */
    public static byte[] m4826q(Cipher cipher, String str) {
        SecureRandom secureRandom = new SecureRandom();
        int blockSize = cipher.getBlockSize();
        if (TextUtils.isEmpty(str)) {
            str = String.valueOf(secureRandom.nextDouble());
        }
        int i2 = blockSize * 2;
        byte[] bArr = new byte[i2];
        byte[] bArr2 = new byte[blockSize];
        secureRandom.nextBytes(bArr2);
        for (int i3 = 1; i3 < i2; i3++) {
            bArr[i3] = (byte) (str.codePointAt(i3 % str.length()) & 127);
            if (i3 >= blockSize) {
                bArr[i3] = (byte) (bArr[0] & bArr[i3]);
            }
        }
        System.arraycopy(bArr, blockSize, bArr2, 0, blockSize);
        return bArr2;
    }

    /* renamed from: q0 */
    public static void m4827q0(Application application) {
        ExecutorService executorService;
        if (application == null) {
            return;
        }
        Application application2 = f10936d;
        if (application2 != null) {
            if (application2.equals(application)) {
                return;
            }
            Application application3 = f10936d;
            C1549s c1549s = C1549s.f1795c;
            c1549s.f1797f.clear();
            application3.unregisterActivityLifecycleCallbacks(c1549s);
            f10936d = application;
            application.registerActivityLifecycleCallbacks(c1549s);
            return;
        }
        f10936d = application;
        Application.ActivityLifecycleCallbacks activityLifecycleCallbacks = C1549s.f1795c;
        Objects.requireNonNull(activityLifecycleCallbacks);
        application.registerActivityLifecycleCallbacks(activityLifecycleCallbacks);
        Runnable[] runnableArr = {new RunnableC1531a()};
        for (int i2 = 0; i2 < 1; i2++) {
            Runnable runnable = runnableArr[i2];
            Map<Integer, Map<Integer, ExecutorService>> map = C1540j.f1773b;
            synchronized (map) {
                Map<Integer, ExecutorService> map2 = map.get(-2);
                if (map2 == null) {
                    ConcurrentHashMap concurrentHashMap = new ConcurrentHashMap();
                    executorService = C1540j.b.m713a(-2, 5);
                    concurrentHashMap.put(5, executorService);
                    map.put(-2, concurrentHashMap);
                } else {
                    executorService = map2.get(5);
                    if (executorService == null) {
                        executorService = C1540j.b.m713a(-2, 5);
                        map2.put(5, executorService);
                    }
                }
            }
            executorService.execute(runnable);
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:35:0x0053 A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:41:? A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:42:0x004c A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:46:0x0045 A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* renamed from: r */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static byte[] m4828r(byte[] r6) {
        /*
            r0 = 0
            java.io.ByteArrayInputStream r1 = new java.io.ByteArrayInputStream     // Catch: java.lang.Throwable -> L3e
            r1.<init>(r6)     // Catch: java.lang.Throwable -> L3e
            java.io.ByteArrayOutputStream r6 = new java.io.ByteArrayOutputStream     // Catch: java.lang.Throwable -> L3b
            r6.<init>()     // Catch: java.lang.Throwable -> L3b
            java.util.zip.GZIPOutputStream r2 = new java.util.zip.GZIPOutputStream     // Catch: java.lang.Throwable -> L36
            r2.<init>(r6)     // Catch: java.lang.Throwable -> L36
            r0 = 4096(0x1000, float:5.74E-42)
            byte[] r0 = new byte[r0]     // Catch: java.lang.Throwable -> L34
        L14:
            int r3 = r1.read(r0)     // Catch: java.lang.Throwable -> L34
            r4 = -1
            if (r3 == r4) goto L20
            r4 = 0
            r2.write(r0, r4, r3)     // Catch: java.lang.Throwable -> L34
            goto L14
        L20:
            r2.flush()     // Catch: java.lang.Throwable -> L34
            r2.finish()     // Catch: java.lang.Throwable -> L34
            byte[] r0 = r6.toByteArray()     // Catch: java.lang.Throwable -> L34
            r1.close()     // Catch: java.lang.Exception -> L2d
        L2d:
            r6.close()     // Catch: java.lang.Exception -> L30
        L30:
            r2.close()     // Catch: java.lang.Exception -> L33
        L33:
            return r0
        L34:
            r0 = move-exception
            goto L43
        L36:
            r2 = move-exception
            r5 = r2
            r2 = r0
            r0 = r5
            goto L43
        L3b:
            r6 = move-exception
            r2 = r0
            goto L41
        L3e:
            r6 = move-exception
            r1 = r0
            r2 = r1
        L41:
            r0 = r6
            r6 = r2
        L43:
            if (r1 == 0) goto L4a
            r1.close()     // Catch: java.lang.Exception -> L49
            goto L4a
        L49:
        L4a:
            if (r6 == 0) goto L51
            r6.close()     // Catch: java.lang.Exception -> L50
            goto L51
        L50:
        L51:
            if (r2 == 0) goto L56
            r2.close()     // Catch: java.lang.Exception -> L56
        L56:
            throw r0
        */
        throw new UnsupportedOperationException("Method not decompiled: p403d.p404a.p405a.p407b.p408a.C4195m.m4828r(byte[]):byte[]");
    }

    /* renamed from: r0 */
    public static String m4829r0(Intent intent) {
        boolean z;
        StringBuilder sb = new StringBuilder(128);
        sb.append("Intent { ");
        String action = intent.getAction();
        boolean z2 = true;
        boolean z3 = false;
        if (action != null) {
            sb.append("act=");
            sb.append(action);
            z = false;
        } else {
            z = true;
        }
        Set<String> categories = intent.getCategories();
        if (categories != null) {
            if (!z) {
                sb.append(' ');
            }
            sb.append("cat=[");
            for (String str : categories) {
                if (!z2) {
                    sb.append(',');
                }
                sb.append(str);
                z2 = false;
            }
            sb.append("]");
            z = false;
        }
        Uri data = intent.getData();
        if (data != null) {
            if (!z) {
                sb.append(' ');
            }
            sb.append("dat=");
            sb.append(data);
            z = false;
        }
        String type = intent.getType();
        if (type != null) {
            if (!z) {
                sb.append(' ');
            }
            sb.append("typ=");
            sb.append(type);
            z = false;
        }
        int flags = intent.getFlags();
        if (flags != 0) {
            if (!z) {
                sb.append(' ');
            }
            sb.append("flg=0x");
            sb.append(Integer.toHexString(flags));
            z = false;
        }
        String str2 = intent.getPackage();
        if (str2 != null) {
            if (!z) {
                sb.append(' ');
            }
            sb.append("pkg=");
            sb.append(str2);
            z = false;
        }
        ComponentName component = intent.getComponent();
        if (component != null) {
            if (!z) {
                sb.append(' ');
            }
            sb.append("cmp=");
            sb.append(component.flattenToShortString());
            z = false;
        }
        Rect sourceBounds = intent.getSourceBounds();
        if (sourceBounds != null) {
            if (!z) {
                sb.append(' ');
            }
            sb.append("bnds=");
            sb.append(sourceBounds.toShortString());
            z = false;
        }
        ClipData clipData = intent.getClipData();
        if (clipData != null) {
            if (!z) {
                sb.append(' ');
            }
            ClipData.Item itemAt = clipData.getItemAt(0);
            if (itemAt == null) {
                sb.append("ClipData.Item {}");
            } else {
                sb.append("ClipData.Item { ");
                String htmlText = itemAt.getHtmlText();
                if (htmlText != null) {
                    C1499a.m606a0(sb, "H:", htmlText, "}");
                } else {
                    CharSequence text = itemAt.getText();
                    if (text != null) {
                        sb.append("T:");
                        sb.append(text);
                        sb.append("}");
                    } else {
                        Uri uri = itemAt.getUri();
                        if (uri != null) {
                            sb.append("U:");
                            sb.append(uri);
                            sb.append("}");
                        } else {
                            Intent intent2 = itemAt.getIntent();
                            if (intent2 != null) {
                                sb.append("I:");
                                sb.append(m4829r0(intent2));
                                sb.append("}");
                            } else {
                                sb.append("NULL");
                                sb.append("}");
                            }
                        }
                    }
                }
            }
            z = false;
        }
        Bundle extras = intent.getExtras();
        if (extras != null) {
            if (!z) {
                sb.append(' ');
            }
            sb.append("extras={");
            sb.append(m4757B(extras));
            sb.append('}');
        } else {
            z3 = z;
        }
        Intent selector = intent.getSelector();
        if (selector != null) {
            if (!z3) {
                sb.append(' ');
            }
            sb.append("sel={");
            sb.append(selector == intent ? "(this Intent)" : m4829r0(selector));
            sb.append("}");
        }
        sb.append(" }");
        return sb.toString();
    }

    /* renamed from: s */
    public static String m4830s(String str) {
        try {
            if (m4822o(str)) {
                return null;
            }
            MessageDigest messageDigest = MessageDigest.getInstance(EvpMdRef.SHA1.JCA_NAME);
            messageDigest.update(str.getBytes("UTF-8"));
            byte[] digest = messageDigest.digest();
            StringBuilder sb = new StringBuilder();
            for (byte b2 : digest) {
                sb.append(String.format("%02x", Byte.valueOf(b2)));
            }
            return sb.toString();
        } catch (Exception unused) {
            return null;
        }
    }

    /* renamed from: s0 */
    public static boolean m4831s0(Uri uri) {
        return uri != null && "content".equals(uri.getScheme()) && "media".equals(uri.getAuthority());
    }

    /* renamed from: t */
    public static String m4832t(String str) {
        try {
            System.clearProperty(str);
        } catch (Throwable unused) {
        }
        if (!m4822o("")) {
            return "";
        }
        String m582D = C1499a.m582D(new StringBuilder(".SystemConfig"), File.separator, str);
        try {
            if (m4818m()) {
                File file = new File(Environment.getExternalStorageDirectory().getAbsolutePath(), m582D);
                if (file.exists()) {
                    file.delete();
                    return "";
                }
            }
        } catch (Exception unused2) {
        }
        return null;
    }

    /* renamed from: t0 */
    public static boolean m4833t0(int i2, int i3) {
        return i2 != Integer.MIN_VALUE && i3 != Integer.MIN_VALUE && i2 <= 512 && i3 <= 384;
    }

    /* renamed from: u */
    public static final int m4834u(int i2) {
        return View.MeasureSpec.makeMeasureSpec(i2, Integer.MIN_VALUE);
    }

    /* renamed from: u0 */
    public static RecyclerView m4835u0(RecyclerView recyclerView, int i2, boolean z, boolean z2, boolean z3, int i3) {
        if ((i3 & 1) != 0) {
            i2 = 1;
        }
        if ((i3 & 2) != 0) {
            z = false;
        }
        if ((i3 & 4) != 0) {
            z2 = true;
        }
        if ((i3 & 8) != 0) {
            z3 = false;
        }
        Intrinsics.checkNotNullParameter(recyclerView, "<this>");
        HoverLinearLayoutManager hoverLinearLayoutManager = new HoverLinearLayoutManager(recyclerView.getContext(), i2, z);
        hoverLinearLayoutManager.f8992k = z2;
        hoverLinearLayoutManager.setStackFromEnd(z3);
        recyclerView.setLayoutManager(hoverLinearLayoutManager);
        return recyclerView;
    }

    /* renamed from: v */
    public static synchronized C1351a m4836v(Context context) {
        synchronized (C4195m.class) {
            try {
                String m436c = C1382g.m436c(null, context, "alipay_cashier_statistic_record", null);
                if (TextUtils.isEmpty(m436c)) {
                    return new C1351a();
                }
                return new C1351a(m436c);
            } catch (Throwable th) {
                m4816l(th);
                return new C1351a();
            }
        }
    }

    /* renamed from: v0 */
    public static final void m4837v0(@NotNull Object obj) {
        Intrinsics.checkNotNullParameter(obj, "<this>");
        String.valueOf(obj);
    }

    /* renamed from: w */
    public static InterfaceC1407a m4838w(Context context, String str) {
        C1403b c1403b;
        if (context == null) {
            return null;
        }
        if (C1408b.f1360a == null) {
            synchronized (C1403b.class) {
                if (C1403b.f1335a == null) {
                    C1403b.f1335a = new C1403b(context, str);
                }
                c1403b = C1403b.f1335a;
            }
            C1408b.f1361b = c1403b;
            C1408b.f1360a = new C1408b();
        }
        return C1408b.f1360a;
    }

    /* renamed from: w0 */
    public static void m4839w0(File file) {
        if (!file.exists()) {
            if (!file.mkdirs()) {
                throw new IOException(String.format("Directory %s can't be created", file.getAbsolutePath()));
            }
        } else {
            if (file.isDirectory()) {
                return;
            }
            throw new IOException("File " + file + " is not directory!");
        }
    }

    /* renamed from: x */
    public static boolean m4840x(String str) {
        return !m4822o(str);
    }

    /* renamed from: x0 */
    public static void m4841x0(MediaFormat mediaFormat, String str, int i2) {
        if (i2 != -1) {
            mediaFormat.setInteger(str, i2);
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* renamed from: y */
    public static byte[] m4842y(byte[] bArr) {
        ByteArrayInputStream byteArrayInputStream;
        ByteArrayOutputStream byteArrayOutputStream;
        Throwable th;
        GZIPInputStream gZIPInputStream;
        try {
            byteArrayInputStream = new ByteArrayInputStream(bArr);
            try {
                gZIPInputStream = new GZIPInputStream(byteArrayInputStream);
                try {
                    byte[] bArr2 = new byte[4096];
                    byteArrayOutputStream = new ByteArrayOutputStream();
                    while (true) {
                        try {
                            int read = gZIPInputStream.read(bArr2, 0, 4096);
                            if (read == -1) {
                                break;
                            }
                            byteArrayOutputStream.write(bArr2, 0, read);
                        } catch (Throwable th2) {
                            th = th2;
                            try {
                                byteArrayOutputStream.close();
                            } catch (Exception unused) {
                            }
                            try {
                                gZIPInputStream.close();
                            } catch (Exception unused2) {
                            }
                            try {
                                byteArrayInputStream.close();
                                throw th;
                            } catch (Exception unused3) {
                                throw th;
                            }
                        }
                    }
                    byteArrayOutputStream.flush();
                    byte[] byteArray = byteArrayOutputStream.toByteArray();
                    try {
                        byteArrayOutputStream.close();
                    } catch (Exception unused4) {
                    }
                    try {
                        gZIPInputStream.close();
                    } catch (Exception unused5) {
                    }
                    try {
                        byteArrayInputStream.close();
                    } catch (Exception unused6) {
                    }
                    return byteArray;
                } catch (Throwable th3) {
                    byteArrayOutputStream = null;
                    th = th3;
                }
            } catch (Throwable th4) {
                th = th4;
                byteArrayOutputStream = null;
                th = th;
                gZIPInputStream = byteArrayOutputStream;
                byteArrayOutputStream.close();
                gZIPInputStream.close();
                byteArrayInputStream.close();
                throw th;
            }
        } catch (Throwable th5) {
            th = th5;
            byteArrayInputStream = null;
            byteArrayOutputStream = null;
        }
    }

    /* renamed from: y0 */
    public static String m4843y0(Object obj, int i2) {
        List<String> list;
        if (obj.getClass().isArray()) {
            if (obj instanceof Object[]) {
                return Arrays.deepToString((Object[]) obj);
            }
            if (obj instanceof boolean[]) {
                return Arrays.toString((boolean[]) obj);
            }
            if (obj instanceof byte[]) {
                return Arrays.toString((byte[]) obj);
            }
            if (obj instanceof char[]) {
                return Arrays.toString((char[]) obj);
            }
            if (obj instanceof double[]) {
                return Arrays.toString((double[]) obj);
            }
            if (obj instanceof float[]) {
                return Arrays.toString((float[]) obj);
            }
            if (obj instanceof int[]) {
                return Arrays.toString((int[]) obj);
            }
            if (obj instanceof long[]) {
                return Arrays.toString((long[]) obj);
            }
            if (obj instanceof short[]) {
                return Arrays.toString((short[]) obj);
            }
            StringBuilder m586H = C1499a.m586H("Array has incompatible type: ");
            m586H.append(obj.getClass());
            throw new IllegalArgumentException(m586H.toString());
        }
        if (obj instanceof Throwable) {
            String str = C1541k.f1782a;
            ArrayList arrayList = new ArrayList();
            for (Throwable th = (Throwable) obj; th != null && !arrayList.contains(th); th = th.getCause()) {
                arrayList.add(th);
            }
            int size = arrayList.size();
            ArrayList arrayList2 = new ArrayList();
            int i3 = size - 1;
            List<String> m714a = C1541k.m714a((Throwable) arrayList.get(i3));
            while (true) {
                size--;
                if (size < 0) {
                    break;
                }
                if (size != 0) {
                    list = C1541k.m714a((Throwable) arrayList.get(size - 1));
                    int size2 = m714a.size() - 1;
                    ArrayList arrayList3 = (ArrayList) list;
                    int size3 = arrayList3.size();
                    while (true) {
                        size3--;
                        if (size2 < 0 || size3 < 0) {
                            break;
                        }
                        if (m714a.get(size2).equals((String) arrayList3.get(size3))) {
                            m714a.remove(size2);
                        }
                        size2--;
                    }
                } else {
                    list = m714a;
                }
                if (size == i3) {
                    arrayList2.add(((Throwable) arrayList.get(size)).toString());
                } else {
                    StringBuilder m586H2 = C1499a.m586H(" Caused by: ");
                    m586H2.append(((Throwable) arrayList.get(size)).toString());
                    arrayList2.add(m586H2.toString());
                }
                arrayList2.addAll(m714a);
                m714a = list;
            }
            StringBuilder sb = new StringBuilder();
            Iterator it = arrayList2.iterator();
            while (it.hasNext()) {
                sb.append((String) it.next());
                sb.append(C1541k.f1782a);
            }
            return sb.toString();
        }
        if (obj instanceof Bundle) {
            return m4757B((Bundle) obj);
        }
        if (obj instanceof Intent) {
            return m4829r0((Intent) obj);
        }
        if (i2 != 32) {
            if (i2 != 48) {
                return obj.toString();
            }
            String obj2 = obj.toString();
            try {
                StreamSource streamSource = new StreamSource(new StringReader(obj2));
                StreamResult streamResult = new StreamResult(new StringWriter());
                Transformer newTransformer = TransformerFactory.newInstance().newTransformer();
                newTransformer.setOutputProperty("indent", "yes");
                newTransformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "2");
                newTransformer.transform(streamSource, streamResult);
                return streamResult.getWriter().toString().replaceFirst(">", ">" + C1535e.f1718c);
            } catch (Exception e2) {
                e2.printStackTrace();
                return obj2;
            }
        }
        if (!(obj instanceof CharSequence)) {
            try {
                return C1550t.m726c().m2853g(obj);
            } catch (Throwable unused) {
                return obj.toString();
            }
        }
        String obj3 = obj.toString();
        try {
            int length = obj3.length();
            for (int i4 = 0; i4 < length; i4++) {
                char charAt = obj3.charAt(i4);
                if (charAt == '{') {
                    obj3 = new JSONObject(obj3).toString(4);
                    break;
                }
                if (charAt == '[') {
                    obj3 = new JSONArray(obj3).toString(4);
                    break;
                }
                if (Character.isWhitespace(charAt)) {
                }
            }
            return obj3;
        } catch (JSONException e3) {
            e3.printStackTrace();
            return obj3;
        }
    }

    /* renamed from: z */
    public static byte[] m4844z(UUID uuid, @Nullable byte[] bArr) {
        return m4755A(uuid, null, bArr);
    }

    /* JADX WARN: Removed duplicated region for block: B:5:0x006d A[RETURN] */
    /* JADX WARN: Removed duplicated region for block: B:7:0x006e  */
    @androidx.annotation.Nullable
    /* renamed from: z0 */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static java.util.UUID m4845z0(byte[] r9) {
        /*
            b.l.a.a.p1.t r0 = new b.l.a.a.p1.t
            r0.<init>(r9)
            int r9 = r0.f6135c
            r1 = 32
            r2 = 0
            if (r9 >= r1) goto Le
        Lc:
            r9 = r2
            goto L6b
        Le:
            r9 = 0
            r0.m2567C(r9)
            int r1 = r0.m2573e()
            int r3 = r0.m2569a()
            int r3 = r3 + 4
            if (r1 == r3) goto L1f
            goto Lc
        L1f:
            int r1 = r0.m2573e()
            r3 = 1886614376(0x70737368, float:3.013775E29)
            if (r1 == r3) goto L29
            goto Lc
        L29:
            int r1 = r0.m2573e()
            int r1 = r1 >> 24
            r1 = r1 & 255(0xff, float:3.57E-43)
            r3 = 1
            if (r1 <= r3) goto L35
            goto Lc
        L35:
            java.util.UUID r4 = new java.util.UUID
            long r5 = r0.m2579k()
            long r7 = r0.m2579k()
            r4.<init>(r5, r7)
            if (r1 != r3) goto L4d
            int r3 = r0.m2588t()
            int r3 = r3 * 16
            r0.m2568D(r3)
        L4d:
            int r3 = r0.m2588t()
            int r5 = r0.m2569a()
            if (r3 == r5) goto L58
            goto Lc
        L58:
            byte[] r5 = new byte[r3]
            byte[] r6 = r0.f6133a
            int r7 = r0.f6134b
            java.lang.System.arraycopy(r6, r7, r5, r9, r3)
            int r9 = r0.f6134b
            int r9 = r9 + r3
            r0.f6134b = r9
            b.l.a.a.f1.c0.g r9 = new b.l.a.a.f1.c0.g
            r9.<init>(r4, r1, r5)
        L6b:
            if (r9 != 0) goto L6e
            return r2
        L6e:
            java.util.UUID r9 = r9.f3676a
            return r9
        */
        throw new UnsupportedOperationException("Method not decompiled: p403d.p404a.p405a.p407b.p408a.C4195m.m4845z0(byte[]):java.util.UUID");
    }
}
