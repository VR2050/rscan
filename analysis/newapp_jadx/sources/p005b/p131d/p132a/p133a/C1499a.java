package p005b.p131d.p132a.p133a;

import android.content.Context;
import android.content.Intent;
import android.content.res.TypedArray;
import android.graphics.Canvas;
import android.net.Uri;
import android.view.View;
import androidx.appcompat.app.AlertDialog;
import androidx.fragment.app.Fragment;
import androidx.recyclerview.widget.RecyclerView;
import com.alibaba.fastjson.asm.MethodWriter;
import com.alibaba.fastjson.parser.JSONLexerBase;
import com.alibaba.fastjson.parser.JSONScanner;
import com.alibaba.fastjson.parser.deserializer.ASMDeserializerFactory;
import com.drake.brv.BindingAdapter;
import com.qunidayede.supportlibrary.utils.GridItemDecoration;
import java.io.File;
import java.lang.reflect.Modifier;
import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import kotlin.UByte;
import kotlin.UByteArray;
import kotlin.UInt;
import kotlin.UIntArray;
import kotlin.ULong;
import kotlin.ULongArray;
import kotlin.UShort;
import kotlin.UShortArray;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.InlineMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.reflect.jvm.internal.impl.metadata.deserialization.Flags;
import kotlin.sequences.Sequence;
import org.conscrypt.OpenSSLProvider;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p005b.p293n.p294a.C2645e0;

/* renamed from: b.d.a.a.a */
/* loaded from: classes.dex */
public class C1499a {
    /* renamed from: A */
    public static String m579A(StringBuilder sb, int i2, char c2) {
        sb.append(i2);
        sb.append(c2);
        return sb.toString();
    }

    /* renamed from: B */
    public static String m580B(StringBuilder sb, int i2, String str) {
        sb.append(i2);
        sb.append(str);
        return sb.toString();
    }

    /* renamed from: C */
    public static String m581C(StringBuilder sb, String str, char c2) {
        sb.append(str);
        sb.append(c2);
        return sb.toString();
    }

    /* renamed from: D */
    public static String m582D(StringBuilder sb, String str, String str2) {
        sb.append(str);
        sb.append(str2);
        return sb.toString();
    }

    /* renamed from: E */
    public static String m583E(StringBuilder sb, String str, String str2, String str3) {
        sb.append(str);
        sb.append(str2);
        sb.append(str3);
        return sb.toString();
    }

    /* renamed from: F */
    public static StringBuilder m584F(char c2) {
        StringBuilder sb = new StringBuilder();
        sb.append(c2);
        return sb;
    }

    /* renamed from: G */
    public static StringBuilder m585G(MethodWriter methodWriter, int i2, String str, String str2, String str3) {
        methodWriter.visitMethodInsn(i2, str, str2, str3);
        return new StringBuilder();
    }

    /* renamed from: H */
    public static StringBuilder m586H(String str) {
        StringBuilder sb = new StringBuilder();
        sb.append(str);
        return sb;
    }

    /* renamed from: I */
    public static int m587I(CharSequence charSequence, String str, Function1 function1, String str2) {
        Intrinsics.checkNotNullParameter(charSequence, str);
        Intrinsics.checkNotNullParameter(function1, str2);
        return charSequence.length();
    }

    /* renamed from: J */
    public static StringBuilder m588J(String str, int i2, String str2) {
        StringBuilder sb = new StringBuilder();
        sb.append(str);
        sb.append(i2);
        sb.append(str2);
        return sb;
    }

    /* renamed from: K */
    public static StringBuilder m589K(String str, int i2, String str2, int i3, String str3) {
        StringBuilder sb = new StringBuilder();
        sb.append(str);
        sb.append(i2);
        sb.append(str2);
        sb.append(i3);
        sb.append(str3);
        return sb;
    }

    /* renamed from: L */
    public static StringBuilder m590L(String str, String str2) {
        StringBuilder sb = new StringBuilder();
        sb.append(str);
        sb.append(str2);
        return sb;
    }

    /* renamed from: M */
    public static StringBuilder m591M(String str, String str2, String str3) {
        StringBuilder sb = new StringBuilder();
        sb.append(str);
        sb.append(str2);
        sb.append(str3);
        return sb;
    }

    /* renamed from: N */
    public static StringBuilder m592N(OpenSSLProvider openSSLProvider, String str, String str2, String str3, String str4) {
        openSSLProvider.put(str, str2);
        openSSLProvider.put(str3, str4);
        return new StringBuilder();
    }

    /* renamed from: O */
    public static ArrayList m593O(LinkedHashMap linkedHashMap, Object obj) {
        ArrayList arrayList = new ArrayList();
        linkedHashMap.put(obj, arrayList);
        return arrayList;
    }

    /* renamed from: P */
    public static ArrayList m594P(Map map, Object obj) {
        ArrayList arrayList = new ArrayList();
        map.put(obj, arrayList);
        return arrayList;
    }

    /* renamed from: Q */
    public static HashMap m595Q(String str, String str2) {
        HashMap hashMap = new HashMap();
        hashMap.put(str, str2);
        return hashMap;
    }

    /* renamed from: R */
    public static HashMap m596R(String str, String str2, String str3, String str4) {
        HashMap hashMap = new HashMap();
        hashMap.put(str, str2);
        hashMap.put(str3, str4);
        return hashMap;
    }

    /* renamed from: S */
    public static Iterator m597S(Iterable iterable, String str, Function1 function1, String str2) {
        Intrinsics.checkNotNullParameter(iterable, str);
        Intrinsics.checkNotNullParameter(function1, str2);
        return iterable.iterator();
    }

    /* renamed from: T */
    public static int m598T(String str, int i2, int i3) {
        return (str.hashCode() + i2) * i3;
    }

    /* renamed from: U */
    public static Iterator m599U(Sequence sequence, String str, Function1 function1, String str2) {
        Intrinsics.checkNotNullParameter(sequence, str);
        Intrinsics.checkNotNullParameter(function1, str2);
        return sequence.iterator();
    }

    /* renamed from: V */
    public static void m600V(int i2, Canvas canvas, int i3, int i4) {
        InlineMarker.finallyStart(i2);
        canvas.restoreToCount(i3);
        InlineMarker.finallyEnd(i4);
    }

    /* renamed from: W */
    public static void m601W(int i2, HashMap hashMap, String str, int i3, String str2, int i4, String str3, int i5, String str4) {
        hashMap.put(str, Integer.valueOf(i2));
        hashMap.put(str2, Integer.valueOf(i3));
        hashMap.put(str3, Integer.valueOf(i4));
        hashMap.put(str4, Integer.valueOf(i5));
    }

    /* renamed from: X */
    public static void m602X(Context context, String str, Context context2, Class cls) {
        Intrinsics.checkNotNullParameter(context, str);
        context.startActivity(new Intent(context2, (Class<?>) cls));
    }

    /* renamed from: Y */
    public static void m603Y(TypedArray typedArray, int i2, int i3, ArrayList arrayList) {
        arrayList.add(Integer.valueOf(typedArray.getColor(i2, i3)));
    }

    /* renamed from: Z */
    public static void m604Z(GridItemDecoration.C4053a c4053a, RecyclerView recyclerView) {
        recyclerView.addItemDecoration(new GridItemDecoration(c4053a));
    }

    /* renamed from: a */
    public static char m605a(int i2, int i3, int i4, JSONLexerBase jSONLexerBase) {
        return jSONLexerBase.charAt(i2 + i3 + i4);
    }

    /* renamed from: a0 */
    public static void m606a0(StringBuilder sb, String str, String str2, String str3) {
        sb.append(str);
        sb.append(str2);
        sb.append(str3);
    }

    /* renamed from: b */
    public static char m607b(int i2, int i3, int i4, JSONScanner jSONScanner) {
        return jSONScanner.charAt(i2 + i3 + i4);
    }

    /* renamed from: b0 */
    public static void m608b0(StringBuilder sb, String str, String str2, String str3, String str4) {
        sb.append(str);
        sb.append(str2);
        sb.append(str3);
        sb.append(str4);
    }

    /* renamed from: c */
    public static Object m609c(CharSequence charSequence, int i2, Function1 function1) {
        return function1.invoke(Character.valueOf(charSequence.charAt(i2)));
    }

    /* renamed from: c0 */
    public static void m610c0(StringBuilder sb, String str, String str2, OpenSSLProvider openSSLProvider, String str3) {
        sb.append(str);
        sb.append(str2);
        openSSLProvider.put(str3, sb.toString());
    }

    /* renamed from: d */
    public static Object m611d(List list, int i2) {
        return list.get(list.size() - i2);
    }

    /* renamed from: d0 */
    public static boolean m612d0(Context context, Intent intent, Context context2, Intent intent2) {
        intent.setData(C2645e0.m3123i(context));
        return C2645e0.m3115a(context2, intent2);
    }

    /* renamed from: e */
    public static Object m613e(byte[] bArr, int i2, Function1 function1) {
        return function1.invoke(UByte.m6067boximpl(UByteArray.m6130getw2LRezQ(bArr, i2)));
    }

    /* renamed from: e0 */
    public static int m614e0(StringBuilder sb, String str, String str2, ASMDeserializerFactory.Context context) {
        sb.append(str);
        sb.append(str2);
        return context.var(sb.toString());
    }

    /* renamed from: f */
    public static Object m615f(int[] iArr, int i2, Function1 function1) {
        return function1.invoke(UInt.m6143boximpl(UIntArray.m6208getpVg5ArA(iArr, i2)));
    }

    /* renamed from: f0 */
    public static boolean m616f0(BindingAdapter bindingAdapter, String str, RecyclerView recyclerView, String str2, Class cls) {
        Intrinsics.checkNotNullParameter(bindingAdapter, str);
        Intrinsics.checkNotNullParameter(recyclerView, str2);
        return Modifier.isInterface(cls.getModifiers());
    }

    /* renamed from: g */
    public static Object m617g(long[] jArr, int i2, Function1 function1) {
        return function1.invoke(ULong.m6221boximpl(ULongArray.m6286getsVKNKU(jArr, i2)));
    }

    /* renamed from: g0 */
    public static boolean m618g0(Flags.BooleanFlagField booleanFlagField, int i2, String str) {
        Boolean bool = booleanFlagField.get(i2);
        Intrinsics.checkNotNullExpressionValue(bool, str);
        return bool.booleanValue();
    }

    /* renamed from: h */
    public static Object m619h(short[] sArr, int i2, Function1 function1) {
        return function1.invoke(UShort.m6327boximpl(UShortArray.m6390getMh2AYeg(sArr, i2)));
    }

    /* renamed from: h0 */
    public static int m620h0(UInt uInt, int i2) {
        return UInt.m6149constructorimpl(uInt.getData() + i2);
    }

    /* renamed from: i */
    public static String m621i(RecyclerView recyclerView, StringBuilder sb) {
        sb.append(recyclerView.exceptionLabel());
        return sb.toString();
    }

    /* renamed from: i0 */
    public static Intent m622i0(String str, String str2) {
        Intent intent = new Intent();
        intent.setClassName(str, str2);
        return intent;
    }

    /* renamed from: j */
    public static String m623j(Class cls, StringBuilder sb) {
        sb.append(cls.getName());
        return sb.toString();
    }

    /* renamed from: j0 */
    public static AlertDialog m624j0(AlertDialog.Builder builder, View view, String str) {
        AlertDialog create = builder.setView(view).create();
        Intrinsics.checkNotNullExpressionValue(create, str);
        return create;
    }

    /* renamed from: k */
    public static String m625k(Class cls, StringBuilder sb, String str, String str2) {
        sb.append(cls.getSimpleName());
        sb.append(str);
        sb.append(cls.getSimpleName());
        sb.append(str2);
        return sb.toString();
    }

    /* renamed from: l */
    public static String m626l(String str, int i2) {
        return str + i2;
    }

    /* renamed from: m */
    public static float m627m(float f2, float f3, float f4, float f5) {
        return ((f2 - f3) * f4) + f5;
    }

    /* renamed from: n */
    public static String m628n(String str, int i2, String str2) {
        return str + i2 + str2;
    }

    /* renamed from: o */
    public static String m629o(String str, int i2, String str2, int i3) {
        return str + i2 + str2 + i3;
    }

    /* renamed from: p */
    public static String m630p(String str, long j2) {
        return str + j2;
    }

    /* renamed from: q */
    public static String m631q(String str, long j2, String str2) {
        return str + j2 + str2;
    }

    /* renamed from: r */
    public static String m632r(String str, Uri uri) {
        return str + uri;
    }

    /* renamed from: s */
    public static String m633s(String str, Fragment fragment, String str2) {
        return str + fragment + str2;
    }

    /* renamed from: t */
    public static String m634t(String str, File file) {
        return str + file;
    }

    /* renamed from: u */
    public static String m635u(String str, Class cls) {
        return str + cls;
    }

    /* renamed from: v */
    public static String m636v(String str, Object obj) {
        return str + obj;
    }

    /* renamed from: w */
    public static String m637w(String str, String str2) {
        return str + str2;
    }

    /* renamed from: x */
    public static int m638x(GridItemDecoration.C4053a c4053a, int i2, RecyclerView recyclerView, double d2) {
        c4053a.m4576a(i2);
        return C2354n.m2437V(recyclerView.getContext(), d2);
    }

    /* renamed from: y */
    public static String m639y(String str, String str2, String str3) {
        return str + str2 + str3;
    }

    /* renamed from: z */
    public static String m640z(String str, Type type) {
        return str + type;
    }
}
