package p005b.p327w.p330b.p336c;

import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import androidx.exifinterface.media.ExifInterface;
import com.google.android.material.badge.BadgeDrawable;
import com.jbzd.media.movecartoons.bean.response.system.MainMenusBean;
import com.qunidayede.supportlibrary.R$drawable;
import java.util.HashMap;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import kotlin.TuplesKt;
import kotlin.collections.MapsKt__MapsKt;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.Charsets;
import kotlin.text.StringsKt__StringsJVMKt;
import net.sourceforge.pinyin4j.ChineseToPinyinResource;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p143g.p144a.p166q.C1779f;
import p005b.p327w.p330b.C2827a;
import p005b.p327w.p330b.p331b.ApplicationC2828a;
import p005b.p327w.p330b.p337d.C2858b;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.w.b.c.d */
/* loaded from: classes2.dex */
public final class C2853d {

    /* renamed from: a */
    @NotNull
    public static final C2853d f7770a = new C2853d();

    /* renamed from: b */
    @NotNull
    public static String f7771b = "";

    /* renamed from: c */
    @NotNull
    public static final HashMap<String, String> f7772c;

    /* renamed from: d */
    @NotNull
    public static final HashMap<String, String> f7773d;

    /* renamed from: e */
    public static final int f7774e;

    /* renamed from: f */
    public static final int f7775f;

    /* renamed from: g */
    public static final int f7776g;

    /* renamed from: h */
    public static final int f7777h;

    static {
        HashMap<String, String> m596R = C1499a.m596R("=", "**", "J", "$$");
        m596R.put("H", "##");
        m596R.put(ExifInterface.GPS_MEASUREMENT_IN_PROGRESS, "^^");
        f7772c = m596R;
        f7773d = MapsKt__MapsKt.hashMapOf(TuplesKt.m5318to("0", "!"), TuplesKt.m5318to("1", ChineseToPinyinResource.Field.RIGHT_BRACKET), TuplesKt.m5318to(MainMenusBean.TYPE_PICK_COLLECTION, "&"), TuplesKt.m5318to("a", "*"), TuplesKt.m5318to("c", "%"), TuplesKt.m5318to("3", ":"), TuplesKt.m5318to("2", BadgeDrawable.DEFAULT_EXCEED_MAX_BADGE_NUMBER_SUFFIX), TuplesKt.m5318to("d", "-"), TuplesKt.m5318to("6", "<"));
        ApplicationC2828a applicationC2828a = C2827a.f7670a;
        if (applicationC2828a == null) {
            Intrinsics.throwUninitializedPropertyAccessException("context");
            throw null;
        }
        String m3300a = C2858b.m3300a(applicationC2828a);
        Boolean valueOf = m3300a == null ? null : Boolean.valueOf(StringsKt__StringsJVMKt.startsWith$default(m3300a, "九妖", false, 2, null));
        Boolean bool = Boolean.TRUE;
        int i2 = Intrinsics.areEqual(valueOf, bool) ? R$drawable.ic_place_holder_horizontal : R$drawable.ic_place_holder_horizontal_51;
        f7774e = i2;
        ApplicationC2828a applicationC2828a2 = C2827a.f7670a;
        if (applicationC2828a2 == null) {
            Intrinsics.throwUninitializedPropertyAccessException("context");
            throw null;
        }
        String m3300a2 = C2858b.m3300a(applicationC2828a2);
        f7775f = Intrinsics.areEqual(m3300a2 == null ? null : Boolean.valueOf(StringsKt__StringsJVMKt.startsWith$default(m3300a2, "九妖", false, 2, null)), bool) ? R$drawable.ic_place_holder_circle : R$drawable.ic_place_holder_circle_51;
        ApplicationC2828a applicationC2828a3 = C2827a.f7670a;
        if (applicationC2828a3 == null) {
            Intrinsics.throwUninitializedPropertyAccessException("context");
            throw null;
        }
        String m3300a3 = C2858b.m3300a(applicationC2828a3);
        f7776g = Intrinsics.areEqual(m3300a3 == null ? null : Boolean.valueOf(StringsKt__StringsJVMKt.startsWith$default(m3300a3, "九妖", false, 2, null)), bool) ? R$drawable.ic_place_holder_vertical : R$drawable.ic_place_holder_vertical_51;
        ApplicationC2828a applicationC2828a4 = C2827a.f7670a;
        if (applicationC2828a4 == null) {
            Intrinsics.throwUninitializedPropertyAccessException("context");
            throw null;
        }
        String m3300a4 = C2858b.m3300a(applicationC2828a4);
        f7777h = Intrinsics.areEqual(m3300a4 == null ? null : Boolean.valueOf(StringsKt__StringsJVMKt.startsWith$default(m3300a4, "九妖", false, 2, null)), bool) ? R$drawable.ic_place_holder_launch : R$drawable.ic_place_holder_launch_banner_51;
        ApplicationC2828a applicationC2828a5 = C2827a.f7670a;
        if (applicationC2828a5 == null) {
            Intrinsics.throwUninitializedPropertyAccessException("context");
            throw null;
        }
        String m3300a5 = C2858b.m3300a(applicationC2828a5);
        Intrinsics.areEqual(m3300a5 != null ? Boolean.valueOf(StringsKt__StringsJVMKt.startsWith$default(m3300a5, "九妖", false, 2, null)) : null, bool);
        Intrinsics.checkNotNullExpressionValue(new C1779f().mo1088l(i2).mo1098y(i2).mo1089m(i2), "RequestOptions()\n        .error(cacheRes)\n        .placeholder(cacheRes)\n        .fallback(cacheRes)");
    }

    @Nullable
    /* renamed from: a */
    public final byte[] m3299a(@Nullable byte[] bArr, @NotNull String key) {
        Intrinsics.checkNotNullParameter(key, "key");
        PackageManager packageManager = C4195m.m4792Y().getPackageManager();
        Intrinsics.checkNotNullExpressionValue(packageManager, "getApp().packageManager");
        try {
            PackageInfo packageInfo = packageManager.getPackageInfo(C4195m.m4792Y().getPackageName(), 0);
            Intrinsics.checkNotNullExpressionValue(packageInfo, "pm.getPackageInfo(Utils.getApp().packageName, 0)");
            Intrinsics.checkNotNullExpressionValue(packageInfo.versionName, "packageInfo.versionName");
        } catch (PackageManager.NameNotFoundException e2) {
            e2.printStackTrace();
        }
        try {
            byte[] bytes = key.getBytes(Charsets.UTF_8);
            Intrinsics.checkNotNullExpressionValue(bytes, "this as java.lang.String).getBytes(charset)");
            SecretKeySpec secretKeySpec = new SecretKeySpec(bytes, "AES");
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(2, secretKeySpec);
            return cipher.doFinal(bArr);
        } catch (Exception e3) {
            System.out.println((Object) e3.toString());
            return null;
        }
    }
}
