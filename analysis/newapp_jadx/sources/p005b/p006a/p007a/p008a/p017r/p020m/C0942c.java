package p005b.p006a.p007a.p008a.p017r.p020m;

import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import java.security.MessageDigest;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.Iterator;
import java.util.Locale;
import java.util.TimeZone;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.StringCompanionObject;
import kotlin.text.Charsets;
import kotlin.text.StringsKt__StringsKt;
import org.conscrypt.EvpMdRef;
import org.jetbrains.annotations.NotNull;
import p005b.p006a.p007a.p008a.p017r.C0924h;
import p005b.p006a.p007a.p008a.p017r.C0925i;
import p403d.p404a.p405a.p407b.p408a.C4195m;
import p458k.C4381g0;
import p458k.C4389k0;
import p458k.InterfaceC4369a0;
import p458k.p459p0.p463g.C4430g;

/* renamed from: b.a.a.a.r.m.c */
/* loaded from: classes2.dex */
public final class C0942c implements InterfaceC4369a0 {
    @Override // p458k.InterfaceC4369a0
    @NotNull
    /* renamed from: a */
    public C4389k0 mo280a(@NotNull InterfaceC4369a0.a chain) {
        String str;
        boolean z;
        Intrinsics.checkNotNullParameter(chain, "chain");
        C4430g c4430g = (C4430g) chain;
        C4381g0.a aVar = new C4381g0.a(c4430g.f11739f);
        Intrinsics.checkParameterIsNotNull("User-Agent", "name");
        Intrinsics.checkParameterIsNotNull("Mozilla/5.0 (Linux; U; Android 8.1.0; zh-CN; EML-AL00 Build/HUAWEIEML-AL00) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/57.0.2987.108 Dart/11.9.4.974 UWS/2.13.1.48 Mobile Safari/537.36 AliApp(DingTalk/4.5.11)  Channel/227200 language/zh-CN", "value");
        aVar.f11447c.m5282a("User-Agent", "Mozilla/5.0 (Linux; U; Android 8.1.0; zh-CN; EML-AL00 Build/HUAWEIEML-AL00) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/57.0.2987.108 Dart/11.9.4.974 UWS/2.13.1.48 Mobile Safari/537.36 AliApp(DingTalk/4.5.11)  Channel/227200 language/zh-CN");
        Intrinsics.checkParameterIsNotNull("deviceType", "name");
        Intrinsics.checkParameterIsNotNull("android", "value");
        aVar.f11447c.m5282a("deviceType", "android");
        PackageManager packageManager = C4195m.m4792Y().getPackageManager();
        Intrinsics.checkNotNullExpressionValue(packageManager, "getApp().packageManager");
        try {
            PackageInfo packageInfo = packageManager.getPackageInfo(C4195m.m4792Y().getPackageName(), 0);
            Intrinsics.checkNotNullExpressionValue(packageInfo, "pm.getPackageInfo(Utils.getApp().packageName, 0)");
            str = packageInfo.versionName;
            Intrinsics.checkNotNullExpressionValue(str, "packageInfo.versionName");
        } catch (PackageManager.NameNotFoundException e2) {
            e2.printStackTrace();
            str = "";
        }
        aVar.m4971a("version", str);
        SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault());
        simpleDateFormat.setTimeZone(TimeZone.getTimeZone("GMT+08"));
        String format = simpleDateFormat.format(new Date());
        Intrinsics.checkNotNullExpressionValue(format, "sdf.format(Date())");
        aVar.m4971a("time", format);
        String str2 = aVar.m4972b().f11440b.f12054l;
        C0925i c0925i = C0925i.f437a;
        ArrayList<C0924h> arrayList = C0925i.f439c;
        ArrayList arrayList2 = new ArrayList();
        for (Object obj : arrayList) {
            if (((C0924h) obj).f436c) {
                arrayList2.add(obj);
            }
        }
        if (!arrayList2.isEmpty()) {
            Iterator it = arrayList2.iterator();
            while (it.hasNext()) {
                if (StringsKt__StringsKt.contains$default((CharSequence) str2, (CharSequence) ((C0924h) it.next()).f435b, false, 2, (Object) null)) {
                    z = true;
                    break;
                }
            }
        }
        z = false;
        if (z) {
            long currentTimeMillis = System.currentTimeMillis() / 1000;
            String valueOf = String.valueOf(30 + currentTimeMillis);
            String substring = m285b(String.valueOf(currentTimeMillis)).substring(0, 8);
            Intrinsics.checkNotNullExpressionValue(substring, "this as java.lang.String…ing(startIndex, endIndex)");
            String m285b = m285b("md5|cd271bb945844572818ba0bda1b59e85|" + valueOf + '|' + substring + '|' + str2);
            StringBuilder sb = new StringBuilder();
            sb.append("md5");
            sb.append('|');
            sb.append(valueOf);
            sb.append('|');
            sb.append(substring);
            sb.append('|');
            sb.append(m285b);
            aVar.m4971a("X-JSL-API-AUTH", sb.toString());
        }
        return c4430g.m5139d(aVar.m4972b());
    }

    /* renamed from: b */
    public final String m285b(String str) {
        MessageDigest messageDigest = MessageDigest.getInstance(EvpMdRef.MD5.JCA_NAME);
        byte[] bytes = str.getBytes(Charsets.UTF_8);
        Intrinsics.checkNotNullExpressionValue(bytes, "this as java.lang.String).getBytes(charset)");
        byte[] digest = messageDigest.digest(bytes);
        StringBuilder sb = new StringBuilder();
        Intrinsics.checkNotNullExpressionValue(digest, "digest");
        int length = digest.length;
        int i2 = 0;
        while (i2 < length) {
            byte b2 = digest[i2];
            i2++;
            StringCompanionObject stringCompanionObject = StringCompanionObject.INSTANCE;
            String format = String.format("%02x", Arrays.copyOf(new Object[]{Byte.valueOf(b2)}, 1));
            Intrinsics.checkNotNullExpressionValue(format, "format(format, *args)");
            sb.append(format);
        }
        String sb2 = sb.toString();
        Intrinsics.checkNotNullExpressionValue(sb2, "sb.toString()");
        return sb2;
    }
}
