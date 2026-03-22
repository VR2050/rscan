package p005b.p327w.p330b.p337d;

import android.content.Context;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Build;
import androidx.core.content.FileProvider;
import com.alibaba.fastjson.asm.Label;
import java.io.File;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt__StringsKt;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.w.b.d.b */
/* loaded from: classes2.dex */
public final class C2858b {
    @Nullable
    /* renamed from: a */
    public static final String m3300a(@NotNull Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        try {
            PackageManager packageManager = context.getPackageManager();
            ApplicationInfo applicationInfo = packageManager.getApplicationInfo(context.getPackageName(), 128);
            Intrinsics.checkNotNullExpressionValue(applicationInfo, "manager.getApplicationInfo(context.packageName, PackageManager.GET_META_DATA)");
            return (String) packageManager.getApplicationLabel(applicationInfo);
        } catch (PackageManager.NameNotFoundException unused) {
            return "";
        }
    }

    /* renamed from: b */
    public static final void m3301b(@NotNull Context context, @NotNull File file) {
        String str;
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(file, "file");
        String name = file.getName();
        Intrinsics.checkNotNullExpressionValue(name, "file.name");
        String substring = name.substring(StringsKt__StringsKt.lastIndexOf$default((CharSequence) name, ".", 0, false, 6, (Object) null) + 1, name.length());
        Intrinsics.checkNotNullExpressionValue(substring, "this as java.lang.String…ing(startIndex, endIndex)");
        if (Intrinsics.areEqual(substring, "apk")) {
            Intent intent = new Intent("android.intent.action.VIEW");
            intent.addFlags(Label.FORWARD_REFERENCE_TYPE_SHORT);
            if (Build.VERSION.SDK_INT >= 24) {
                try {
                    str = C4195m.m4792Y().getPackageManager().getPackageInfo(C4195m.m4792Y().getPackageName(), 0).packageName;
                    Intrinsics.checkNotNullExpressionValue(str, "packageInfo.packageName");
                } catch (Exception e2) {
                    e2.printStackTrace();
                    str = "";
                }
                Uri uriForFile = FileProvider.getUriForFile(context, Intrinsics.stringPlus(str, ".fileprovider"), file);
                intent.addFlags(1);
                intent.setDataAndType(uriForFile, "application/vnd.android.package-archive");
            } else {
                intent.setDataAndType(Uri.fromFile(file), "application/vnd.android.package-archive");
            }
            context.startActivity(intent);
        }
    }
}
