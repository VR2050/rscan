package p005b.p006a.p007a.p008a.p009a;

import com.jbzd.media.movecartoons.MyApp;
import com.jbzd.media.movecartoons.bean.response.system.SystemInfoBean;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt__StringsKt;

/* renamed from: b.a.a.a.a.h0 */
/* loaded from: classes2.dex */
public final class RunnableC0849h0 implements Runnable {
    @Override // java.lang.Runnable
    public void run() {
        MyApp myApp = MyApp.f9891f;
        SystemInfoBean m4185f = MyApp.m4185f();
        Intrinsics.checkNotNull(m4185f);
        String str = m4185f.upload_file_url;
        Intrinsics.checkNotNullExpressionValue(str, "MyApp.systemBean!!.upload_file_url");
        SystemInfoBean m4185f2 = MyApp.m4185f();
        Intrinsics.checkNotNull(m4185f2);
        String str2 = m4185f2.upload_file_url;
        Intrinsics.checkNotNullExpressionValue(str2, "MyApp.systemBean!!.upload_file_url");
        Intrinsics.checkNotNullExpressionValue(str.substring(0, StringsKt__StringsKt.lastIndexOf$default((CharSequence) str2, "/", 0, false, 6, (Object) null) + 1), "this as java.lang.String…ing(startIndex, endIndex)");
        throw null;
    }
}
