package p005b.p085c.p088b.p101k;

import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.webkit.DownloadListener;
import com.alibaba.fastjson.asm.Label;
import com.alipay.sdk.widget.C3197e;

/* renamed from: b.c.b.k.f */
/* loaded from: classes.dex */
public class C1389f implements DownloadListener {

    /* renamed from: a */
    public final /* synthetic */ Context f1321a;

    public C1389f(C3197e c3197e, Context context) {
        this.f1321a = context;
    }

    @Override // android.webkit.DownloadListener
    public void onDownloadStart(String str, String str2, String str3, String str4, long j2) {
        try {
            Intent intent = new Intent("android.intent.action.VIEW", Uri.parse(str));
            intent.setFlags(Label.FORWARD_REFERENCE_TYPE_SHORT);
            this.f1321a.startActivity(intent);
        } catch (Throwable unused) {
        }
    }
}
