package p005b.p085c.p088b.p101k;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.DialogInterface;
import android.text.TextUtils;
import android.webkit.SslErrorHandler;
import com.alipay.sdk.widget.C3196d;
import java.io.PrintWriter;
import java.io.StringWriter;
import p005b.p085c.p088b.p089a.C1349f;
import p005b.p085c.p088b.p089a.p090h.C1353c;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.c.b.k.e */
/* loaded from: classes.dex */
public class RunnableC1388e implements Runnable {

    /* renamed from: c */
    public final /* synthetic */ Activity f1317c;

    /* renamed from: e */
    public final /* synthetic */ SslErrorHandler f1318e;

    /* renamed from: f */
    public final /* synthetic */ C3196d f1319f;

    /* renamed from: b.c.b.k.e$a */
    public class a implements DialogInterface.OnClickListener {
        public a() {
        }

        @Override // android.content.DialogInterface.OnClickListener
        public void onClick(DialogInterface dialogInterface, int i2) {
            RunnableC1388e.this.f1318e.cancel();
            C1353c.m362c(RunnableC1388e.this.f1319f.f8688j, "net", "SSLDenied", "2");
            C1349f.f1170b = C1349f.m357b();
            RunnableC1388e.this.f1317c.finish();
        }
    }

    public RunnableC1388e(C3196d c3196d, Activity activity, SslErrorHandler sslErrorHandler) {
        this.f1319f = c3196d;
        this.f1317c = activity;
        this.f1318e = sslErrorHandler;
    }

    @Override // java.lang.Runnable
    public void run() {
        Activity activity = this.f1317c;
        a aVar = new a();
        AlertDialog.Builder builder = new AlertDialog.Builder(activity);
        TextUtils.isEmpty(null);
        if (!TextUtils.isEmpty("确定")) {
            builder.setNegativeButton("确定", aVar);
        }
        builder.setTitle("安全警告");
        builder.setMessage("安全连接证书校验无效，将无法保证访问数据的安全性，请安装支付宝后重试。");
        AlertDialog create = builder.create();
        create.setCanceledOnTouchOutside(false);
        create.setOnKeyListener(new DialogInterfaceOnKeyListenerC1386c());
        try {
            create.show();
        } catch (Throwable th) {
            C4195m.m4787T("mspl", "showDialog ");
            StringWriter stringWriter = new StringWriter();
            th.printStackTrace(new PrintWriter(stringWriter));
            stringWriter.toString();
        }
    }
}
