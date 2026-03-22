package p005b.p085c.p102c.p103a.p104a.p110e;

import android.content.Context;
import com.alipay.android.phone.mrpc.core.AbstractC3163w;
import com.alipay.android.phone.mrpc.core.C3138aa;
import com.alipay.android.phone.mrpc.core.C3148h;
import com.alipay.tscenter.biz.rpc.deviceFp.BugTrackMessageService;
import com.alipay.tscenter.biz.rpc.report.general.DataReportService;
import com.alipay.tscenter.biz.rpc.report.general.model.DataReportResult;

/* renamed from: b.c.c.a.a.e.b */
/* loaded from: classes.dex */
public class C1403b implements InterfaceC1402a {

    /* renamed from: a */
    public static C1403b f1335a;

    /* renamed from: b */
    public static DataReportResult f1336b;

    /* renamed from: c */
    public AbstractC3163w f1337c;

    /* renamed from: d */
    public BugTrackMessageService f1338d;

    /* renamed from: e */
    public DataReportService f1339e;

    public C1403b(Context context, String str) {
        this.f1337c = null;
        this.f1338d = null;
        this.f1339e = null;
        C3138aa c3138aa = new C3138aa();
        c3138aa.m3652a(str);
        C3148h c3148h = new C3148h(context);
        this.f1337c = c3148h;
        this.f1338d = (BugTrackMessageService) c3148h.mo3674a(BugTrackMessageService.class, c3138aa);
        this.f1339e = (DataReportService) this.f1337c.mo3674a(DataReportService.class, c3138aa);
    }
}
