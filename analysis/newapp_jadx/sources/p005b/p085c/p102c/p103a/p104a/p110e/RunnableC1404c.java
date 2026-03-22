package p005b.p085c.p102c.p103a.p104a.p110e;

import com.alipay.tscenter.biz.rpc.report.general.model.DataReportRequest;
import com.alipay.tscenter.biz.rpc.report.general.model.DataReportResult;
import java.io.PrintWriter;
import java.io.StringWriter;

/* renamed from: b.c.c.a.a.e.c */
/* loaded from: classes.dex */
public class RunnableC1404c implements Runnable {

    /* renamed from: c */
    public final /* synthetic */ DataReportRequest f1340c;

    /* renamed from: e */
    public final /* synthetic */ C1403b f1341e;

    public RunnableC1404c(C1403b c1403b, DataReportRequest dataReportRequest) {
        this.f1341e = c1403b;
        this.f1340c = dataReportRequest;
    }

    @Override // java.lang.Runnable
    public void run() {
        try {
            C1403b.f1336b = this.f1341e.f1339e.reportData(this.f1340c);
        } catch (Throwable th) {
            DataReportResult dataReportResult = new DataReportResult();
            C1403b.f1336b = dataReportResult;
            dataReportResult.success = false;
            StringBuilder sb = new StringBuilder("static data rpc upload error, ");
            StringWriter stringWriter = new StringWriter();
            th.printStackTrace(new PrintWriter(stringWriter));
            sb.append(stringWriter.toString());
            dataReportResult.resultCode = sb.toString();
            StringBuilder sb2 = new StringBuilder("rpc failed:");
            StringWriter stringWriter2 = new StringWriter();
            th.printStackTrace(new PrintWriter(stringWriter2));
            sb2.append(stringWriter2.toString());
        }
    }
}
