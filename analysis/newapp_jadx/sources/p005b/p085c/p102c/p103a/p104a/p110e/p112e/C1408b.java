package p005b.p085c.p102c.p103a.p104a.p110e.p112e;

import com.alipay.tscenter.biz.rpc.deviceFp.BugTrackMessageService;
import com.alipay.tscenter.biz.rpc.report.general.model.DataReportRequest;
import com.alipay.tscenter.biz.rpc.report.general.model.DataReportResult;
import com.jbzd.media.movecartoons.bean.response.FindBean;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import org.json.JSONObject;
import p005b.p085c.p102c.p103a.p104a.p110e.C1403b;
import p005b.p085c.p102c.p103a.p104a.p110e.InterfaceC1402a;
import p005b.p085c.p102c.p103a.p104a.p110e.RunnableC1404c;
import p005b.p085c.p102c.p103a.p104a.p110e.p111d.C1405a;
import p005b.p085c.p102c.p103a.p104a.p110e.p111d.C1406b;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.c.c.a.a.e.e.b */
/* loaded from: classes.dex */
public class C1408b implements InterfaceC1407a {

    /* renamed from: a */
    public static InterfaceC1407a f1360a;

    /* renamed from: b */
    public static InterfaceC1402a f1361b;

    /* renamed from: a */
    public C1405a m482a(C1406b c1406b) {
        DataReportResult dataReportResult;
        DataReportRequest dataReportRequest = new DataReportRequest();
        dataReportRequest.f8715os = c1406b.f1353a;
        dataReportRequest.rpcVersion = c1406b.f1359g;
        dataReportRequest.bizType = "1";
        HashMap hashMap = new HashMap();
        dataReportRequest.bizData = hashMap;
        hashMap.put("apdid", c1406b.f1354b);
        dataReportRequest.bizData.put("apdidToken", c1406b.f1355c);
        dataReportRequest.bizData.put("umidToken", c1406b.f1356d);
        dataReportRequest.bizData.put("dynamicKey", c1406b.f1357e);
        dataReportRequest.deviceData = c1406b.f1358f;
        C1403b c1403b = (C1403b) f1361b;
        Objects.requireNonNull(c1403b);
        if (dataReportRequest == null) {
            dataReportResult = null;
        } else {
            if (c1403b.f1339e != null) {
                C1403b.f1336b = null;
                new Thread(new RunnableC1404c(c1403b, dataReportRequest)).start();
                for (int i2 = 300000; C1403b.f1336b == null && i2 >= 0; i2 -= 50) {
                    Thread.sleep(50L);
                }
            }
            dataReportResult = C1403b.f1336b;
        }
        C1405a c1405a = new C1405a();
        if (dataReportResult == null) {
            return null;
        }
        c1405a.f1342a = dataReportResult.success;
        c1405a.f1343b = dataReportResult.resultCode;
        Map<String, String> map = dataReportResult.resultData;
        if (map != null) {
            c1405a.f1344c = map.get("apdid");
            c1405a.f1345d = map.get("apdidToken");
            c1405a.f1348g = map.get("dynamicKey");
            c1405a.f1349h = map.get("timeInterval");
            c1405a.f1350i = map.get("webrtcUrl");
            c1405a.f1351j = "";
            String str = map.get("drmSwitch");
            if (C4195m.m4840x(str)) {
                if (str.length() > 0) {
                    StringBuilder sb = new StringBuilder();
                    sb.append(str.charAt(0));
                    c1405a.f1346e = sb.toString();
                }
                if (str.length() >= 3) {
                    StringBuilder sb2 = new StringBuilder();
                    sb2.append(str.charAt(2));
                    c1405a.f1347f = sb2.toString();
                }
            }
            if (map.containsKey("apse_degrade")) {
                c1405a.f1352k = map.get("apse_degrade");
            }
        }
        return c1405a;
    }

    /* renamed from: b */
    public boolean m483b(String str) {
        BugTrackMessageService bugTrackMessageService;
        C1403b c1403b = (C1403b) f1361b;
        Objects.requireNonNull(c1403b);
        if (C4195m.m4822o(str) || (bugTrackMessageService = c1403b.f1338d) == null) {
            return false;
        }
        String str2 = null;
        try {
            str2 = bugTrackMessageService.logCollect(C4195m.m4791X(str));
        } catch (Throwable unused) {
        }
        if (C4195m.m4822o(str2)) {
            return false;
        }
        return ((Boolean) new JSONObject(str2).get(FindBean.status_success)).booleanValue();
    }
}
