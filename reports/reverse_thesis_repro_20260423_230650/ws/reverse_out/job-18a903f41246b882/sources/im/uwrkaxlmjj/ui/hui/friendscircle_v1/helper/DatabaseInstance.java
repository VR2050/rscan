package im.uwrkaxlmjj.ui.hui.friendscircle_v1.helper;

import android.content.Context;
import com.litesuits.orm.LiteOrm;
import com.litesuits.orm.db.assit.QueryBuilder;
import com.litesuits.orm.db.assit.WhereBuilder;
import im.uwrkaxlmjj.ui.hui.visualcall.VisualCallRequestBean;
import im.uwrkaxlmjj.ui.hui.visualcall.VisualCallRequestParaBean;
import java.util.ArrayList;
import java.util.List;

/* JADX INFO: loaded from: classes5.dex */
public class DatabaseInstance {
    private static final String TAG = DatabaseInstance.class.getSimpleName();
    private static LiteOrm fcLiteOrm;
    private static LiteOrm liteOrm;

    public static LiteOrm getInstance(Context mContext) {
        if (liteOrm == null) {
            synchronized (DatabaseInstance.class) {
                if (liteOrm == null) {
                    liteOrm = LiteOrm.newCascadeInstance(mContext, "user1.db");
                }
            }
        }
        liteOrm.setDebugged(true);
        return liteOrm;
    }

    public static LiteOrm getLiteOrm() {
        return liteOrm;
    }

    public static VisualCallRequestBean queryVisualCallById(String strId) {
        return (VisualCallRequestBean) liteOrm.queryById(strId, VisualCallRequestBean.class);
    }

    public static ArrayList<VisualCallRequestParaBean> queryVisualCallRequest() {
        return liteOrm.query(VisualCallRequestParaBean.class);
    }

    public static void saveVisualCallRequest(VisualCallRequestBean bean) {
        liteOrm.save(bean);
        List<VisualCallRequestBean> list = liteOrm.query(new QueryBuilder(VisualCallRequestBean.class).appendOrderDescBy("timestamp"));
        if (list.size() > 100) {
            long limitId = list.get(30).getTimestamp();
            WhereBuilder mQueryBuilder = new WhereBuilder(VisualCallRequestBean.class).where("timestamp<?", Long.valueOf(limitId));
            liteOrm.delete(mQueryBuilder);
        }
    }

    public static void saveVisualCallPara(VisualCallRequestParaBean bean) {
        liteOrm.save(bean);
    }

    public static long getVisualCallCount() {
        return liteOrm.queryCount(VisualCallRequestParaBean.class);
    }

    public static void deleteVisualCallRequest() {
        liteOrm.deleteAll(VisualCallRequestParaBean.class);
    }

    public static void deleteVisualCallId() {
        liteOrm.deleteAll(VisualCallRequestBean.class);
    }
}
