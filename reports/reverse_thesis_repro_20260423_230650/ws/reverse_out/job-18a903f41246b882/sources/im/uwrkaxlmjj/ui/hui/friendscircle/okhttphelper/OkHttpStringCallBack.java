package im.uwrkaxlmjj.ui.hui.friendscircle.okhttphelper;

import android.content.Context;
import com.google.android.exoplayer2.util.Log;
import com.socks.library.KLog;
import com.zhy.http.okhttp.callback.StringCallback;
import im.uwrkaxlmjj.ui.actionbar.AlertDialog;
import java.net.UnknownHostException;
import okhttp3.Call;
import okhttp3.Request;
import org.json.JSONException;

/* JADX INFO: loaded from: classes5.dex */
public class OkHttpStringCallBack extends StringCallback {
    private Context mContext;
    private AlertDialog progressDialog;

    public OkHttpStringCallBack(Context mContext) {
        this.progressDialog = null;
        this.mContext = null;
        this.mContext = mContext;
        if (mContext != null) {
            AlertDialog alertDialog = new AlertDialog(mContext, 3);
            this.progressDialog = alertDialog;
            alertDialog.setCanCancel(false);
        }
    }

    public OkHttpStringCallBack() {
        this.progressDialog = null;
        this.mContext = null;
    }

    @Override // com.zhy.http.okhttp.callback.Callback
    public void onBefore(Request request, int id) {
        try {
            if (this.mContext == null) {
                return;
            }
            if (this.progressDialog == null) {
                AlertDialog alertDialog = new AlertDialog(this.mContext, 3);
                this.progressDialog = alertDialog;
                alertDialog.setCanCancel(false);
            }
            this.progressDialog.show();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Override // com.zhy.http.okhttp.callback.Callback
    public void onAfter(int id) {
        try {
            if (this.progressDialog != null) {
                this.progressDialog.dismiss();
                this.progressDialog = null;
            }
        } catch (Exception e) {
            e.printStackTrace();
            this.progressDialog = null;
        }
    }

    @Override // com.zhy.http.okhttp.callback.Callback
    public void onError(Call call, Exception e, int id) throws JSONException {
        KLog.e("---------请求异常" + e.getMessage() + "   " + id);
        if (e instanceof UnknownHostException) {
            return;
        }
        e.printStackTrace();
    }

    @Override // com.zhy.http.okhttp.callback.Callback
    public void onResponse(String response, int id) {
        KLog.d("");
        Log.e("okhttp", "onResponse：complete");
    }

    @Override // com.zhy.http.okhttp.callback.Callback
    public void inProgress(float progress, long total, int id) {
    }
}
