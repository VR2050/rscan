package im.uwrkaxlmjj.ui.hui.friendscircle.okhttphelper;

import com.bjz.comm.net.UrlConstant;
import com.bjz.comm.net.utils.HttpUtils;
import com.zhy.http.okhttp.OkHttpUtils;
import im.uwrkaxlmjj.messenger.AccountInstance;
import im.uwrkaxlmjj.messenger.UserConfig;
import java.io.IOException;
import okhttp3.Response;

/* JADX INFO: loaded from: classes5.dex */
public class LiveOkHttpUtils {
    public static String REMOTE_URL = "";

    public static Response doGetSyn(String url) {
        try {
            Response response = OkHttpUtils.get().addHeader("User-Agent", UrlConstant.USER_AGENT_LIVE).addHeader("authorization", getTokenFromLocal()).addHeader("user-id", String.valueOf(AccountInstance.getInstance(UserConfig.selectedAccount).getUserConfig().getCurrentUser().id)).url(url).build().execute();
            return response;
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }

    private static String getTokenFromLocal() {
        return HttpUtils.getInstance().getAuthorization();
    }
}
