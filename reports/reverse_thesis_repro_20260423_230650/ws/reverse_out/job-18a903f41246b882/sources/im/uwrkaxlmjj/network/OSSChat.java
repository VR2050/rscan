package im.uwrkaxlmjj.network;

import android.os.Handler;
import android.os.Looper;
import android.text.TextUtils;
import android.util.Log;
import com.google.android.exoplayer2.DefaultRenderersFactory;
import com.just.agentweb.DefaultWebClient;
import im.uwrkaxlmjj.ui.hui.friendscircle.okhttphelper.MD5Utils;
import im.uwrkaxlmjj.ui.utils.AesUtils;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.concurrent.TimeUnit;
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

/* JADX INFO: loaded from: classes2.dex */
public class OSSChat {
    private static OSSChat instance;
    public String serverUrl;

    public interface OSSChatCallback {
        void onFail();

        void onSuccess(String str);
    }

    public static synchronized OSSChat getInstance() {
        if (instance == null) {
            instance = new OSSChat();
        }
        return instance;
    }

    public void sendOSSRequest(OSSChatCallback ossChatCallback) {
        if (!TextUtils.isEmpty(this.serverUrl)) {
            ossChatCallback.onSuccess(this.serverUrl);
            return;
        }
        OkHttpClient.Builder builder = new OkHttpClient.Builder();
        builder.connectTimeout(DefaultRenderersFactory.DEFAULT_ALLOWED_VIDEO_JOINING_TIME_MS, TimeUnit.SECONDS);
        builder.readTimeout(DefaultRenderersFactory.DEFAULT_ALLOWED_VIDEO_JOINING_TIME_MS, TimeUnit.SECONDS);
        OkHttpClient client = builder.build();
        Request request = new Request.Builder().url(getUrl()).get().build();
        client.newCall(request).enqueue(new AnonymousClass1(ossChatCallback));
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.network.OSSChat$1, reason: invalid class name */
    class AnonymousClass1 implements Callback {
        Handler mainHandler = new Handler(Looper.getMainLooper());
        final /* synthetic */ OSSChatCallback val$ossChatCallback;

        AnonymousClass1(OSSChatCallback oSSChatCallback) {
            this.val$ossChatCallback = oSSChatCallback;
        }

        @Override // okhttp3.Callback
        public void onFailure(Call call, IOException e) {
            Log.d("bond", "oss获取失败 = " + e.toString());
            Handler handler = this.mainHandler;
            OSSChatCallback oSSChatCallback = this.val$ossChatCallback;
            oSSChatCallback.getClass();
            handler.post(new $$Lambda$mH_Wcgg_yhJ0n3phIdjxwRXNISQ(oSSChatCallback));
        }

        @Override // okhttp3.Callback
        public void onResponse(Call call, Response response) throws IOException {
            if (response.isSuccessful()) {
                String text = response.body().string();
                Log.d("bond", "客服链接获取成功 = " + text);
                try {
                    byte[] rets = AesUtils.decryptYunceng(text);
                    final String retStr = new String(rets);
                    OSSChat.this.serverUrl = retStr;
                    Handler handler = this.mainHandler;
                    final OSSChatCallback oSSChatCallback = this.val$ossChatCallback;
                    handler.post(new Runnable() { // from class: im.uwrkaxlmjj.network.-$$Lambda$OSSChat$1$l8h4BMNHuZUuBE7dEN0Gdwus_UY
                        @Override // java.lang.Runnable
                        public final void run() {
                            oSSChatCallback.onSuccess(retStr);
                        }
                    });
                    return;
                } catch (Exception e) {
                    Log.d("bond", "客服链接解密失败 = " + e.toString());
                    Handler handler2 = this.mainHandler;
                    OSSChatCallback oSSChatCallback2 = this.val$ossChatCallback;
                    oSSChatCallback2.getClass();
                    handler2.post(new $$Lambda$mH_Wcgg_yhJ0n3phIdjxwRXNISQ(oSSChatCallback2));
                    return;
                }
            }
            Log.d("bond", "客服链接获取失败 = " + response.toString());
            Handler handler3 = this.mainHandler;
            OSSChatCallback oSSChatCallback3 = this.val$ossChatCallback;
            oSSChatCallback3.getClass();
            handler3.post(new $$Lambda$mH_Wcgg_yhJ0n3phIdjxwRXNISQ(oSSChatCallback3));
        }
    }

    private String getUrl() {
        Date date = new Date();
        SimpleDateFormat dateFormat = new SimpleDateFormat("YYYYMMdd");
        String format = dateFormat.format(date);
        String md5_tong = MD5Utils.getMD5String(NetworkConstant.ENABLE_SETTING + format);
        Log.d("bond", "环境时间：" + NetworkConstant.ENABLE_SETTING + format);
        return DefaultWebClient.HTTPS_SCHEME + md5_tong + "." + NetworkConstant.OSS_URL + "/Sbcc_osschat.txt";
    }
}
