package im.uwrkaxlmjj.network;

import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import com.google.android.exoplayer2.DefaultRenderersFactory;
import com.just.agentweb.DefaultWebClient;
import im.uwrkaxlmjj.ui.hui.friendscircle.okhttphelper.MD5Utils;
import java.io.IOException;
import java.io.PrintStream;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.concurrent.TimeUnit;
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import org.webrtc.utils.RecvStatsReportCommon;

/* JADX INFO: loaded from: classes2.dex */
public class OSSNet {
    private OSSCallback mCallback;
    private int ossIndex = 0;
    private String[] oss_list;

    public interface OSSCallback {
        void onFail();

        void onSuccess(String str);
    }

    static /* synthetic */ int access$108(OSSNet x0) {
        int i = x0.ossIndex;
        x0.ossIndex = i + 1;
        return i;
    }

    public void initOssNet(OSSCallback call) {
        this.mCallback = call;
        initOssUrl();
        sendOSSRequest();
    }

    private String initOssUrl() {
        Date date = new Date();
        SimpleDateFormat dateFormat = new SimpleDateFormat("YYYYMMdd");
        String format = dateFormat.format(date);
        String md5_tong = MD5Utils.getMD5String(NetworkConstant.ENABLE_SETTING + format);
        String md5_tong_1 = MD5Utils.getMD5String(NetworkConstant.ENABLE_SETTING + format + "1");
        StringBuilder sb = new StringBuilder();
        sb.append(((double) System.currentTimeMillis()) + (Math.random() * 100.0d));
        sb.append("");
        String md5_tong_2 = MD5Utils.getMD5String(sb.toString());
        String md5_txt = MD5Utils.getMD5String(NetworkConstant.ENABLE_SETTING + format + RecvStatsReportCommon.sdk_platform);
        Log.d("bond", "环境时间：" + NetworkConstant.ENABLE_SETTING + format);
        Log.d("bond", "md5_tong：" + md5_tong + "  " + md5_tong_1 + "  " + md5_tong_2 + " md5_txt:" + md5_txt);
        PrintStream printStream = System.out;
        StringBuilder sb2 = new StringBuilder();
        sb2.append("环境时间：");
        sb2.append(NetworkConstant.ENABLE_SETTING);
        sb2.append(format);
        printStream.println(sb2.toString());
        System.out.println("md5_tong：" + md5_tong + "  " + md5_tong_1 + "  " + md5_tong_2 + " md5_txt:" + md5_txt);
        String[] strArr = {DefaultWebClient.HTTPS_SCHEME + md5_tong + "." + NetworkConstant.OSS_URL + "/" + md5_txt + ".txt", DefaultWebClient.HTTPS_SCHEME + md5_tong_1 + "." + NetworkConstant.OSS_URL + "/" + md5_txt + ".txt", DefaultWebClient.HTTPS_SCHEME + md5_tong_2 + "." + NetworkConstant.OSS_URL + "/" + md5_txt + ".txt"};
        this.oss_list = strArr;
        return strArr[this.ossIndex];
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void sendOSSRequest() {
        if (this.oss_list == null) {
            initOssUrl();
        }
        OkHttpClient.Builder builder = new OkHttpClient.Builder();
        builder.connectTimeout(DefaultRenderersFactory.DEFAULT_ALLOWED_VIDEO_JOINING_TIME_MS, TimeUnit.SECONDS);
        builder.readTimeout(DefaultRenderersFactory.DEFAULT_ALLOWED_VIDEO_JOINING_TIME_MS, TimeUnit.SECONDS);
        OkHttpClient client = builder.build();
        Request request = new Request.Builder().url(this.oss_list[this.ossIndex]).get().build();
        client.newCall(request).enqueue(new AnonymousClass1());
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.network.OSSNet$1, reason: invalid class name */
    class AnonymousClass1 implements Callback {
        Handler mainHandler = new Handler(Looper.getMainLooper());

        AnonymousClass1() {
        }

        @Override // okhttp3.Callback
        public void onFailure(Call call, IOException e) {
            Log.e("bond", "oss失败URL = " + OSSNet.this.oss_list[OSSNet.this.ossIndex]);
            Log.e("bond", "oss获取失败 = " + e.toString());
            if (OSSNet.this.ossIndex >= OSSNet.this.oss_list.length - 1) {
                if (OSSNet.this.mCallback != null) {
                    OSSNet.this.mCallback.onFail();
                }
            } else {
                OSSNet.access$108(OSSNet.this);
                OSSNet.this.sendOSSRequest();
            }
        }

        @Override // okhttp3.Callback
        public void onResponse(Call call, Response response) throws IOException {
            if (response.isSuccessful()) {
                final String text = response.body().string();
                Log.e("bond", "oss获取成功 = " + text);
                if (OSSNet.this.mCallback != null) {
                    this.mainHandler.post(new Runnable() { // from class: im.uwrkaxlmjj.network.-$$Lambda$OSSNet$1$WNBx2NI3jnE62LYS8NMMSSXSbYU
                        @Override // java.lang.Runnable
                        public final void run() {
                            this.f$0.lambda$onResponse$0$OSSNet$1(text);
                        }
                    });
                    return;
                }
                return;
            }
            Log.e("bond", "oss解析失败URL = " + OSSNet.this.oss_list[OSSNet.this.ossIndex]);
            if (OSSNet.this.ossIndex < OSSNet.this.oss_list.length - 1) {
                OSSNet.access$108(OSSNet.this);
                OSSNet.this.sendOSSRequest();
            }
        }

        public /* synthetic */ void lambda$onResponse$0$OSSNet$1(String text) {
            OSSNet.this.mCallback.onSuccess(text);
        }
    }
}
