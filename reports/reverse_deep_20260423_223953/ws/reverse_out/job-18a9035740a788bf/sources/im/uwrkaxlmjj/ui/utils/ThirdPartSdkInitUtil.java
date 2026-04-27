package im.uwrkaxlmjj.ui.utils;

import android.app.ActivityManager;
import android.content.Context;
import android.net.http.HttpResponseCache;
import android.os.Process;
import com.bjz.comm.net.factory.SSLSocketClient;
import com.scwang.smartrefresh.layout.SmartRefreshLayout;
import com.scwang.smartrefresh.layout.api.DefaultRefreshFooterCreator;
import com.scwang.smartrefresh.layout.api.DefaultRefreshHeaderCreator;
import com.scwang.smartrefresh.layout.api.RefreshFooter;
import com.scwang.smartrefresh.layout.api.RefreshHeader;
import com.scwang.smartrefresh.layout.api.RefreshLayout;
import com.scwang.smartrefresh.layout.footer.ClassicsFooter;
import com.zhy.http.okhttp.OkHttpUtils;
import com.zhy.http.okhttp.log.LoggerInterceptor;
import im.uwrkaxlmjj.messenger.BuildVars;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.constants.Constants;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.player.config.VideoPlayerConfig;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.player.factory.ExoPlayerFactory;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.player.player.VideoPlayerManager;
import im.uwrkaxlmjj.ui.hui.views.NormalRefreshHeader;
import java.io.File;
import java.io.IOException;
import java.util.concurrent.TimeUnit;
import okhttp3.OkHttpClient;

/* JADX INFO: loaded from: classes5.dex */
public class ThirdPartSdkInitUtil implements Constants {
    private static final String TAG = "ThirdPartSdkInit";
    private static volatile boolean sdkIsInit;

    public static void initOtherSdk(Context applicationContext) {
        if (applicationContext == null) {
            return;
        }
        if (BuildVars.LOGS_ENABLED) {
            FileLog.d("SDKINIT  ===> ThirdPartSdkInitUtil initOtherSdk ===> start , sdkIsInit = " + sdkIsInit);
        }
        if (sdkIsInit) {
            return;
        }
        sdkIsInit = true;
        SmartRefreshLayout.setDefaultRefreshHeaderCreator(new DefaultRefreshHeaderCreator() { // from class: im.uwrkaxlmjj.ui.utils.-$$Lambda$ThirdPartSdkInitUtil$7YuUwHepSMQWthzoHbUCtYYMDB0
            @Override // com.scwang.smartrefresh.layout.api.DefaultRefreshHeaderCreator
            public final RefreshHeader createRefreshHeader(Context context, RefreshLayout refreshLayout) {
                return ThirdPartSdkInitUtil.lambda$initOtherSdk$0(context, refreshLayout);
            }
        });
        SmartRefreshLayout.setDefaultRefreshFooterCreator(new DefaultRefreshFooterCreator() { // from class: im.uwrkaxlmjj.ui.utils.-$$Lambda$ThirdPartSdkInitUtil$8MFL4qS2JY6elIPhcNuN5c9WAA4
            @Override // com.scwang.smartrefresh.layout.api.DefaultRefreshFooterCreator
            public final RefreshFooter createRefreshFooter(Context context, RefreshLayout refreshLayout) {
                return ThirdPartSdkInitUtil.lambda$initOtherSdk$1(context, refreshLayout);
            }
        });
        OkHttpClient okHttpClient = new OkHttpClient.Builder().addInterceptor(new LoggerInterceptor("fcokhttp", true)).connectTimeout(OkHttpUtils.DEFAULT_MILLISECONDS, TimeUnit.MILLISECONDS).readTimeout(20000L, TimeUnit.MILLISECONDS).sslSocketFactory(SSLSocketClient.getSSLSocketFactory()).hostnameVerifier(SSLSocketClient.getHostnameVerifier()).build();
        OkHttpUtils.initClient(okHttpClient);
        isMainProcess(applicationContext);
        VideoPlayerManager.loadConfig(new VideoPlayerConfig.Builder(applicationContext).buildPlayerFactory(new ExoPlayerFactory(applicationContext)).enableSmallWindowPlay().enableCache(true).enableLog(true).build());
        try {
            File cache = new File(applicationContext.getCacheDir(), "http");
            HttpResponseCache.install(cache, 268435456L);
        } catch (IOException e) {
            e.printStackTrace();
        }
        if (BuildVars.LOGS_ENABLED) {
            FileLog.d("SDKINIT  ===> ThirdPartSdkInitUtil initOtherSdk ===> end , sdkIsInit = " + sdkIsInit);
        }
    }

    static /* synthetic */ RefreshHeader lambda$initOtherSdk$0(Context context, RefreshLayout layout) {
        layout.setPrimaryColors(Theme.getColor(Theme.key_windowBackgroundGray), Theme.getColor(Theme.key_windowBackgroundWhiteGrayText3));
        return new NormalRefreshHeader(context);
    }

    static /* synthetic */ RefreshFooter lambda$initOtherSdk$1(Context context, RefreshLayout layout) {
        layout.setPrimaryColors(Theme.getColor(Theme.key_windowBackgroundGray), Theme.getColor(Theme.key_windowBackgroundWhiteGrayText3));
        return new ClassicsFooter(context);
    }

    private static boolean isMainProcess(Context applicationContext) {
        int pid = Process.myPid();
        ActivityManager activityManager = (ActivityManager) applicationContext.getSystemService("activity");
        for (ActivityManager.RunningAppProcessInfo appProcess : activityManager.getRunningAppProcesses()) {
            if (appProcess.pid == pid) {
                return applicationContext.getApplicationInfo().packageName.equals(appProcess.processName);
            }
        }
        return false;
    }
}
