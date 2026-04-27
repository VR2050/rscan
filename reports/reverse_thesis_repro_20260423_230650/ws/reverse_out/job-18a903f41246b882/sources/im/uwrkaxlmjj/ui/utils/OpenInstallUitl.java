package im.uwrkaxlmjj.ui.utils;

import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.text.TextUtils;
import com.fm.openinstall.listener.AppInstallAdapter;
import com.fm.openinstall.listener.AppWakeUpAdapter;
import com.fm.openinstall.model.AppData;
import im.uwrkaxlmjj.messenger.FileLog;

/* JADX INFO: loaded from: classes5.dex */
public class OpenInstallUitl {
    private static volatile OpenInstallUitl Instance = null;
    public static final String TAG = "OpenInstallUitl";
    private AppInstallAdapter installCallback;
    private String openChannel;
    private AppWakeUpAdapter wakeUpcallback;

    public static OpenInstallUitl getInstance() {
        if (Instance == null) {
            synchronized (OpenInstallUitl.class) {
                if (Instance == null) {
                    Instance = new OpenInstallUitl();
                }
            }
        }
        return Instance;
    }

    public static void init(Context context) {
    }

    public static void reportRegister() {
    }

    public static void reportEffectPoint(String pointId, long pointValue) {
    }

    private OpenInstallUitl() {
    }

    public String getOpenChannel() {
        return this.openChannel;
    }

    public void getInstallOrWakeUp(Intent intent) {
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.utils.OpenInstallUitl$1, reason: invalid class name */
    class AnonymousClass1 extends AppInstallAdapter {
        final /* synthetic */ SharedPreferences val$sp;

        AnonymousClass1(SharedPreferences sharedPreferences) {
            this.val$sp = sharedPreferences;
        }

        @Override // com.fm.openinstall.listener.AppInstallAdapter
        public void onInstall(AppData appData) {
            StringBuilder sb = new StringBuilder();
            sb.append("onInstall ---> , appData=");
            sb.append(appData != null ? appData.toString() : "null");
            FileLog.d(OpenInstallUitl.TAG, sb.toString());
            if (appData != null) {
                OpenInstallUitl.this.openChannel = appData.channel;
                SharedPreferences.Editor editor = this.val$sp.edit();
                if (editor != null) {
                    boolean needC = false;
                    if (!TextUtils.isEmpty(appData.data)) {
                        editor.putString("Op_data", appData.data);
                        needC = true;
                    }
                    if (!TextUtils.isEmpty(appData.channel)) {
                        editor.putString("Op_channel", appData.channel);
                        needC = true;
                    }
                    if (needC) {
                        editor.commit();
                    }
                }
            }
        }
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.utils.OpenInstallUitl$2, reason: invalid class name */
    class AnonymousClass2 extends AppWakeUpAdapter {
        AnonymousClass2() {
        }

        @Override // com.fm.openinstall.listener.AppWakeUpAdapter
        public void onWakeUp(AppData appData) {
            StringBuilder sb = new StringBuilder();
            sb.append("onWakeUp ---> , appData=");
            sb.append(appData != null ? appData.toString() : "null");
            FileLog.d(OpenInstallUitl.TAG, sb.toString());
        }
    }

    public void onDestroy() {
        this.wakeUpcallback = null;
        this.installCallback = null;
    }
}
