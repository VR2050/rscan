package im.uwrkaxlmjj.network;

import android.util.Log;
import com.csm.shield.GameShield;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import java.lang.reflect.Array;

/* JADX INFO: loaded from: classes2.dex */
public class NetWorkManager {
    private static NetWorkManager instance;
    protected int currentAccount = UserConfig.selectedAccount;

    public static synchronized NetWorkManager getInstance() {
        if (instance == null) {
            instance = new NetWorkManager();
        }
        return instance;
    }

    public void initNetWork() {
        Log.d("bond", "网络数据初始化");
        setServer2("server 0");
        connectsNet(this.currentAccount);
    }

    public void setServer2(final String str) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.network.-$$Lambda$NetWorkManager$g-KLzofKEpq0vhi2lw8Sx4Qndas
            @Override // java.lang.Runnable
            public final void run() {
                NotificationCenter.getInstance(0).postNotificationName(NotificationCenter.getBackupIpStatus, str);
            }
        });
    }

    public void restartApplication() {
        connectsNet(this.currentAccount);
    }

    private void connectsNet(int currentAccount) {
        try {
            int status = GameShield.sdkInitEx(NetworkConstant.K);
            setServer2(status == 0 ? "server 2" : "server " + status);
            if (status == 0) {
                int[][] ports = (int[][]) Array.newInstance((Class<?>) int.class, 10, 2);
                if (GameShield.getPorts(ports, 10, 2) < 0) {
                    Log.e("bond", "Failed to get ports");
                    return;
                }
                for (int i = 0; i < 3; i++) {
                    ConnectionsManager.getInstance(i).setAddress(currentAccount, "127.0.0.1", ports[0][1]);
                }
            }
        } catch (Exception e) {
            setServer2("server 1");
            Log.e("bond", "Failed to start proxy", e);
        }
    }

    public void applyDatacenterAddress(int currentAccount, boolean isDel) {
        connectsNet(currentAccount);
    }
}
