package im.uwrkaxlmjj.ui.hui.visualcall;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkInfo;
import android.os.Build;

/* JADX INFO: loaded from: classes5.dex */
public class CallNetWorkReceiver extends BroadcastReceiver {
    private NetworkInfo dataNetworkInfo;
    private NetWorkStateCallBack mCallBack;
    private NetworkInfo wifiNetworkInfo;

    public interface NetWorkStateCallBack {
        void onNetWorkConnected();

        void onNetWorkDisconnected();
    }

    @Override // android.content.BroadcastReceiver
    public void onReceive(Context context, Intent intent) {
        NetworkInfo networkInfo;
        if (Build.VERSION.SDK_INT < 23) {
            ConnectivityManager connMgr = (ConnectivityManager) context.getSystemService("connectivity");
            this.wifiNetworkInfo = connMgr.getNetworkInfo(1);
            this.dataNetworkInfo = connMgr.getNetworkInfo(0);
        } else {
            ConnectivityManager connMgr2 = (ConnectivityManager) context.getSystemService("connectivity");
            Network[] networks = connMgr2.getAllNetworks();
            for (Network network : networks) {
                NetworkInfo networkInfo2 = connMgr2.getNetworkInfo(network);
                if (networkInfo2.getType() == 1) {
                    this.wifiNetworkInfo = networkInfo2;
                } else if (networkInfo2.getType() == 0) {
                    this.dataNetworkInfo = networkInfo2;
                }
            }
        }
        NetworkInfo networkInfo3 = this.wifiNetworkInfo;
        if ((networkInfo3 != null && networkInfo3.isConnected()) || ((networkInfo = this.dataNetworkInfo) != null && networkInfo.isConnected())) {
            NetWorkStateCallBack netWorkStateCallBack = this.mCallBack;
            if (netWorkStateCallBack != null) {
                netWorkStateCallBack.onNetWorkConnected();
                return;
            }
            return;
        }
        NetWorkStateCallBack netWorkStateCallBack2 = this.mCallBack;
        if (netWorkStateCallBack2 != null) {
            netWorkStateCallBack2.onNetWorkDisconnected();
        }
    }

    public void setCallBack(NetWorkStateCallBack mCallBack) {
        this.mCallBack = mCallBack;
    }
}
