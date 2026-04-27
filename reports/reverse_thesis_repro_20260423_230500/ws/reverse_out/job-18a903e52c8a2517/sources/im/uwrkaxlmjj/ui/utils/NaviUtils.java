package im.uwrkaxlmjj.ui.utils;

import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class NaviUtils {
    public static final String PN_BAIDU_MAP = "com.baidu.BaiduMap";
    public static final String PN_GAODE_MAP = "com.autonavi.minimap";
    public static final String PN_TENCENT_MAP = "com.tencent.map";

    public static void startBaiduNavi(Context context, String sName, double sLat, double sLng, String dName, double dLat, double dLng) {
        String uriString = "baidumap://map/direction?mode=driving&origin=latlng:" + sLat + "," + sLng + "|name:" + sName + "&destination=latlng:" + dLat + "," + dLng + "|name:" + dName;
        Intent intent = new Intent("android.intent.action.VIEW");
        intent.setPackage(PN_BAIDU_MAP);
        intent.setData(Uri.parse(uriString));
        context.startActivity(intent);
    }

    public static void startGaodeNavi(Context context, String sName, double sLat, double sLng, String dName, double dLat, double dLng) {
        String uriString = ("amapuri://route/plan?sourceApplication=" + context.getResources().getString(R.string.AppName)) + "&sname=" + sName + "&slat=" + sLat + "&slon=" + sLng + "&dname=" + dName + "&dlat=" + dLat + "&dlon=" + dLng + "&dev=0&t=0";
        Intent intent = new Intent("android.intent.action.VIEW");
        intent.setPackage(PN_GAODE_MAP);
        intent.setData(Uri.parse(uriString));
        context.startActivity(intent);
    }

    public static void startTencentNavi(Context context, String sName, double sLat, double sLng, String dName, double dLat, double dLng) {
        String uriString = "qqmap://map/routeplan?type=drive&policy=0&referer=zhongshuo&from=" + sName + "&fromcoord=" + sLat + "," + sLng + "&to=" + dName + "&tocoord=" + dLat + "," + dLng;
        Intent intent = new Intent("android.intent.action.VIEW");
        intent.setPackage(PN_TENCENT_MAP);
        intent.setData(Uri.parse(uriString));
        context.startActivity(intent);
    }
}
