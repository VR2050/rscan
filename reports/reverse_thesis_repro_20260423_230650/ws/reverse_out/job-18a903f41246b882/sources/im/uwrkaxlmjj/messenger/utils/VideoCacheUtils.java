package im.uwrkaxlmjj.messenger.utils;

import android.content.Context;
import com.bjz.comm.net.utils.HttpUtils;
import com.danikula.videocache.HttpProxyCacheServer;
import com.danikula.videocache.headers.HeaderInjector;
import java.util.HashMap;
import java.util.Map;

/* JADX INFO: loaded from: classes2.dex */
public class VideoCacheUtils {
    private static HttpProxyCacheServer proxy = null;

    public static String getProxyUrl(Context context, String strOrgUrl) {
        if (proxy == null) {
            proxy = new HttpProxyCacheServer.Builder(context.getApplicationContext()).headerInjector(new HeaderInjector() { // from class: im.uwrkaxlmjj.messenger.utils.-$$Lambda$VideoCacheUtils$4yS6FynNYDVG-MsxaXuzXnoJSgU
                @Override // com.danikula.videocache.headers.HeaderInjector
                public final Map addHeaders(String str) {
                    return VideoCacheUtils.lambda$getProxyUrl$0(str);
                }
            }).build();
        }
        return proxy.getProxyUrl(strOrgUrl);
    }

    static /* synthetic */ Map lambda$getProxyUrl$0(String url) {
        Map<String, String> map = new HashMap<>();
        map.put("user-agent", HttpUtils.getInstance().getUserAgentFC());
        return map;
    }
}
